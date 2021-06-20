package de.qtc.rmg.operations;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import de.qtc.rmg.internal.ExceptionHandler;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.networking.RMIWhisperer;
import de.qtc.rmg.utils.RMGUtils;

/**
 * The MethodGuesser class is used to brute force available remote methods on Java RMI endpoints. It uses
 * low level Java RMI functions to invoke methods parsed from a wordlist with incorrect argument types. The
 * server-side exception can be used as an indicator whether the invoked method exists on the server.
 *
 * When a RMI client calls a remote method, it establishes a TCP connection to the remote endpoint
 * and sends (among others) the following information:
 *
 *         - The ObjID of the RemoteObject that should receive the call
 *         - A method hash, that identifies the remote method to be called
 *         - A collection of method arguments to be used for the call
 *
 * During method guessing, remote-method-guesser uses a wordlist of Java methods and computes their hash
 * values. The corresponding hashes are then sent to the server, together with an collection of argument types
 * that do NOT match the expected argument types by the remote method. If a remote method does not
 * exist, the server throws an exception complaining about an unknown hash value. On the other hand, if the
 * remote method exists, the server will complain about the mismatch of argument types.
 *
 * This allows to reliably detect remote methods without the risk of causing unwanted actions on the server
 * side by actually invoking them. The idea for such a guessing approach was not invented by remote-method-guesser,
 * but was, to the best of our knowledge, first implemented by the rmiscout project. However, remote-method-guesser
 * takes this approach further and implements the mismatch of argument types in a way that prevents the underlying
 * TCP stream from being corrupted. This allows remote-method-guesser to reuse already established TCP connections
 * which provides a great performance boost, especially on TLS protected endpoints.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MethodGuesser {

    private int padding = 0;
    private int legacyMode;

    private RMIWhisperer rmiEndpoint;
    private Set<MethodCandidate> candidates;
    private List<RemoteObjectClient> clientList;
    private HashMap<String, String[]> duplicateMap;
    private List<Set<MethodCandidate>> candidateSets;
    private Map<String, ArrayList<MethodCandidate>> knownMethods;

    /**
     * To create a MethodGuesser object, you usually pass the obtained information from an RMI registry endpoint.
     * This includes the RMIWhisperer to the registry itself together with an ArrayList containing the bound- and
     * corresponding class names. Moreover, the method candidates to be guessed and the current legacy mode are
     * required.
     *
     * The MethodGuesser creates a RemoteObjectClient for each unique remote class and guess the specified candidates
     * on it when invoking the guess action. The list of candidates is split to the number of available threads
     * first. Therefore, method guessing is performed in n * t tasks, where n is the number of bound names and t is
     * the number of threads.
     *
     * @param rmi RMIWhisperer for the current registry
     * @param classArray Two HashMap that contain boundName -> className pairs for known and unknown classes
     * @param candidates MethodCandidates that should be guessed
     * @param legacyMode Determines how to handle legacy objects during guessing
     */
    public MethodGuesser(RMIWhisperer rmi, HashMap<String,String>[] classArray, Set<MethodCandidate> candidates, int legacyMode)
    {
        this.rmiEndpoint = rmi;
        this.legacyMode = legacyMode;
        this.candidates = candidates;

        this.duplicateMap = new HashMap<String, String[]>();
        this.knownMethods = new HashMap<String,ArrayList<MethodCandidate>>();
        this.candidateSets = RMGUtils.splitSet(candidates, RMGOption.THREADS.getInt());

        HashMap<String, String> boundClasses = (HashMap<String, String>)classArray[1];

        if( classArray[0].size() != 0 && RMGOption.FORCE_GUESSING.getBool() )
            boundClasses.putAll(classArray[0]);

        else
            handleKnownMethods(classArray[0]);

        this.clientList = new ArrayList<RemoteObjectClient>();
        initClientList(boundClasses);
    }

    /**
     * This function is basically used to prevent guessing on duplicate classes. Some RMI endpoints bind
     * multiple instances of the same remote class to the registry. Guessing each of them is usually not
     * what you want, as they use the same implementation. This function checks the bound class names for
     * duplicates and handles them according to the RMGOption.GUESS_DUPLICATES value.
     *
     * If guessing duplicates was requested, the function creates a new RemoteObjectClient for each boundName.
     * If guessing duplicates was not requested, only the first boundName is used to create a RemoteObjectClient
     * and all other bound names that are based on the same class are registered as duplicates.
     *
     * @param boundClasses Map of boundName -> className pairs
     */
    private void initClientList(HashMap<String, String> boundClasses)
    {
        RemoteObjectClient client = null;
        HashMap<String, ArrayList<String>> classBoundnameMap = new HashMap<String, ArrayList<String>>();

        for( Map.Entry<String, String> entry : boundClasses.entrySet() ) {
            setPadding(entry.getKey());
            classBoundnameMap.computeIfAbsent(entry.getValue(), k -> new ArrayList<String>()).add(entry.getKey());
        }

        for( Map.Entry<String, ArrayList<String>> entry : classBoundnameMap.entrySet() ) {

            String className = entry.getKey();
            ArrayList<String> boundNames = entry.getValue();
            String[] boundNamesStr = boundNames.toArray(new String[0]);

            for( String boundName : boundNames ) {
                client = new RemoteObjectClient(rmiEndpoint, boundName, className, legacyMode);
                clientList.add(client);

                if( RMGOption.GUESS_DUPLICATES.getBool() )
                    continue;

                if( boundNamesStr.length > 1 )
                    duplicateMap.put(boundName, (String[]) Arrays.copyOfRange(boundNamesStr, 1, boundNamesStr.length));

                break;
            }
        }

        printDuplicates();
    }

    /**
     * This function is just used for displaying the result. It is called when iterating over the boundNames
     * and saves the length of the longest boundName. This is used as a padding value for the other boundNames.
     *
     * @param value String to obtain the length from
     */
    private void setPadding(String value)
    {
        if( padding < value.length() )
            padding = value.length();
    }

    private void printDuplicates()
    {
        if( duplicateMap.size() == 0 )
            return;

        Logger.disableIfNotVerbose();
        Logger.printInfoBox();

        Logger.println("The following bound names use the same remote class:");
        Logger.println("");
        Logger.increaseIndent();

        for( Map.Entry<String, String[]> entry : duplicateMap.entrySet() ) {

            Logger.printlnMixedBlue("-", entry.getKey());
            Logger.increaseIndent();

            for(String dup : entry.getValue() ) {
                Logger.printlnMixedYellow("-->", dup);
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
        Logger.println("");
        Logger.printlnMixedBlue("Method guessing", "is skipped", "for duplicate remote classes.");
        Logger.printlnMixedYellow("You can use", "--guess-duplicates", "to guess them anyway.");
        Logger.decreaseIndent();
        Logger.enable();
    }

    /**
     * When known remote objects are encountered and --force-guessing was not used, the corresponding remote methods
     * are added automatically to the list of guessed methods. This function performs this task and also prints according
     * information for the user.
     *
     * @param classArray Map of boundName -> knownClass pairs
     */
    private void handleKnownMethods(HashMap<String,String> classArray)
    {
        if( classArray.size() == 0 )
            return;

        ArrayList<String> knownBoundNames = new ArrayList<String>();

        for( Map.Entry<String, String> entry : classArray.entrySet() ) {
            knownBoundNames.add(entry.getKey() + " (" + entry.getValue() + ")");
            RMGUtils.addKnownMethods(entry.getKey(), entry.getValue(), knownMethods);
        }

        Logger.disableIfNotVerbose();
        Logger.printInfoBox();

        Logger.println("The following bound names use a known remote object class:");
        Logger.println("");
        Logger.increaseIndent();

        for(String boundName : knownBoundNames )
            Logger.printlnMixedBlue("-", boundName);

        Logger.decreaseIndent();
        Logger.println("");
        Logger.printlnMixedBlue("Method guessing", "is skipped", "and known methods are listed instead.");
        Logger.printlnMixedYellow("You can use", "--force-guessing", "to guess methods anyway.");
        Logger.decreaseIndent();
        Logger.println("");
        Logger.enable();
    }

    /**
     * When bound names were skipped because they are duplicates, they still need to obtain valid methods
     * that were guessed on the chosen duplicate. This function adds each duplicate boundName to the results
     * list and appends the methods that were found in the chosen duplicate.
     *
     * @param results ResultList that was obtained after method guessing.
     */
    private void handleDuplicates(Map<String, ArrayList<MethodCandidate>> results)
    {
        for( Map.Entry<String, String[]> entry: duplicateMap.entrySet()) {

            String boundName = entry.getKey();
            String[] boundNames = entry.getValue();

            ArrayList<MethodCandidate> existingMethods = results.get(boundName);

            if( existingMethods != null ) {
                for( String duplicate : boundNames )
                    results.put(duplicate + " (== " + boundName + ")", existingMethods);
            }
        }
    }

    /**
     * Helper function that prints some visual text when the guesser is started. Just contains information
     * on the number of methods that are guessed or the concrete method signature (if specified).
     */
    public void printGuessingIntro()
    {
        int count = candidates.size();

        if(count == 0) {
            Logger.eprintlnMixedYellow("List of candidate methods contains", "0", "elements.");
            Logger.eprintln("Please use a valid and non empty wordlist file.");
            RMGUtils.exit();

        } else if( clientList.size() == 0 ) {
            return;
        }

        Logger.println("");
        Logger.printlnMixedYellow("Starting Method Guessing on", String.valueOf(count), "method signature(s).");

        if( count == 1 ) {
            Logger.printlnMixedBlue("Method signature:", ((MethodCandidate)candidates.toArray()[0]).getSignature() + ".");
        }
    }

    /**
     * This method starts the actual guessing process. It creates a GuessingWorker for each remoteClient in the clientMap
     * and for each Set of MethodCandidates in the candidateSets.
     *
     * @return Map of successfully guessed methods (boundName -> List<MethodCandidates>)
     */
    public Map<String, ArrayList<MethodCandidate>> guessMethods()
    {
        Logger.println("");

        if( clientList.size() == 0 )
            return knownMethods;

        Logger.increaseIndent();
        Logger.printlnYellow("MethodGuesser is running:");
        Logger.increaseIndent();
        Logger.printlnBlue("--------------------------------");

        ConcurrentHashMap<String, ArrayList<MethodCandidate>> existingMethods = new ConcurrentHashMap<String, ArrayList<MethodCandidate>>();
        ExecutorService pool = Executors.newFixedThreadPool(RMGOption.THREADS.getInt());

        for( RemoteObjectClient client : clientList ) {
            for( Set<MethodCandidate> candidates : candidateSets ) {
                Runnable r = new GuessingWorker(client, candidates, client.getBoundName(), existingMethods);
                pool.execute(r);
            }
        }

        try {
            pool.shutdown();
            pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);

        } catch (InterruptedException e) {
             Logger.eprintln("Interrupted!");
        }

        Logger.decreaseIndent();
        Logger.printlnYellow("done.");
        Logger.println("");

        handleDuplicates(existingMethods);
        existingMethods.putAll(knownMethods);
        return existingMethods;
    }

    /**
     * The GuessingWorker class performs the actual method guessing in terms of RMI calls. It implements Runnable and
     * is intended to be run within a thread pool. Each GuessingWorker gets assigned a Set of MethodCandidates and iterates
     * over the corresponding set. It uses the obtained RemoteObjectClient object to dispatch a call to the candidates and
     * inspects the server-side exception to determine whether the method exists on the remote object.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    private class GuessingWorker implements Runnable {

        private String boundName;
        private Set<MethodCandidate> candidates;
        private RemoteObjectClient client;
        private ConcurrentHashMap<String, ArrayList<MethodCandidate>> existingMethods;

        /**
         * Initialize the guessing worker with all the required information.
         *
         * @param client RemoteObjectClient to the targeted remote object
         * @param candidate MethodCanidates to guess
         * @param boundName BoundName that is currently guessed by this guesser
         * @param existingMethods Map of existing methods. If a candidate exists, it is pushed here
         */
        public GuessingWorker(RemoteObjectClient client, Set<MethodCandidate> candidates, String boundName, ConcurrentHashMap<String, ArrayList<MethodCandidate>> existingMethods)
        {
            this.client = client;
            this.boundName = boundName;
            this.candidates = candidates;
            this.existingMethods = existingMethods;
        }

        /**
         * This function is called when a guessed MethodCandidate exists. It creates a corresponding log entry and
         * saves the candidate within the results map.
         *
         * @param candidate MethodCandidate that was successfully guessed
         */
        private void logHit(MethodCandidate candidate)
        {
            String prefix = Logger.blue("[ " + Logger.padRight(boundName, padding) + " ] ");
            Logger.printlnMixedYellow(prefix + "HIT! Method with signature", candidate.getSignature(), "exists!");
            existingMethods.computeIfAbsent(boundName, k -> new ArrayList<MethodCandidate>()).add(candidate);
        }

        /**
         * Invokes the assigned MethodCandidates. Methods are invoked by using a specially crafting argument array.
         * The array is crafted in a way that method calls will never be fully dispatched on the server side while
         * simultaneously preventing corruption of the underlying TCP stream. This allows to reuse the TCP connection
         * during method guessing which makes the process much faster, especially on TLS protected connections.
         */
        public void run() {

            for( MethodCandidate candidate : candidates ) {

                try {
                    client.guessingCall(candidate);
                    logHit(candidate); // If there was no exception, the method exists (zero arg / valid call)

                } catch(java.rmi.ServerException e) {

                    Throwable cause = ExceptionHandler.getCause(e);

                    /*
                     * In case of an existing method, the specially crafted argument array that is used during guessing calls
                     * will always lead to one of the following exceptions. These are caught and indicate an existing method.
                     * One could also attempt to catch the 'unrecognized method hash' exception from the server to match non
                     * existing methods, but this requires an additional string compare that might be slower.
                     */
                    if( cause instanceof java.io.OptionalDataException || cause instanceof java.io.StreamCorruptedException) {
                        logHit(candidate);
                    }

                } catch(Exception e) {

                    /*
                     * If we end up here, an unexpected exception was raised that indicates a general error.
                     */
                    StringWriter writer = new StringWriter();
                    e.printStackTrace(new PrintWriter(writer));

                    String info = "Caught unexpected " + e.getClass().getName() + " during method guessing.\n"
                                 +"Please report this to improve rmg :)\n"
                                 +"Stack-Trace:\n"
                                 +writer.toString();

                    Logger.println(info);
                }
            }
        }
    }
}
