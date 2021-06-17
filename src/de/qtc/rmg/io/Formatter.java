package de.qtc.rmg.io;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import de.qtc.rmg.internal.CodebaseCollector;
import de.qtc.rmg.internal.MethodCandidate;

/**
 * The Formatter class is basically a legacy class. In previous versions, rmg supported JSON
 * output and the formatter was used to print results either as plain text or as JSON. In
 * current versions, JSON support was removed, which make the class basically no longer required.
 * It will be probably removed in future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Formatter {

    /**
     * Creates a formatted list of available bound names and their corresponding classes. Classes
     * are divided in known classes (classes that are available on the current class path) and
     * unknown classes (not available on the current class path).
     *
     * @param classes array of maps containing boundname-classes pairs
     */
    public void listBoundNames(HashMap<String,String>[] classes)
    {
        HashMap<String,String> knownClasses = classes[0];
        HashMap<String,String>  unknownClasses = classes[1];

        Logger.printlnBlue("RMI registry bound names:");
        Logger.println("");
        Logger.increaseIndent();

        Set<String> boundNames = new HashSet<String>();
        boundNames.addAll(knownClasses.keySet());
        boundNames.addAll(unknownClasses.keySet());

        if( boundNames.size() == 0 ) {
            Logger.println("- No objects are bound to the registry.");
        }

        for( String name : boundNames ) {

            Logger.printlnMixedYellow("-", name);

            if( knownClasses == null || unknownClasses == null ) {
                continue;
            }

            Logger.increaseIndent();

            if( knownClasses.containsKey(name) ) {
                Logger.printlnMixedBlue("-->", knownClasses.get(name), "(known class)");
            }

            if( unknownClasses.containsKey(name) ) {
                Logger.printlnMixedBlue("-->", unknownClasses.get(name), "(unknown class)");
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
    }

    /**
     * Prints a formatted list of successfully guessed remote methods.
     *
     * @param results HashMap that contains the guessed MethodCandidates for each bound name
     */
    public void listGuessedMethods(Map<String, ArrayList<MethodCandidate>> results)
    {
        if( results.size() == 0 ) {
            Logger.printlnBlue("No remote methods identified :(");
            return;
        }

        Logger.println("Listing successfully guessed methods:");
        Logger.increaseIndent();

        SortedSet<String> boundNames = new TreeSet<String>(results.keySet());

        for(String boundName : boundNames ) {

            ArrayList<MethodCandidate> methods = results.get(boundName);

            Logger.printlnMixedBlue("-", boundName);
            Logger.increaseIndent();

            if(methods.size() == 0)
                Logger.printlnMixedYellow("-->", "0 remote methods have been identified.");

            for( MethodCandidate m : methods ) {
                Logger.printlnMixedYellow("-->", m.getSignature());
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
    }

    /**
     * Lists enumerated codebases exposed by the RMI server. The corresponding information is fetched
     * from a static method on the CodebaseCollector class. It returns a HashMap that maps codebases
     * to classes that their annotated with the corresponding codebase during RMI communication.
     */
    public void listCodeases()
    {
        Logger.printlnBlue("RMI server codebase enumeration:");
        Logger.println("");
        Logger.increaseIndent();

        HashMap<String,Set<String>> codebases = CodebaseCollector.getCodebases();
        if(codebases.isEmpty()) {
            Logger.printlnMixedYellow("- The remote server", "does not", "expose any codebases.");
            Logger.decreaseIndent();
            return;
        }

        for( Entry<String,Set<String>> item : codebases.entrySet() ) {

            Logger.printlnMixedYellow("-", item.getKey());
            Logger.increaseIndent();

            Iterator<String> iterator = item.getValue().iterator();
            while( iterator.hasNext() ) {
                Logger.printlnMixedBlue("-->", iterator.next());
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
    }
}
