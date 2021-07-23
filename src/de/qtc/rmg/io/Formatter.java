package de.qtc.rmg.io;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import de.qtc.rmg.internal.CodebaseCollector;
import de.qtc.rmg.internal.MethodCandidate;
import de.qtc.rmg.operations.RemoteObjectClient;
import de.qtc.rmg.utils.RemoteObjectWrapper;

/**
 * The formatter class is used to print formatted output for the enum and guess operations.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Formatter {

    /**
     * Creates a formatted list of available bound names and their corresponding classes. Classes
     * are divided in known classes (classes that are available on the current class path) and
     * unknown classes (not available on the current class path). Furthermore, some other meta
     * information for each bound name is printed (TCP endpoint + ObjID).
     *
     * @param remoteObjects Array of RemoteObjectWrappers obtained from the RMI registry
     */
    public void listBoundNames(RemoteObjectWrapper[] remoteObjects)
    {
        Logger.printlnBlue("RMI registry bound names:");
        Logger.lineBreak();
        Logger.increaseIndent();

        if( remoteObjects.length == 0 ) {
            Logger.println("- No objects are bound to the registry.");
        }

        for(RemoteObjectWrapper remoteObject : remoteObjects) {

            Logger.printlnMixedYellow("-", remoteObject.boundName);
            Logger.increaseIndent();

            if(remoteObjects == null)
                continue;

            if( remoteObject.isKnown )
                Logger.printlnMixedBlue("-->", remoteObject.className, "(known class)");
            else
                Logger.printlnMixedBlue("-->", remoteObject.className, "(unknown class)");

            printLiveRef(remoteObject);
            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
    }

    /**
     * Prints a formatted list of successfully guessed remote methods.
     *
     * @param results Array of RemoteObjectClients containing the successfully guessed methods
     */
    public void listGuessedMethods(List<RemoteObjectClient> results)
    {
        if( results.isEmpty() ) {
            Logger.printlnBlue("No remote methods identified :(");
            return;
        }

        Logger.println("Listing successfully guessed methods:");
        Logger.lineBreak();
        Logger.increaseIndent();

        for(RemoteObjectClient client : results ) {

            List<MethodCandidate> methods = client.remoteMethods;

            Logger.printlnMixedBlue("-", String.join(" == ", client.getBoundNames()));
            Logger.increaseIndent();

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
     * to classes that their annotated with it. This function prints this HashMap in a human readable
     * format.
     */
    public void listCodeases()
    {
        Logger.printlnBlue("RMI server codebase enumeration:");
        Logger.lineBreak();
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

    /**
     * Print formatted output to display a LiveRef. To make fields more accessible, the ref needs to
     * be wrapped into an RemoteObjectWrapper first.
     *
     * @param ref RemoteObjectWrapper wrapper around a LiveRef
     */
    private void printLiveRef(RemoteObjectWrapper ref)
    {
        if(ref == null)
            return;

        Logger.print("    ");
        Logger.printPlainMixedBlue("Endpoint:", ref.getTarget());
        Logger.printlnPlainMixedBlue(" ObjID:", ref.objID.toString());
    }
}
