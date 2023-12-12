package eu.tneitzel.rmg.io;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import eu.tneitzel.rmg.endpoints.KnownEndpoint;
import eu.tneitzel.rmg.endpoints.Vulnerability;
import eu.tneitzel.rmg.internal.CodebaseCollector;
import eu.tneitzel.rmg.internal.MethodCandidate;
import eu.tneitzel.rmg.operations.RemoteObjectClient;
import eu.tneitzel.rmg.utils.ActivatableWrapper;
import eu.tneitzel.rmg.utils.RemoteObjectWrapper;
import eu.tneitzel.rmg.utils.SpringRemotingWrapper;
import eu.tneitzel.rmg.utils.UnicastWrapper;

/**
 * The formatter class is used to print formatted output for the enum and guess operations.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Formatter
{
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

        if (remoteObjects == null || remoteObjects.length == 0)
        {
            Logger.println("- No objects are bound to the registry.");
            return;
        }

        for (RemoteObjectWrapper remoteObject : remoteObjects)
        {
            Logger.printlnMixedYellow("-", remoteObject.boundName);

            if (remoteObject.remoteObject == null)
            {
                continue;
            }

            Logger.increaseIndent();

            if (remoteObject.isKnown())
            {
                Logger.printMixedBlue("-->", remoteObject.getInterfaceName(), "");
                remoteObject.knownEndpoint.printEnum();
            }

            else
            {
                Logger.printMixedBlue("-->", remoteObject.getInterfaceName());
                Logger.printlnPlainMixedPurple("", "(unknown class)");
            }

            printRemoteRef(remoteObject);
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
        if (results.isEmpty())
        {
            Logger.printlnBlue("No remote methods identified :(");
            return;
        }

        Logger.println("Listing successfully guessed methods:");
        Logger.lineBreak();
        Logger.increaseIndent();

        for (RemoteObjectClient client : results)
        {
            List<MethodCandidate> methods = client.remoteMethods;

            Logger.printlnMixedBlue("-", String.join(" == ", client.getBoundNames()));
            Logger.increaseIndent();

            for (MethodCandidate m : methods)
            {
                if (client.remoteObject instanceof SpringRemotingWrapper)
                {
                    Logger.printlnMixedYellow("-->",SpringRemotingWrapper.getSignature(m));
                }

                else
                {
                    Logger.printlnMixedYellow("-->", m.getSignature());
                }
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
    public void listCodebases()
    {
        Logger.printlnBlue("RMI server codebase enumeration:");
        Logger.lineBreak();
        Logger.increaseIndent();

        HashMap<String,Set<String>> codebases = CodebaseCollector.getCodebases();
        if (codebases.isEmpty())
        {
            Logger.printlnMixedYellow("- The remote server", "does not", "expose any codebases.");
            Logger.decreaseIndent();
            return;
        }

        for (Entry<String,Set<String>> item : codebases.entrySet())
        {
            Logger.printlnMixedYellow("-", item.getKey());
            Logger.increaseIndent();

            Iterator<String> iterator = item.getValue().iterator();
            while (iterator.hasNext())
            {
                Logger.printlnMixedBlue("-->", iterator.next());
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
    }

    /**
     * Prints the meta information contained in a KnownEndpoint in formatted way. This function
     * generates the output that is displayed when using remote-method-guesser's 'known' action.
     *
     * @param knownEndpoint The KnownEndpoint to print
     */
    public void listKnownEndpoint(KnownEndpoint knownEndpoint)
    {
        Logger.printlnBlue("Name:");
        Logger.increaseIndent();

        Logger.printlnYellow(knownEndpoint.getName());
        Logger.decreaseIndent();
        Logger.lineBreak();

        Logger.printlnBlue("Class Name:");
        Logger.increaseIndent();

        for (String className : knownEndpoint.getClassName())
        {
            Logger.printlnMixedYellow("-", className);
        }

        Logger.decreaseIndent();
        Logger.lineBreak();

        Logger.printlnBlue("Description:");
        Logger.increaseIndent();

        String[] lines = knownEndpoint.getDescription().split("\n");

        for (String line : lines)
        {
            Logger.printlnYellow(line);
        }

        Logger.decreaseIndent();
        Logger.lineBreak();

        Logger.printlnBlue("Remote Methods:");
        Logger.increaseIndent();

        for (String remoteMethod : knownEndpoint.getRemoteMethods())
        {
            Logger.printlnMixedYellow("-", remoteMethod);
        }

        Logger.decreaseIndent();
        Logger.lineBreak();

        Logger.printlnBlue("References:");
        Logger.increaseIndent();

        for (String reference : knownEndpoint.getReferences())
        {
            Logger.printlnMixedYellow("-", reference);
        }

        Logger.decreaseIndent();
        listVulnerabilities(knownEndpoint.getVulnerabilities());
    }

    /**
     * Print vulnerability information contained within a KnownEndpoint in a formatted way.
     * This function is called by listKnownEndpoint to display vulnerabilities that are known
     * for the corresponding endpoint.
     *
     * @param vulns List of vulnerabilities to display
     */
    private void listVulnerabilities(List<Vulnerability> vulns)
    {
        if (vulns == null || vulns.size() == 0)
        {
            return;
        }

        Logger.lineBreak();
        Logger.printlnBlue("Vulnerabilities:");
        Logger.increaseIndent();

        for (Vulnerability vuln : vulns)
        {
            Logger.lineBreak();
            Logger.printlnBlue("-----------------------------------");

            Logger.printlnBlue("Name:");
            Logger.increaseIndent();

            Logger.printlnYellow(vuln.getName());
            Logger.decreaseIndent();
            Logger.lineBreak();

            Logger.printlnBlue("Description:");
            Logger.increaseIndent();

            String[] lines = vuln.getDescription().split("\n");

            for (String line : lines)
            {
                Logger.printlnYellow(line);
            }

            Logger.decreaseIndent();
            Logger.lineBreak();

            Logger.printlnBlue("References:");
            Logger.increaseIndent();

            for (String reference : vuln.getReferences())
            {
                Logger.printlnMixedYellow("-", reference);
            }

            Logger.decreaseIndent();
        }
    }

    /**
     * Checks whether the specified RemoteObjectWrapper is a UnicastWrapper or an
     * ActivatableWrapper and calls the corresponding function accordingly.
     *
     * @param wrapper RemoteObjectWrapper containing the RemoteRef
     */
    private void printRemoteRef(RemoteObjectWrapper wrapper)
    {
        if (wrapper instanceof SpringRemotingWrapper)
        {
            printSpringRemoting((SpringRemotingWrapper)wrapper);
        }

        else if (wrapper instanceof UnicastWrapper)
        {
            printUnicastRef((UnicastWrapper)wrapper);
        }

        else
        {
            printActivatableRef((ActivatableWrapper)wrapper);
        }
    }

    /**
     * Print information on a SpringRemotingWrapper. This information includes the real
     * interface name that can be accessed via the spring remoting wrapper and all information
     * that is printed by the printUnicastRef method.
     *
     * @param ref SpringRemotingWrapper containing the wrapper
     */
    private void printSpringRemoting(SpringRemotingWrapper ref)
    {
        String interfaceName = ref.getInterfaceName();

        if (interfaceName != null)
        {
            Logger.print("    ");
            Logger.printlnPlainMixedPurple("Spring Remoting Interface:", interfaceName);
        }

        printUnicastRef((UnicastWrapper)ref);
    }

    /**
     * Print information on a UnicastRef. This information includes the remote
     * endpoint, whether it uses TLS and the ObjID of the associated remote object.
     *
     * @param ref UnicastWrapper containing the UnicastRef
     */
    private void printUnicastRef(UnicastWrapper ref)
    {
        if (ref == null || ref.remoteObject == null)
        {
            return;
        }

        Logger.print("    ");
        Logger.printPlainMixedBlue("Endpoint:", ref.getTarget());

        switch (ref.isTLSProtected())
        {
            case 1:
                Logger.printPlainMixedGreen("  TLS:", "yes");
                break;

            case -1:
                Logger.printPlainMixedRed("  TLS:", "no");
                break;

            default:
                Logger.printPlainMixedPurple("  TLS:", "unknown");
        }

        Logger.printlnPlainMixedBlue("  CLS:", ref.getSocketFactoryClassName());
        Logger.printlnPlainMixedBlue("  ObjID:", ref.objID.toString());
    }

    /**
     * Print some more information on a ActivatableRef. This always includes
     * the endpoint of the corresponding Activator instance and the associated
     * ActivationID. If the ActivatableRef was already activated, the associated
     * UnicastRef information is also printed, as in the case of printUnicastRef.
     *
     * @param ref ActivatableWrapper containing the activatable ref
     */
    private void printActivatableRef(ActivatableWrapper ref)
    {
        if (ref == null || ref.remoteObject == null)
        {
            return;
        }

        Logger.print("    ");
        Logger.printPlainMixedBlue("Activator:", ref.getActivatorEndpoint());
        Logger.printlnPlainMixedBlue("  ActivationID:", ref.activationUID.toString());

        UnicastWrapper unicastRef = ref.getActivated();
        if (unicastRef != null)
        {
            printUnicastRef(unicastRef);
        }
    }
}
