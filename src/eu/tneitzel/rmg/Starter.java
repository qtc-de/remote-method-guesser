package eu.tneitzel.rmg;

import eu.tneitzel.rmg.internal.ArgumentHandler;
import eu.tneitzel.rmg.operations.Dispatcher;
import eu.tneitzel.rmg.operations.Operation;
import eu.tneitzel.rmg.plugin.PluginSystem;
import eu.tneitzel.rmg.utils.RMGUtils;

/**
 * The Starter class contains the entrypoint of remote-method-guesser. It is responsible
 * for creating a Dispatcher object, that is used to dispatch the actual method call.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Starter
{
    /**
     * Main method :)
     *
     * @param argv  arguments passed to the program
     */
    public static void main(String[] argv)
    {
        String pluginPath = RMGUtils.getOption("--plugin", argv);
        PluginSystem.init(pluginPath);

        ArgumentHandler handler = new ArgumentHandler(argv);
        Operation operation = handler.getAction();

        RMGUtils.init();
        RMGUtils.disableWarning();
        RMGUtils.enableCodebaseCollector();
        Dispatcher dispatcher = new Dispatcher(handler);

        operation.invoke(dispatcher);
    }
}
