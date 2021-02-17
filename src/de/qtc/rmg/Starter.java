package de.qtc.rmg;

import de.qtc.rmg.internal.ArgumentParser;
import de.qtc.rmg.io.Logger;
import de.qtc.rmg.operations.Dispatcher;
import de.qtc.rmg.utils.RMGUtils;

public class Starter {

    public static void main(String[] argv) {

        ArgumentParser parser = new ArgumentParser(argv);
        parser.checkArgumentCount(2);
        String action = parser.getAction();

        RMGUtils.init();
        RMGUtils.disableWarning();
        Dispatcher dispatcher = new Dispatcher(parser);

        switch( action ) {

            case "act":
                dispatcher.dispatchActivator();
                break;

            case "bind":
                dispatcher.dispatchBind();
                break;

            case "call":
                dispatcher.dispatchCall();
                break;

            case "codebase":
                dispatcher.dispatchCodebase();
                break;

            case "dgc":
                dispatcher.dispatchDGC();
                break;

            case "enum":
                dispatcher.dispatchEnum();
                break;

            case "guess":
                dispatcher.dispatchGuess();
                break;

            case "listen":
                dispatcher.dispatchListen();
                break;

            case "method":
                dispatcher.dispatchMethod();
                break;

            case "rebind":
                dispatcher.dispatchRebind();
                break;

            case "reg":
                dispatcher.dispatchRegistry();
                break;

            case "unbind":
                dispatcher.dispatchUnbind();
                break;

            default:
                Logger.printlnPlainMixedYellow("Unknown action:", action);
                parser.printHelp();
        }
    }
}
