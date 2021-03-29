package de.qtc.rmg;

import de.qtc.rmg.internal.ArgumentParser;
import de.qtc.rmg.operations.Dispatcher;
import de.qtc.rmg.operations.Operation;
import de.qtc.rmg.utils.RMGUtils;

public class Starter {

    public static void main(String[] argv) {

        ArgumentParser parser = new ArgumentParser(argv);
        parser.checkArgumentCount(2);
        Operation operation = parser.getAction();

        RMGUtils.init();
        RMGUtils.disableWarning();
        Dispatcher dispatcher = new Dispatcher(parser);

        operation.invoke(dispatcher);
    }
}
