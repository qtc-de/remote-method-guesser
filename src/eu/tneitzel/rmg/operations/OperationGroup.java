package eu.tneitzel.rmg.operations;

import eu.tneitzel.argparse4j.global.IActionGroup;

/**
 * When plugins implement IActionProvider, they can add additional arguments
 * to rmg. In this case, we use the IActionGroup to distinguish from plugin and
 * native actions.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum OperationGroup implements IActionGroup
{
	/** Native rmg operations */
    NATIVE("actions:"),
    /** Operations added by plugins */
    PLUGIN("plugin actions:");

    private final String name;

    OperationGroup(String name)
    {
        this.name = name;
    }

    @Override
    public String getName()
    {
        return name;
    }
}
