package eu.tneitzel.rmg.plugin;

import eu.tneitzel.argparse4j.global.IAction;
import eu.tneitzel.argparse4j.global.IOption;
import eu.tneitzel.rmg.internal.RMGOption;

public enum QuartzAction implements IAction
{
    VERSION("version", "get the version of the remote scheduler", new IOption[] {
            RMGOption.TARGET_HOST,
            RMGOption.TARGET_PORT,
            RMGOption.TARGET_BOUND_NAME,
    });

    private final String name;
    private final String desc;
    private final IOption[] options;

    QuartzAction(String name, String desc, IOption[] options)
    {
        this.name = name;
        this.desc = desc;
        this.options = options;
    }

    @Override
    public String getName()
    {
        return name;
    }

    @Override
    public String getDescription()
    {
        return desc;
    }

    @Override
    public IOption[] getOptions()
    {
        return options;
    }

}
