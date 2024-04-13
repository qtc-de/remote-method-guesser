package eu.tneitzel.rmg.plugin;

import eu.tneitzel.argparse4j.global.IAction;
import eu.tneitzel.argparse4j.global.IOption;
import eu.tneitzel.rmg.internal.RMGOption;

/*
 * Actions supported by the Quartz Scheduler plugin.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum QuartzAction implements IAction
{
    LIST("list", "list jobs registred within sche scheduler", new IOption[] {
            RMGOption.TARGET_HOST,
            RMGOption.TARGET_PORT,
            RMGOption.TARGET_BOUND_NAME,
    }),

    DELETE("delete", "delete a job from the scheduler", new IOption[] {
            RMGOption.TARGET_HOST,
            RMGOption.TARGET_PORT,
            RMGOption.TARGET_BOUND_NAME,
            QuartzOption.DELETE_GROUP,
            QuartzOption.DELETE_NAME,
    }),

    SCHEDULE("schedule", "schedule a NativeJob for command execution", new IOption[] {
            RMGOption.TARGET_HOST,
            RMGOption.TARGET_PORT,
            RMGOption.TARGET_BOUND_NAME,
            QuartzOption.SCHEDULE_CMD,
            QuartzOption.SCHEDULE_DATE,
            QuartzOption.SCHEDULE_NAME,
            QuartzOption.SCHEDULE_GROUP,
            QuartzOption.SCHEDULE_REPEAT,
            QuartzOption.SCHEDULE_REPEAT_COUNT,
    }),

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
