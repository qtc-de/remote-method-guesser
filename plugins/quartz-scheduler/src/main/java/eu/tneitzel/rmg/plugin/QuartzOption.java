package eu.tneitzel.rmg.plugin;

import eu.tneitzel.argparse4j.global.IOption;
import eu.tneitzel.argparse4j.global.modifiers.IArgumentModifier;
import eu.tneitzel.argparse4j.global.modifiers.MetaVar;
import eu.tneitzel.argparse4j.global.modifiers.Type;
import eu.tneitzel.argparse4j.impl.Arguments;
import eu.tneitzel.argparse4j.inf.ArgumentAction;

/*
 * Options supported by the Quartz Scheduler plugin.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum QuartzOption implements IOption
{
    SCHEDULE_CMD("cmd",
                 "command to execute within the job",
                 Arguments.store(),
                 new IArgumentModifier[] {
                     new MetaVar("cmd")
                 }),

    SCHEDULE_DATE("--date",
            "date to execute the job (format: hh:mm:ss:DD.MM.YYYY)",
            Arguments.store(),
            new IArgumentModifier[] {
                new MetaVar("date")
            }),

    SCHEDULE_NAME("--name",
            "name of the job to add",
            Arguments.store(),
            new IArgumentModifier[] {
                new MetaVar("name")
            }),

    SCHEDULE_GROUP("--group",
            "name of the group to add the job to",
            Arguments.store(),
            new IArgumentModifier[] {
                new MetaVar("name")
            }),

    SCHEDULE_REPEAT("--repeat",
            "repeat the job after the specified amount of minutes",
            Arguments.store(),
            new IArgumentModifier[] {
                new Type(int.class),
                new MetaVar("minutes")
            }),

    SCHEDULE_REPEAT_COUNT("--repeat-count",
            "how often to repeat the command",
            Arguments.store(),
            new IArgumentModifier[] {
                new Type(int.class),
                new MetaVar("n")
            }),


    DELETE_GROUP("group",
            "name of the group to delete the job from",
            Arguments.store(),
            new IArgumentModifier[] {
                new MetaVar("name")
            }),

    DELETE_NAME("name",
            "name of the job to delete",
            Arguments.store(),
            new IArgumentModifier[] {
                new MetaVar("name")
            });


     /** the name of the option */
    private final String name;
    /** description of the option */
    private final String description;
    /** argumentAction of the option */
    private final ArgumentAction argumentAction;
    /** argumentModifier of the option */
    private final IArgumentModifier[] modifiers;
    /** the value of the option */
    public Object value = null;

    /**
     * Initialize a QuartzOption.
     *
     * @param name the name of the option
     * @param description the description of the option
     * @param argumentAction the associated argument action (store, storeTrue, etc.)
     */
    QuartzOption(String name, String description, ArgumentAction argumentAction)
    {
        this(name, description, argumentAction, new IArgumentModifier[] {});
    }

    /**
     * Initialize a QuartzOption.
     *
     * @param name the name of the option
     * @param description the description of the option
     * @param argumentAction the associated argument action (store, storeTrue, etc.)
     * @param modifiers the argumentModifiers for the option
     */
    QuartzOption(String name, String description, ArgumentAction argumentAction, IArgumentModifier[] modifiers)
    {
        this.name = name;
        this.description = description;
        this.argumentAction = argumentAction;
        this.modifiers = modifiers;
    }

    public String getName()
    {
        return name;
    }

    public String getDescription()
    {
        return description;
    }

    public ArgumentAction getArgumentAction()
    {
        return argumentAction;
    }

    public IArgumentModifier[] getArgumentModifiers()
    {
        return modifiers;
    }

    public void setValue(Object value)
    {
        this.value = value;
    }

    public <T> T getValue(T def)
    {
        T value = this.getValue();

        if (value == null)
        {
            return def;
        }

        return value;
    }

    public <T> T getValue()
    {
        try
        {
            return (T)value;
        }

        catch (ClassCastException e) {}

        return null;
    }
}
