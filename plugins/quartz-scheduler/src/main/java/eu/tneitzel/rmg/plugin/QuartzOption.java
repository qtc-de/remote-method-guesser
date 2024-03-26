package eu.tneitzel.rmg.plugin;

import eu.tneitzel.argparse4j.global.IOption;
import eu.tneitzel.argparse4j.global.modifiers.IArgumentModifier;
import eu.tneitzel.argparse4j.global.modifiers.MetaVar;
import eu.tneitzel.argparse4j.impl.Arguments;
import eu.tneitzel.argparse4j.inf.ArgumentAction;

public enum QuartzOption implements IOption
{
    SCHEDULE_CMD("cmd",
                 "command to execute within the job",
                 Arguments.store(),
                 new IArgumentModifier[] {
                     new MetaVar("cmd")
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
