package eu.tneitzel.rmg.internal;

import eu.tneitzel.argparse4j.global.IOptionGroup;

/**
 * The RMGOptionGroup enum is used to bundle certain options into a logical context. The corresponding
 * options can then be displayed within an ArgumentGroup inside of help menus. Arguments that should
 * not be displayed within a separate ArgumentGroup should set the RMGOptionGroup.NONE. Currently,
 * the RMGOptionGroup.ACTION is basically equivalent to RMGOptionGroup.NONE, but this may changes in
 * future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum RMGOptionGroup implements IOptionGroup
{
    /** SSRF related arguments */
    SSRF("ssrf arguments"),
    /** target related arguments */
    TARGET("target arguments"),
    /** connection related arguments */
    CONNECTION("connection arguments"),
    /** general arguments */
    GENERAL("general arguments"),
    /** action related arguments */
    ACTION("action arguments"),
    /** no option group */
    NONE("");

    private final String name;

    /**
     * RMGOptionGroups are initialized by the group name that should be displayed within the help menu.
     *
     * @param name ArgumentGroup name to display in the help menu
     */
    RMGOptionGroup(String name)
    {
        this.name = name;
    }

    @Override
    public String getName()
    {
        return name;
    }
}
