package de.qtc.rmg.internal;

import java.util.HashMap;

import de.qtc.rmg.operations.Operation;
import net.sourceforge.argparse4j.inf.ArgumentGroup;
import net.sourceforge.argparse4j.inf.ArgumentParser;

/**
 * The RMGOptionGroup enum is used to bundle certain options into a logical context. The corresponding
 * options can then be displayed within an ArgumentGroup inside of help menus. Arguments that should
 * not be displayed within a separate ArgumentGroup should set the RMGOptionGroup.NONE. Currently,
 * the RMGOptionGroup.ACTION is basically equivalent to RMGOptionGroup.NONE, but this may changes in
 * future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum RMGOptionGroup {

    SSRF("ssrf arguments"),
    TARGET("target arguments"),
    CONNECTION("connection arguments"),
    GENERAL("general arguments"),
    ACTION("action arguments"),
    NONE("");

    private final String name;
    private final HashMap<Operation,ArgumentGroup> argumentGroups;

    /**
     * RMGOptionGroups are initialized by the group name that should be displayed within the help menu.
     *
     * @param name ArgumentGroup name to display in the help menu
     */
    RMGOptionGroup(String name)
    {
        this.name = name;
        this.argumentGroups = new HashMap<Operation,ArgumentGroup>();
    }

    /**
     * Helper function that adds the ArgumentGroup to an ArgumentParser. Each remote-method-guesser operation
     * uses a separate subparser. Each subparser contains its own ArgumentGroup. Therefore, it is required to
     * create each ArgumentGroup for each operation.
     *
     * This function first checks whether the ArgumentGroup for the specified operation was already created.
     * If so, it is simply returned. Otherwise, it is created, added to the parser and added to an internally
     * stored HashMap for later use.
     *
     * @param argParser ArgumentParser to add the ArgumentGroup to
     * @param operation remote-method-guesser operation for the current ArgumentGroup
     * @return ArgumentGroup for the specified operation
     */
    public ArgumentGroup addArgumentGroup(ArgumentParser argParser, Operation operation)
    {
        ArgumentGroup group = argumentGroups.get(operation);

        if( group == null ) {
            group = argParser.addArgumentGroup(name);
            argumentGroups.put(operation, group);
        }

        return group;
    }
}