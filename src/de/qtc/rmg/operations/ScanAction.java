package de.qtc.rmg.operations;

import java.util.EnumSet;
import java.util.List;

/**
 * The ScanAction Enum represents available enumeration techniques that are applied during rmg's
 * enum action. It is used to allow users to specify custom enum configurations where only subsets
 * of the available enum methods are used. The main reason for adding this class was to support all
 * enumeration techniques during SSRF attacks.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum ScanAction {

    LIST,
    STRING_MARSHALLING,
    CODEBASE,
    LOCALHOST_BYPASS,
    SECURITY_MANAGER,
    JEP290,
    FILTER_BYPASS,
    ACTIVATOR;

    /**
     * Parses a list of user specified scan actions into the corresponding enum items. For an
     * user specified string to match an enum item, it is sufficient if the string starts with
     * the same character sequence as the enum item.
     *
     * @param actions User specified list of strings (requested enum techniques)
     * @return corresponding EnumSet containing the requested actions
     */
    public static EnumSet<ScanAction> parseScanActions(List<String> actions)
    {
        EnumSet<ScanAction> actionSet = EnumSet.noneOf(ScanAction.class);

        for(String action : actions) {
            for(ScanAction item : ScanAction.values() ) {
                if(item.name().toLowerCase().startsWith(action.toLowerCase())) {
                    actionSet.add(item);
                }
            }
        }

        return actionSet;
    }
}
