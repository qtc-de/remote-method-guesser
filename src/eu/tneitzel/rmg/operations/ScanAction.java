package eu.tneitzel.rmg.operations;

import java.util.EnumSet;
import java.util.List;

import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.utils.RMGUtils;

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

        outer:
        for(String action : actions) {

            String actionName = action.toLowerCase();

            for(ScanAction item : ScanAction.values() ) {

                String itemName = item.name().toLowerCase();

                if(itemName.startsWith(actionName) || itemName.replace('_', '-').startsWith(actionName)) {
                    actionSet.add(item);
                    continue outer;
                }
            }

            Logger.eprintlnMixedYellow("Error: Unknown ScanAction", action, "was specified.");
            RMGUtils.exit();
        }

        return actionSet;
    }
}
