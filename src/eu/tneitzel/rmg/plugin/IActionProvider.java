package eu.tneitzel.rmg.plugin;

import eu.tneitzel.argparse4j.global.IAction;

/**
 * The IActionProvider interface can be implemented by plugins to add custom actions to
 * remote-method-guesser. All actions provided by the getActions method will be added to
 * the command line. If the user decides to invoke such an action, the dispatch action is
 * called with the selected action as argument.
 *
 * @author Tobias Neitzel (@qtc_de)
 */

public interface IActionProvider
{
    /**
     * Return all actions that get added by the plugin.
     *
     * @return actions that are added by the plugin
     */
    IAction[] getActions();

    /**
     * Is called by remote-method-guesser if the user specified an action that was defined
     * by the plugin.
     *
     * @param action the action specified by the user
     */
    void dispatch(IAction action);
}
