package eu.tneitzel.rmg.plugin;

import eu.tneitzel.argparse4j.global.IAction;
import java.rmi.RemoteException;

/**
 * The Quartz Scheduler plugin implements IActionProvider to add additional
 * actions to remote method guesser.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Template implements IActionProvider
{
    @Override
    public IAction[] getActions()
    {
        return QuartzAction.values();
    }

    @Override
    public void dispatch(IAction action)
    {
        try
        {
            if (action == QuartzAction.LIST)
            {
                Dispatcher.dispatchList();
            }

            if (action == QuartzAction.DELETE)
            {
                Dispatcher.dispatchDelete();
            }

            else if (action == QuartzAction.SCHEDULE)
            {
                Dispatcher.dispatchScheduleJob();
            }

            else if (action == QuartzAction.VERSION)
            {
                Dispatcher.dispatchVersion();
            }
        }

        catch (RemoteException e)
        {
            e.printStackTrace();
        }
    }
}
