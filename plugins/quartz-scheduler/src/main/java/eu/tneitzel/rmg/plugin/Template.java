package eu.tneitzel.rmg.plugin;

import eu.tneitzel.argparse4j.global.IAction;
import java.rmi.RemoteException;

/**
 * The Quartz Scheduler plugin implements IActionProvider to add additional
 * actions to remote method guesser.
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
            if (action == QuartzAction.VERSION)
            {
                Dispatcher.dispatchVersion();
            }

            else if (action == QuartzAction.SCHEDULE)
            {
                Dispatcher.dispatchScheduleJob();
            }
        }

        catch (RemoteException e)
        {
            e.printStackTrace();
        }
    }
}
