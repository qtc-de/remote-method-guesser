package eu.tneitzel.rmg.plugin;

import eu.tneitzel.argparse4j.global.IAction;
import java.rmi.RemoteException;

/**
 * The Template class represents a template to develop remote-method-guesser plugins.
 * It implements all the available plugin interfaces, but only uses placeholder implementations.
 * If you want to build a plugin from it, remove the interfaces and methods that you do not
 * intend to use. Other methods need to be overwritten with actual useful implementations.
 *
 * When changing the class name, make sure to also change the RmgPluginClass entry within the
 * pom.xml file.
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
        }

        catch (RemoteException e)
        {
            e.printStackTrace();
        }
    }
}
