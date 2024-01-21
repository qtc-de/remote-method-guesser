package eu.tneitzel.rmg.plugin;

import java.rmi.RemoteException;

import org.quartz.core.RemotableQuartzScheduler;

import eu.tneitzel.rmg.io.Logger;

public class Dispatcher
{
    public static void dispatchVersion() throws RemoteException
    {
        RemotableQuartzScheduler scheduler = Helpers.getScheduler();
        String version = scheduler.getVersion();

        Logger.printlnMixedYellow("Remote Quartz Scheduler version:", version);
    }
}
