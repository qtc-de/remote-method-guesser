package eu.tneitzel.rmg.plugin;

import java.rmi.NoSuchObjectException;
import java.rmi.UnmarshalException;

import org.quartz.core.RemotableQuartzScheduler;

import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.networking.RMIRegistryEndpoint;
import eu.tneitzel.rmg.utils.RMGUtils;

/*
 * Different helper functions for various tasks.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Helpers
{
    private static RemotableQuartzScheduler scheduler = null;

    /*
     * Obtain a remote reference to the Quartz Scheduler. This function performs the RMI lookup
     * and saves the obtained ref within the scheduler variable for later use.
     */
    public static RemotableQuartzScheduler getScheduler()
    {
        if (scheduler == null)
        {
            String host = RMGOption.TARGET_HOST.getValue();
            int port = RMGOption.TARGET_PORT.getValue();

            try
            {
                RMIRegistryEndpoint endpoint = new RMIRegistryEndpoint(host, port);

                if (RMGOption.TARGET_BOUND_NAME.isNull())
                {
                    Logger.println("No bound name specified. Trying to find it automatically.");

                    for (String boundName : endpoint.getBoundNames())
                    {
                        try
                        {
                            scheduler = (RemotableQuartzScheduler)endpoint.lookup(boundName);
                            Logger.printlnMixedBlue("Found Quartz Scheduler with bound name:", boundName);

                            return scheduler;
                        }

                        catch (ClassCastException e)
                        {
                            continue;
                        }
                    }

                    Logger.printlnMixedRed("Quartz Scheduler bound name", "not found");
                    Logger.printlnMixedYellow("Try to specify it manually via the", "--bound-name", "option.");
                    RMGUtils.exit();
                }

                else
                {
                    scheduler = (RemotableQuartzScheduler)endpoint.lookup(RMGOption.TARGET_BOUND_NAME.<String>getValue());
                }
            }

            catch (UnmarshalException | NoSuchObjectException e)
            {
                Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "while calling the RMI registry.");
                RMGUtils.exit();
            }
        }

        return scheduler;
    }

    /*
     * Quartz Scheduler contains a function that creates a Date from six integers. This
     * function splits a user specified date string into these integers and returns them
     * as array.
     */
    public static int[] parseDate(String date)
    {
        int[] dateInts = new int[6];
        String[] split = date.split(":");

        if (split.length != 6)
        {
            Logger.printlnMixedYellow("Invalid date format. Format should be:", "hh:mm:ss:DD:MM:YYYY");
            RMGUtils.exit();
        }

        for (int ctr = 0; ctr < 6; ctr++)
        {
            dateInts[ctr] = Integer.parseInt(split[ctr]);
        }

        return dateInts;
    }
}
