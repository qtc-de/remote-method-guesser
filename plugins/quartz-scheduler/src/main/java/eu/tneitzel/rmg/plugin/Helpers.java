package eu.tneitzel.rmg.plugin;

import org.quartz.core.RemotableQuartzScheduler;

import eu.tneitzel.rmg.internal.RMGOption;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.networking.RMIRegistryEndpoint;
import eu.tneitzel.rmg.operations.RemoteObjectClient;
import eu.tneitzel.rmg.utils.RMGUtils;

public class Helpers
{
    private static RemotableQuartzScheduler scheduler = null;

    public static RemotableQuartzScheduler getScheduler()
    {
        if (scheduler == null)
        {
            if (RMGOption.TARGET_BOUND_NAME.isNull())
            {
                Logger.printlnMixedYellow("The", "--bound-name", "option is required for all quartz actions.");
                RMGUtils.exit();
            }

            String host = RMGOption.TARGET_HOST.getValue();
            int port = RMGOption.TARGET_PORT.getValue();

            RMIRegistryEndpoint endpoint = new RMIRegistryEndpoint(host, port);
            RemoteObjectClient client = new RemoteObjectClient(endpoint, RMGOption.TARGET_BOUND_NAME.<String>getValue());

            scheduler = client.createProxy(RemotableQuartzScheduler.class);
        }

        return scheduler;
    }
}
