package eu.tneitzel.rmg.plugin;

import java.rmi.RemoteException;

import org.quartz.JobBuilder;
import org.quartz.JobDetail;
import org.quartz.SchedulerException;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.quartz.core.RemotableQuartzScheduler;
import org.quartz.jobs.NativeJob;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.utils.RMGUtils;

public class Dispatcher
{
    public static void dispatchVersion() throws RemoteException
    {
        RemotableQuartzScheduler scheduler = Helpers.getScheduler();
        String version = scheduler.getVersion();

        Logger.printlnMixedYellow("Remote Quartz Scheduler version:", version);
    }

    public static void dispatchScheduleJob() throws RemoteException
    {
        RemotableQuartzScheduler scheduler = Helpers.getScheduler();

        String cmd = QuartzOption.SCHEDULE_CMD.getValue();
        String jobName = String.format("rmg-job-%d", System.currentTimeMillis());

        Logger.printMixedBlue("Scheduling job", jobName, "executing ");
        Logger.printlnPlainYellow(cmd);

        JobDetail myJob = JobBuilder.newJob(NativeJob.class).withIdentity(jobName).usingJobData(org.quartz.jobs.NativeJob.PROP_COMMAND, cmd).build();
        Trigger myTrigger = TriggerBuilder.newTrigger().startNow().build();

        try
        {
            scheduler.scheduleJob(myJob, myTrigger);
        }

        catch (SchedulerException e)
        {
            Logger.printlnMixedYellow("Caught unexpected", "SchedulerException", "after scheduling the job.");
            ExceptionHandler.showStackTrace(e);

            RMGUtils.exit();
        }
    }
}
