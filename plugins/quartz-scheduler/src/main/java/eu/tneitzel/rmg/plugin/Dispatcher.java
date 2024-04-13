package eu.tneitzel.rmg.plugin;

import java.rmi.RemoteException;
import java.util.Date;
import java.util.Set;

import org.quartz.DateBuilder;
import org.quartz.JobBuilder;
import org.quartz.JobKey;
import org.quartz.SchedulerException;
import org.quartz.SimpleScheduleBuilder;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.quartz.core.RemotableQuartzScheduler;
import org.quartz.impl.matchers.GroupMatcher;
import org.quartz.jobs.NativeJob;

import eu.tneitzel.rmg.internal.ExceptionHandler;
import eu.tneitzel.rmg.io.Logger;
import eu.tneitzel.rmg.utils.RMGUtils;

/*
 * The Dispatcher class is responsible for communicating with the Quartz scheduler and performs
 * the actual actions supported by the plugin. All functions obtain their arguments from the
 * global argument store.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher
{
    /*
     * Obtains the version number of the remote Quartz Scheduler and displays it.
     */
    public static void dispatchVersion() throws RemoteException
    {
        RemotableQuartzScheduler scheduler = Helpers.getScheduler();
        String version = scheduler.getVersion();

        Logger.printlnMixedYellow("Remote Quartz Scheduler version:", version);
    }

    /*
     * Schedules a new Native Job within the Quartz Scheduler. This can be used for execution
     * of operating system commands.
     */
    public static void dispatchScheduleJob() throws RemoteException
    {
        RemotableQuartzScheduler scheduler = Helpers.getScheduler();

        String cmd = QuartzOption.SCHEDULE_CMD.getValue();
        String jobName = String.format("rmg-job-%d", System.currentTimeMillis());

        jobName = QuartzOption.SCHEDULE_NAME.getValue(jobName);
        String jobGroup = QuartzOption.SCHEDULE_GROUP.getValue();

        Logger.printMixedBlue("Creating job", String.format("%s.%s", (jobGroup == null)? "DEFAULT" : jobGroup, jobName), "executing ");
        Logger.printlnPlainYellow(cmd);

        TriggerBuilder<Trigger> triggerBuilder = TriggerBuilder.newTrigger();

        if (QuartzOption.SCHEDULE_DATE.notNull())
        {
            String dateString = QuartzOption.SCHEDULE_DATE.getValue();

            Logger.printMixedBlue("Setting", "job execution time", "to:");
            Logger.printlnYellow(dateString);

            int[] dateInts = Helpers.parseDate(dateString);

            Date date = DateBuilder.dateOf(dateInts[0], dateInts[1], dateInts[2], dateInts[3], dateInts[4], dateInts[5]);
            triggerBuilder.startAt(date);
        }

        else
        {
            Logger.printMixedBlue("Setting", "job execution time", "to:");
            Logger.printlnYellow("Now");

            triggerBuilder.startNow();
        }

        if (QuartzOption.SCHEDULE_REPEAT.notNull())
        {
            int repeatRate = QuartzOption.SCHEDULE_REPEAT.getValue();

            Logger.printMixedBlue("Setting", "job repeat rate", "to:");
            Logger.printlnYellow(repeatRate + "m");

            SimpleScheduleBuilder scheduleBuilder = SimpleScheduleBuilder.simpleSchedule().withIntervalInMinutes(repeatRate);

            if (QuartzOption.SCHEDULE_REPEAT_COUNT.notNull())
            {
                int repeatCount = QuartzOption.SCHEDULE_REPEAT_COUNT.getValue();

                Logger.printMixedBlue("Setting", "job repeat count", "to:");
                Logger.printlnYellow(String.valueOf(repeatCount));

                scheduleBuilder.withRepeatCount(repeatCount);
            }

            else
            {
                Logger.printMixedBlue("Setting", "job repeat count", "to:");
                Logger.printlnYellow("Infinity");

                scheduleBuilder.repeatForever();
            }

            triggerBuilder.withSchedule(scheduleBuilder);
        }

        JobBuilder jobBuilder = JobBuilder.newJob(NativeJob.class);
        jobBuilder.withIdentity(jobName, jobGroup);
        jobBuilder.usingJobData(org.quartz.jobs.NativeJob.PROP_COMMAND, cmd);

        try
        {
            scheduler.scheduleJob(jobBuilder.build(), triggerBuilder.build());
        }

        catch (SchedulerException e)
        {
            Logger.printlnMixedYellow("Caught unexpected", "SchedulerException", "after scheduling the job.");
            ExceptionHandler.showStackTrace(e);

            RMGUtils.exit();
        }
    }

    /*
     * Delete one of the registered Jobs within the scheduler.
     */
    public static void dispatchDelete() throws RemoteException
    {
        RemotableQuartzScheduler scheduler = Helpers.getScheduler();

        String jobGroup = QuartzOption.DELETE_GROUP.getValue();
        String jobName = QuartzOption.DELETE_NAME.getValue();

        try
        {
            Logger.printlnMixedYellow("Deleting job", String.format("%s.%s", jobGroup, jobName));
            scheduler.deleteJob(new JobKey(jobName, jobGroup));
        }

        catch (SchedulerException e)
        {
            Logger.printlnMixedYellow("Caught unexpected", "SchedulerException", "after deleting job.");
            ExceptionHandler.showStackTrace(e);

            RMGUtils.exit();
        }
    }

    /*
     * List Jobs that are currently registered within sche scheduler.
     */
    public static void dispatchList() throws RemoteException
    {
        RemotableQuartzScheduler scheduler = Helpers.getScheduler();

        try
        {
            Logger.printlnYellow("Listing Jobs:");
            Set<JobKey> keys = scheduler.getJobKeys(GroupMatcher.anyGroup());

            for (JobKey job : keys)
            {
                Logger.printMixedBlue("\tGroup:", job.getGroup());
                Logger.printlnPlainMixedBlue(" Name:", job.getName());
            }
        }

        catch (SchedulerException e)
        {
            Logger.printlnMixedYellow("Caught unexpected", "SchedulerException", "after deleting job.");
            ExceptionHandler.showStackTrace(e);

            RMGUtils.exit();
        }
    }
}
