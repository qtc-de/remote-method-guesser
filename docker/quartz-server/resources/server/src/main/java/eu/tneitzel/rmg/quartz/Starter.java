package eu.tneitzel.rmg.quartz;

import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SchedulerFactory;
import org.quartz.SchedulerMetaData;
import org.quartz.impl.StdSchedulerFactory;

public class Starter
{
    public static void main(String[] args)
    {
        int jobsExecuted = 0;
        Scheduler sched  = null;

        try
        {
            System.out.println("[+] Creating a scheduler.");

            SchedulerFactory sf = new StdSchedulerFactory();
            sched = sf.getScheduler();

            System.out.println("[+] Starting scheduler.");
            sched.start();

            while (true)
            {
                SchedulerMetaData data = sched.getMetaData();

                if (data.getNumberOfJobsExecuted() > jobsExecuted)
                {
                    jobsExecuted = data.getNumberOfJobsExecuted();
                    System.out.println("[+] Number of executed jobs: " + jobsExecuted);
                }

                Thread.sleep(5000);
            }
        }

        catch (SchedulerException e)
        {
            System.out.println("[+] Caught SchedulerException:");
            e.printStackTrace();
        }

        catch (InterruptedException e)
        {
            System.out.println("[+] Aborted.:");
        }

        finally
        {
            if (sched == null)
            {
                return;
            }

            System.out.println("[+] Stopping scheduler.");

            try
            {
                sched.shutdown();
            }

            catch (SchedulerException e)
            {
                System.out.println("[+] Caught SchedulerException:");
                e.printStackTrace();
            }
        }
    }
}
