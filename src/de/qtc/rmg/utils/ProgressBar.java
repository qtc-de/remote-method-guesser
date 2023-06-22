package de.qtc.rmg.utils;

import de.qtc.rmg.internal.RMGOption;
import de.qtc.rmg.io.Logger;

/**
 * Simple progress bar that is used during the guess and scan operations.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ProgressBar {

    private int done;
    private int work;
    private final int length;
    private final String formatString;

    /**
     * Initialize the progress bar with the amount of work and the desired length.
     *
     * @param work Amount of work that needs to be done
     * @param length Length of the actual progress bar (# - part)
     */
    public ProgressBar(int work, int length)
    {
        this.work = work;
        this.length = length;
        this.done = 0;

        int digits = String.valueOf(work).length();
        this.formatString = "[%" + String.valueOf(digits) + "d / %d] [%s] %3d%%\r";
    }

    /**
     * During the scan action, the amount of work may increases and we need a function
     * to increase the value.
     */
    public synchronized void addWork()
    {
        if(RMGOption.NO_PROGRESS.getBool() == true)
            return;

        this.work += 1;
    }

    /**
     * Is called for each task that is done. Increases the number of done tasks and
     * updates the progress bar.
     */
    public synchronized void taskDone()
    {
        if(RMGOption.NO_PROGRESS.getBool() == true)
            return;

        this.done += 1;
        printBar();
    }

    /**
     * Prints the current progress bar to stdout.
     */
    private void printBar()
    {
        float progress = (float)done / work;

        int percentage = (int) Math.round(progress * 100);
        int barLength = (int) Math.round(progress * length);

        String progressBar = new String(new char[barLength]).replace("\0", "#");
        progressBar = progressBar + new String(new char[length - barLength]).replace("\0", " ");
        progressBar = String.format(formatString, done, work, progressBar, percentage);

        Logger.print(progressBar);
    }
}
