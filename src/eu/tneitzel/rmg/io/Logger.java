package eu.tneitzel.rmg.io;

import eu.tneitzel.rmg.internal.RMGOption;

/**
 * The Logger class exposes static methods that can be used to create colored output.
 * Additionally, most of the methods add a '[+]' or '[-]' prefix. The Logger class
 * also handles a unified indent that can be increased or decreased by invoking classes.
 * This saves invoking classes from handle indentation manually. It is probably not the
 * prettiest approach, but it works quite nice :D
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Logger
{
    private static String ANSI_RESET = "\u001B[0m";
    private static String ANSI_YELLOW = "\u001B[33m";
    private static String ANSI_BLUE = "\u001B[34m";
    private static String ANSI_RED = "\u001B[31m";
    private static String ANSI_GREEN = "\u001B[32m";
    private static String ANSI_PURPLE = "\u001B[35m";

    /** current indent of the logger */
    public static int indent = 0;
    /** how many lines have already be printed */
    public static int printCount = 0;
    /** whether stdout is enabled */
    public static boolean stdout = true;
    /** whether stderr is enabled */
    public static boolean stderr = true;

    /**
     *
     */
    public static void disable() {
        Logger.stdout = false;
        Logger.stderr = false;
    }

    /**
     *
     */
    public static void disableStdout() {
        Logger.stdout = false;
    }

    /**
     *
     */
    public static void disableStderr() {
        Logger.stderr = false;
    }

    /**
     *
     */
    public static void disableIfNotVerbose() {
        if( !RMGOption.GLOBAL_VERBOSE.getBool() )
            disable();
    }

    /**
     *
     */
    public static void enable() {
        Logger.stdout = true;
        Logger.stderr = true;
    }

    /**
     *
     */
    public static void enableStdout() {
        Logger.stdout = true;
    }

    /**
     *
     */
    public static void enableStderr() {
        Logger.stderr = true;
    }

    /**
     * Format the specified string in blue.
     *
     * @param msg message to format
     * @return formatted message
     */
    public static String blue(String msg)
    {
        return ANSI_BLUE + msg + ANSI_RESET;
    }

    /**
     * Format the specified string in yellow.
     *
     * @param msg message to format
     * @return formatted message
     */
    public static String yellow(String msg)
    {
        return ANSI_YELLOW + msg + ANSI_RESET;
    }

    /**
     * Format the specified string in red.
     *
     * @param msg message to format
     * @return formatted message
     */
    public static String red(String msg)
    {
        return ANSI_RED + msg + ANSI_RESET;
    }

    /**
     * Format the specified string in purple.
     *
     * @param msg message to format
     * @return formatted message
     */
    public static String purple(String msg)
    {
        return ANSI_PURPLE + msg + ANSI_RESET;
    }

    /**
     * Format the specified string in green.
     *
     * @param msg message to format
     * @return formatted message
     */
    public static String green(String msg)
    {
        return ANSI_GREEN + msg + ANSI_RESET;
    }

    private static String prefix()
    {
        Logger.printCount++;
        return "[+]" + Logger.getIndent();
    }

    private static String eprefix()
    {
        Logger.printCount++;
        return "[-]" + Logger.getIndent();
    }

    private static void log(String msg)
    {
        log(msg, true);
    }

    private static void log(String msg, boolean newline)
    {
        if( Logger.stdout ) {

            if( newline )
                System.out.println(msg);
            else
                System.out.print(msg);
        }
    }

    private static void elog(String msg)
    {
        elog(msg, true);
    }

    private static void elog(String msg, boolean newline)
    {
        if( Logger.stderr ) {

            if( newline )
                System.err.println(msg);
            else
                System.err.print(msg);
        }
    }

    /**
     *
     */
    public static void lineBreak()
    {
        if( printCount != 0 ) {

            Logger.printCount++;
            log("[+]", true);
        }
    }

    /**
     * @param msg the message to log
     */
    public static void print(String msg)
    {
        log(prefix() + msg, false);
    }

    /**
     * @param msg the message to log
     */
    public static void printPlain(String msg)
    {
        log(msg, false);
    }

    /**
     * @param msg the message to log
     */
    public static void println(String msg)
    {
        log(prefix() + msg);
    }

    /**
     * @param msg the message to log
     */
    public static void printlnPlain(String msg)
    {
        log(msg, true);
    }

    /**
     * @param msg the message to log
     */
    public static void eprint(String msg)
    {
        elog(eprefix() + msg, false);
    }

    /**
     * @param msg the message to log
     */
    public static void eprintln(String msg)
    {
        elog(eprefix() + msg);
    }

    /**
     * @param msg the message to log
     */
    public static void eprintlnPlain(String msg)
    {
        elog(msg);
    }

    /**
     * @param msg the message to log
     */
    public static void printlnBlue(String msg)
    {
        log(prefix() + blue(msg));
    }

    /**
     * @param msg the message to log
     */
    public static void eprintlnBlue(String msg)
    {
        elog(prefix() + blue(msg));
    }

    /**
     * @param msg the message to log
     */
    public static void printlnYellow(String msg)
    {
        log(prefix() + yellow(msg));
    }

    /**
     * @param msg the message to log
     */
    public static void eprintlnYellow(String msg)
    {
        elog(prefix() + yellow(msg));
    }

    /**
     * @param msg the message to log
     */
    public static void printlnPlainBlue(String msg)
    {
        log(blue(msg));
    }

    /**
     * @param msg the message to log
     */
    public static void printPlainBlue(String msg)
    {
        log(blue(msg), false);
    }

    /**
     * @param msg the message to log
     */
    public static void printPlainGreen(String msg)
    {
        log(green(msg), false);
    }

    /**
     * @param msg the message to log
     */
    public static void printlnPlainGreen(String msg)
    {
        log(green(msg), true);
    }

    /**
     * @param msg the message to log
     */
    public static void eprintlnPlainBlue(String msg)
    {
        elog(blue(msg));
    }

    /**
     * @param msg the message to log
     */
    public static void printlnPlainYellow(String msg)
    {
        log(yellow(msg));
    }

    /**
     * @param msg the message to log
     */
    public static void printPlainYellow(String msg)
    {
        log(yellow(msg), false);
    }

    /**
     * @param msg the message to log
     */
    public static void eprintlnPlainYellow(String msg)
    {
        elog(yellow(msg));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnMixedRed(String first, String second)
    {
        log(prefix() + first + " " + red(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnPlainMixedRed(String first, String second)
    {
        log(first + " " + red(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printPlainMixedRed(String first, String second)
    {
        log(first + " " + red(second), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnMixedGreen(String first, String second)
    {
        log(prefix() + first + " " + green(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnPlainMixedGreen(String first, String second)
    {
        log(first + " " + green(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printPlainMixedGreen(String first, String second)
    {
        log(first + " " + green(second), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnMixedPurple(String first, String second)
    {
        log(prefix() + first + " " + purple(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnPlainMixedPurple(String first, String second)
    {
        log(first + " " + purple(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printPlainMixedPurple(String first, String second)
    {
        log(first + " " + purple(second), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnMixedBlue(String first, String second)
    {
        log(prefix() + first + " " + blue(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printlnMixedBlue(String first, String second, String third)
    {
        log(prefix() + first + " " + blue(second) + " " + third);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnMixedYellow(String first, String second)
    {
        log(prefix() + first + " " + yellow(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printlnMixedYellow(String first, String second, String third)
    {
        log(prefix() + first + " " + yellow(second) + " " + third);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnPlainMixedYellow(String first, String second)
    {
        log(first + " " + yellow(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printlnPlainMixedYellow(String first, String second, String third)
    {
        log(first + " " + yellow(second) + " " + third);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printPlainMixedYellowFirst(String first, String second) {
        log(yellow(first) + " " + second, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintPlainMixedYellowFirst(String first, String second) {
        elog(yellow(first) + " " + second, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnPlainMixedYellowFirst(String first, String second)
    {
        log(yellow(first) + " " + second);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printlnPlainMixedYellowFirst(String first, String second, String third)
    {
        log(yellow(first) + " " + second + " " + yellow(third));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnPlainMixedBlue(String first, String second)
    {
        log(first + " " + blue(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintlnPlainMixedBlue(String first, String second)
    {
        elog(first + " " + blue(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printlnPlainMixedBlue(String first, String second, String third)
    {
        log(first + " " + blue(second) + " " + third);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintlnPlainMixedBlue(String first, String second, String third)
    {
        elog(first + " " + blue(second) + " " + third);
    }


    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printPlainMixedBlue(String first, String second)
    {
        log(first + " " + blue(second), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printPlainMixedBlueFirst(String first, String second, String third)
    {
        log(blue(first) + " " + second + " " + blue(third), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintlnMixedBlue(String first, String second)
    {
        elog(eprefix() + first + " " + blue(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintlnMixedBlue(String first, String second, String third)
    {
        elog(eprefix() + first + " " + blue(second) + " " + third);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintlnMixedYellow(String first, String second)
    {
        elog(eprefix() + first + " " + yellow(second));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintlnMixedYellow(String first, String second, String third)
    {
        elog(eprefix() + first + " " + yellow(second) + " " + third);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnMixedBlueFirst(String first, String second)
    {
        log(prefix() + blue(first) + " " + second);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printlnMixedBlueFirst(String first, String second, String third)
    {
        log(prefix() + blue(first) + " " + second + " " + blue(third));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnPlainMixedBlueFirst(String first, String second)
    {
        log(blue(first) + " " + second);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintlnPlainMixedBlueFirst(String first, String second)
    {
        elog(blue(first) + " " + second);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintlnPlainMixedBlueFirst(String first, String second, String third)
    {
        elog(blue(first) + " " + second + " " +  blue(third));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printlnPlainMixedBlueFirst(String first, String second, String third)
    {
        log(blue(first) + " " + second + " " + blue(third));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printlnMixedYellowFirst(String first, String second)
    {
        log(prefix() + yellow(first) + " " + second);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printlnMixedYellowFirst(String first, String second, String third)
    {
        log(prefix() + yellow(first) + " " + second + " " + yellow(third));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintlnMixedBlueFirst(String first, String second)
    {
        elog(eprefix() + blue(first) + " " + second);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintlnMixedBlueFirst(String first, String second, String third)
    {
        elog(eprefix() + blue(first) + " " + second + " " + blue(third));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintlnMixedYellowFirst(String first, String second)
    {
        elog(eprefix() + yellow(first) + " " + second);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintlnMixedYellowFirst(String first, String second, String third)
    {
        elog(eprefix() + yellow(first) + " " + second + " " + yellow(third));
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printMixedBlue(String first, String second)
    {
        log(prefix() + first + " " + blue(second), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printMixedBlue(String first, String second, String third)
    {
        log(prefix() + first + " " + blue(second) + " " + third, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printMixedYellow(String first, String second)
    {
        log(prefix() + first + " " + yellow(second), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printMixedYellow(String first, String second, String third)
    {
        log(prefix() + first + " " + yellow(second) + " " + third, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintMixedBlue(String first, String second)
    {
        elog(eprefix() + first + " " + blue(second), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintMixedBlue(String first, String second, String third)
    {
        elog(eprefix() + first + " " + blue(second) + " " + third, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintMixedYellow(String first, String second)
    {
        elog(eprefix() + first + " " + yellow(second), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintMixedYellow(String first, String second, String third)
    {
        elog(eprefix() + first + " " + yellow(second) + " " + third, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printMixedBlueFirst(String first, String second)
    {
        log(prefix() + blue(first) + " " + second, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printMixedBlueFirst(String first, String second, String third)
    {
        log(prefix() + blue(first) + " " + second + " " + blue(third), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void printMixedYellowFirst(String first, String second)
    {
        log(prefix() + yellow(first) + " " + second, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void printMixedYellowFirst(String first, String second, String third)
    {
        log(prefix() + yellow(first) + " " + second + " " + yellow(third), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintMixedBlueFirst(String first, String second)
    {
        elog(eprefix() + blue(first) + " " + second, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintMixedBlueFirst(String first, String second, String third)
    {
        elog(eprefix() + blue(first) + " " + second + " " + blue(third), false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     */
    public static void eprintMixedYellowFirst(String first, String second)
    {
        elog(eprefix() + yellow(first) + " " + second, false);
    }

    /**
     * @param first the first part of the message to log
     * @param second the second part of the message to log
     * @param third the third part of the message to log
     */
    public static void eprintMixedYellowFirst(String first, String second, String third)
    {
        elog(eprefix() + yellow(first) + " " + second + " " + yellow(third), false);
    }

    /**
     *
     */
    public static void printInfoBox()
    {
        Logger.lineBreak();
        Logger.printlnBlue("Info:");
        Logger.increaseIndent();
        Logger.printlnBlue("--------------------------------");
    }

    /**
     *
     */
    public static void statusVulnerable()
    {
        printlnMixedRed("  Vulnerability Status:", "Vulnerable");
    }

    /**
     *
     */
    public static void statusOk()
    {
        printlnMixedGreen("  Vulnerability Status:", "Non Vulnerable");
    }

    /**
     *
     */
    public static void statusOutdated()
    {
        printlnMixedPurple("  Configuration Status:", "Outdated");
    }

    /**
     *
     */
    public static void statusDefault()
    {
        printlnMixedGreen("  Configuration Status:", "Current Default");
    }

    /**
     *
     */
    public static void statusNonDefault()
    {
        printlnMixedRed("  Configuration Status:", "Non Default");
    }

    /**
     * @param statusType
     */
    public static void statusUndecided(String statusType)
    {
        printlnMixedPurple("  " + statusType + " Status:", "Undecided");
    }

    /**
     *
     */
    public static void increaseIndent()
    {
        if(Logger.printCount != 0)
            indent += 1;
    }

    /**
     *
     */
    public static void decreaseIndent()
    {
        indent -= 1;
        if(indent < 0)
            indent = 0;
    }

    /**
     * @return the current Logger indent
     */
    public static String getIndent()
    {
        return " " + new String(new char[indent]).replace("\0", "\t");
    }

    /**
     *
     */
    public static void disableColor()
    {
        ANSI_RESET = "";
        ANSI_YELLOW = "";
        ANSI_BLUE = "";
        ANSI_RED = "";
        ANSI_GREEN = "";
        ANSI_PURPLE = "";
    }

    /**
     * @param endpointName
     * @param callName
     * @param className
     */
    public static void printCodebaseAttackIntro(String endpointName, String callName, String className)
    {
        Logger.printlnBlue("Attempting codebase attack on " + endpointName + " endpoint...");
        Logger.print("Using class ");
        Logger.printPlainMixedBlueFirst(className, "with codebase", MaliciousOutputStream.getDefaultLocation());
        Logger.printlnPlainMixedYellow(" during", callName, "call.");
        Logger.lineBreak();
        Logger.increaseIndent();
    }

    /**
     * @param endpointName
     */
    public static void printGadgetCallIntro(String endpointName)
    {
        Logger.lineBreak();
        Logger.printlnBlue("Attempting deserialization attack on " + endpointName + " endpoint...");
        Logger.lineBreak();
        Logger.increaseIndent();
    }

    /**
     * @param s the string to pad
     * @param n the padding to apply
     * @return padded string
     */
    public static String padRight(String s, int n) {
        return String.format("%-" + n + "s", s);
    }
}
