package de.qtc.rmg.server.ssrf.utils;

import java.text.SimpleDateFormat;
import java.util.Calendar;

/**
 * Logger class that helps to print some formatted output including timestamps.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Logger {

    private static String ANSI_RESET = "\u001B[0m";
    private static String ANSI_YELLOW = "\u001B[33m";
    private static String ANSI_BLUE = "\u001B[34m";

    public static int indent = 0;
    public static boolean verbose = true;
    public static Calendar cal = Calendar.getInstance();
    public static SimpleDateFormat date = new SimpleDateFormat("yyyy.MM.dd - HH:mm:ss");

    private static String blue(String msg)
    {
        return ANSI_BLUE + msg + ANSI_RESET;
    }

    private static String yellow(String msg)
    {
        return ANSI_YELLOW + msg + ANSI_RESET;
    }

    private static String prefix()
    {
        return "[" + date.format(cal.getTime()) + "]" + Logger.getIndent();
    }

    private static String eprefix()
    {
        return "[" + date.format(cal.getTime()) + "]" + Logger.getIndent();
    }

    private static void log(String msg)
    {
        log(msg, true);
    }

    private static void log(String msg, boolean newline)
    {
        if( Logger.verbose ) {

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
        if( newline )
            System.out.println(msg);
        else
            System.out.print(msg);
    }

    public static void print(String msg)
    {
        log(prefix() + msg, false);
    }

    public static void println(String msg)
    {
        log(prefix() + msg);
    }

    public static void printlnPlain(String msg)
    {
        log(msg, true);
    }

    public static void eprint(String msg)
    {
        elog(eprefix() + msg, false);
    }

    public static void eprintln(String msg)
    {
        elog(eprefix() + msg);
    }

    public static void eprintlnPlain(String msg)
    {
        elog(msg);
    }

    public static void printlnBlue(String msg)
    {
        log(prefix() + blue(msg));
    }

    public static void eprintlnBlue(String msg)
    {
        elog(prefix() + blue(msg));
    }

    public static void printlnYellow(String msg)
    {
        log(prefix() + yellow(msg));
    }

    public static void eprintlnYellow(String msg)
    {
        elog(prefix() + yellow(msg));
    }

    public static void printlnPlainBlue(String msg)
    {
        log(blue(msg));
    }

    public static void eprintlnPlainBlue(String msg)
    {
        elog(blue(msg));
    }

    public static void printlnPlainYellow(String msg)
    {
        log(yellow(msg));
    }

    public static void eprintlnPlainYellow(String msg)
    {
        elog(yellow(msg));
    }

    public static void printlnMixedBlue(String first, String second)
    {
        log(prefix() + first + " " + blue(second));
    }

    public static void printlnMixedBlue(String first, String second, String third)
    {
        log(prefix() + first + " " + blue(second) + " " + third);
    }

    public static void printlnMixedYellow(String first, String second)
    {
        log(prefix() + first + " " + yellow(second));
    }

    public static void printlnMixedYellow(String first, String second, String third)
    {
        log(prefix() + first + " " + yellow(second) + " " + third);
    }

    public static void eprintlnMixedBlue(String first, String second)
    {
        elog(eprefix() + first + " " + blue(second));
    }

    public static void eprintlnMixedBlue(String first, String second, String third)
    {
        elog(eprefix() + first + " " + blue(second) + " " + third);
    }

    public static void eprintlnMixedYellow(String first, String second)
    {
        elog(eprefix() + first + " " + yellow(second));
    }

    public static void eprintlnMixedYellow(String first, String second, String third)
    {
        elog(eprefix() + first + " " + yellow(second) + " " + third);
    }

    public static void printlnMixedBlueFirst(String first, String second)
    {
        log(prefix() + blue(first) + " " + second);
    }

    public static void printlnMixedBlueFirst(String first, String second, String third)
    {
        log(prefix() + blue(first) + " " + second + " " + blue(third));
    }

    public static void printlnMixedBlueYellow(String first, String second, String third)
    {
        log(prefix() + blue(first) + " " + second + " " + yellow(third));
    }

    public static void printlnMixedYellowFirst(String first, String second)
    {
        log(prefix() + yellow(first) + " " + second);
    }

    public static void printlnMixedYellowFirst(String first, String second, String third)
    {
        log(prefix() + yellow(first) + " " + second + " " + yellow(third));
    }

    public static void eprintlnMixedBlueFirst(String first, String second)
    {
        elog(eprefix() + blue(first) + " " + second);
    }

    public static void erintlnMixedBlueFirst(String first, String second, String third)
    {
        elog(eprefix() + blue(first) + " " + second + " " + blue(third));
    }

    public static void eprintlnMixedYellowFirst(String first, String second)
    {
        elog(eprefix() + yellow(first) + " " + second);
    }

    public static void eprintlnMixedYellowFirst(String first, String second, String third)
    {
        elog(eprefix() + yellow(first) + " " + second + " " + yellow(third));
    }

    public static void printMixedBlue(String first, String second)
    {
        log(prefix() + first + " " + blue(second), false);
    }

    public static void printlnPlainMixedBlue(String first, String second)
    {
        log(first + " " + blue(second), true);
    }

    public static void printlnPlainMixedBlue(String first, String second, String third)
    {
        log(first + " " + blue(second) + " " + third, true);
    }

    public static void printMixedBlue(String first, String second, String third)
    {
        log(prefix() + first + " " + blue(second) + " " + third, false);
    }

    public static void printMixedYellow(String first, String second)
    {
        log(prefix() + first + " " + yellow(second), false);
    }

    public static void printMixedYellow(String first, String second, String third)
    {
        log(prefix() + first + " " + yellow(second) + " " + third, false);
    }

    public static void eprintMixedBlue(String first, String second)
    {
        elog(eprefix() + first + " " + blue(second), false);
    }

    public static void eprintMixedBlue(String first, String second, String third)
    {
        elog(eprefix() + first + " " + blue(second) + " " + third, false);
    }

    public static void eprintMixedYellow(String first, String second)
    {
        elog(eprefix() + first + " " + yellow(second), false);
    }

    public static void eprintMixedYellow(String first, String second, String third)
    {
        elog(eprefix() + first + " " + yellow(second) + " " + third, false);
    }

    public static void printMixedBlueFirst(String first, String second)
    {
        log(prefix() + blue(first) + " " + second, false);
    }

    public static void printMixedBlueFirst(String first, String second, String third)
    {
        log(prefix() + blue(first) + " " + second + " " + blue(third), false);
    }

    public static void printMixedYellowFirst(String first, String second)
    {
        log(prefix() + yellow(first) + " " + second, false);
    }

    public static void printMixedYellowFirst(String first, String second, String third)
    {
        log(prefix() + yellow(first) + " " + second + " " + yellow(third), false);
    }

    public static void eprintMixedBlueFirst(String first, String second)
    {
        elog(eprefix() + blue(first) + " " + second, false);
    }

    public static void erintMixedBlueFirst(String first, String second, String third)
    {
        elog(eprefix() + blue(first) + " " + second + " " + blue(third), false);
    }

    public static void eprintMixedYellowFirst(String first, String second)
    {
        elog(eprefix() + yellow(first) + " " + second, false);
    }

    public static void eprintMixedYellowFirst(String first, String second, String third)
    {
        elog(eprefix() + yellow(first) + " " + second + " " + yellow(third), false);
    }

    public static void increaseIndent()
    {
        indent += 1;
    }

    public static void decreaseIndent()
    {
        indent -= 1;
    }

    public static String getIndent()
    {
        if( verbose )
            return " " + new String(new char[indent]).replace("\0", "    ");
        else
            return " ";
    }

    public static void disableColor()
    {
        ANSI_RESET = "";
        ANSI_YELLOW = "";
        ANSI_BLUE = "";
    }
}