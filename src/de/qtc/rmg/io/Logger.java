package de.qtc.rmg.io;

public class Logger {

    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_BLUE = "\u001B[34m";

    public static int indent = 0;
    public static boolean verbose = true;

    private static String blue(String msg)
    {
        return ANSI_BLUE + msg + ANSI_RESET;
    }

    private static String yellow(String msg)
    {
        return ANSI_YELLOW + msg + ANSI_YELLOW;
    }

    private static String prefix()
    {
        return "[+]" + Logger.getIndent();
    }

    private static String eprefix()
    {
        return "[-]" + Logger.getIndent();
    }

    private static void log(String msg)
    {
        log(msg, false);
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
        elog(msg, false);
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
        log(prefix() + msg, true);
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
        elog(eprefix() + msg, true);
    }

    public static void eprintlnPlain(String msg)
    {
        elog(msg, true);
    }

    public static void printlnBlue(String msg)
    {
        log(prefix() + blue(msg), true);
    }

    public static void eprintlnBlue(String msg)
    {
        elog(prefix() + blue(msg), true);
    }

    public static void printlnYellow(String msg)
    {
        log(prefix() + yellow(msg), true);
    }

    public static void eprintlnYellow(String msg)
    {
        elog(prefix() + yellow(msg), true);
    }

    public static void printlnPlainBlue(String msg)
    {
        log(blue(msg), true);
    }

    public static void eprintlnPlainBlue(String msg)
    {
        elog(blue(msg), true);
    }

    public static void printlnPlainYellow(String msg)
    {
        log(yellow(msg), true);
    }

    public static void eprintlnPlainYellow(String msg)
    {
        elog(yellow(msg), true);
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
        elog(prefix() + first + " " + blue(second));
    }

    public static void eprintlnMixedBlue(String first, String second, String third)
    {
        elog(prefix() + first + " " + blue(second) + " " + third);
    }

    public static void eprintlnMixedYellow(String first, String second)
    {
        elog(prefix() + first + " " + yellow(second));
    }

    public static void eprintlnMixedYellow(String first, String second, String third)
    {
        elog(prefix() + first + " " + yellow(second) + " " + third);
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
            return " " + new String(new char[indent]).replace("\0", "\t");
        else
            return " ";
    }
}
