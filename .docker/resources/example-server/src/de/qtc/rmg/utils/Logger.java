package de.qtc.rmg.server.utils;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class Logger {

    public static int indent = 0;
    public static Calender cal = Calendar.getInstance();
    public static SimpleDateFormat date = new SimpleDateFormat("HH:mm:ss");

    private static String prefix()
    {
        return "[+] " + date.format(cal.getTime()) + Logger.getIndent();
    }

    private static String eprefix()
    {
        return "[-] " + date.format(cal.getTime()) + Logger.getIndent();
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
        return " " + new String(new char[indent]).replace("\0", "\t");
    }
}
