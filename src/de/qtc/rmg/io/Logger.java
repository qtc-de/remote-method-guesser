package de.qtc.rmg.io;

public class Logger {

    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";


    public static boolean verbose = true;

    public static void print(String msg) {
        if( Logger.verbose ) {
            System.out.print(msg);
        }
    }

    public static void eprint(String msg) {
        System.err.print(msg);
    }

    public static void println(String msg) {
        if( Logger.verbose ) {
            System.out.println(msg);
        }
    }

    public static void eprintln(String msg) {
        System.err.println(msg);
    }

    public static void println_bl(String msg) {
        if( Logger.verbose ) {
            System.out.println("[+]" + ANSI_BLUE + msg + ANSI_RESET);
        }
    }

    public static void eprintln_bl(String msg) {
        System.err.println("[+]" + ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void println_ye(String msg) {
        if( Logger.verbose ) {
            System.out.println("[+]" + ANSI_YELLOW + msg + ANSI_RESET);
        }
    }

    public static void eprintln_ye(String msg) {
        System.err.println("[+]" + ANSI_YELLOW + msg + ANSI_RESET);
    }

}
