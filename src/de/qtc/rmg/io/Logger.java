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

    public static int indent = 0;
    public static boolean verbose = true;

    public static void print(String msg) {
        if( Logger.verbose ) {
            System.out.print("[+]" + Logger.getIndent() + msg);
        }
    }

    public static void eprint(String msg) {
        System.err.print("[-]" + Logger.getIndent() + msg);
    }

    public static void println(String msg) {
        if( Logger.verbose ) {
            System.out.println("[+]" + Logger.getIndent() + msg);
        }
    }

    public static void printlnPlain(String msg) {
        if( Logger.verbose ) {
            System.out.println(msg);
        }
    }

    public static void eprintln(String msg) {
        System.err.println("[-]" + Logger.getIndent() + msg);
    }

    public static void eprintlnPlain(String msg) {
        System.err.println(msg);
    }

    public static void println_bl(String msg) {
        if( Logger.verbose ) {
            System.out.println("[+]" + Logger.getIndent() + ANSI_BLUE + msg + ANSI_RESET);
        }
    }

    public static void eprintln_bl(String msg) {
        System.err.println("[-]" + Logger.getIndent() + ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void println_ye(String msg) {
        if( Logger.verbose ) {
            System.out.println("[+]" + Logger.getIndent() + ANSI_YELLOW + msg + ANSI_RESET);
        }
    }

    public static void eprintln_ye(String msg) {
        System.err.println("[-]" + Logger.getIndent() + ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void printlnPlain_bl(String msg) {
        if( Logger.verbose ) {
            System.out.println(ANSI_BLUE + msg + ANSI_RESET);
        }
    }

    public static void eprintlnPlain_bl(String msg) {
        System.err.println(ANSI_BLUE + msg + ANSI_RESET);
    }

    public static void printlnPlain_ye(String msg) {
        if( Logger.verbose ) {
            System.out.println(ANSI_YELLOW + msg + ANSI_RESET);
        }
    }

    public static void eprintlnPlain_ye(String msg) {
        System.err.println(ANSI_YELLOW + msg + ANSI_RESET);
    }

    public static void increaseIndent() {
        indent += 1;
    }

    public static void decreaseIndent() {
        indent -= 1;
    }

    public static String getIndent() {
        return " " + "\t".repeat(indent);
    }
}
