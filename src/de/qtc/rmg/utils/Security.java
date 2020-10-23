package de.qtc.rmg.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class Security {

    public static boolean trusted = false;

    private static Pattern boundName = Pattern.compile("[a-zA-Z0-9_-]+");
    private static Pattern className = Pattern.compile("[a-zA-Z0-9_]+");
    private static Pattern jarFile = Pattern.compile("([a-zA-Z0-9_])+\\.jar");
    private static Pattern javaFile = Pattern.compile("([a-zA-Z0-9_])+\\.java");
    private static Pattern packageName = Pattern.compile("([a-zA-Z0-9_]\\.?)+");
    private static Pattern shellInjection = Pattern.compile(".*[ '\"#&;`|*?~<>^()\\[\\]{}$\\\\\n].*");

    public static void checkBoundName(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = boundName.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Bound name '" + input + "' contains invalid characters.");
    }

    public static void checkClassName(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = className.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' contains invalid characters.");
    }

    public static void checkPackageName(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = packageName.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Package name '" + input + "' contains invalid characters.");
    }

    public static void checkJavaFile(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = javaFile.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Filename '" + input + "' contains invalid characters.");
    }

    public static void checkJarFile(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = jarFile.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Jar name '" + input + "' contains invalid characters.");
    }

    public static void checkShellInjection(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = shellInjection.matcher(input);
        if( m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' contains shell injection characters.");
    }
}

