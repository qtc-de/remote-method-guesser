package de.qtc.rmg.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

abstract class Security {

    public static boolean trusted = false;

    private static Pattern alphaNumeric = Pattern.compile("[a-zA-Z0-9]");
    private static Pattern jarFile = Pattern.compile("[a-zA-Z0-9]\\.jar");
    private static Pattern javaFile = Pattern.compile("[a-zA-Z0-9]\\.java");
    private static Pattern packageName = Pattern.compile("([a-zA-Z0-9]\\.?)+");
    private static Pattern shellInjection = Pattern.compile(".*[ '\"#&;`|*?~<>^()\\[\\]{}$\\\\\n].*");

    public static void checkAlphaNumeric(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = alphaNumeric.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' contains non alphanumeric characters.");
    }

    public static void checkPackageName(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = packageName.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' is not a valid package name.");
    }

    public static void checkJavaFile(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = javaFile.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' is not a valid .java file.");
    }

    public static void checkJarFile(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = jarFile.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' is not a valid .jar file.");
    }

    public static void checkShellInjection(String input) throws UnexpectedCharacterException {
        if( trusted )
            return;

        Matcher m = shellInjection.matcher(input);
        if( m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' contains shell injection characters.");
    }
}

@SuppressWarnings("serial")
class UnexpectedCharacterException extends Exception {
      public UnexpectedCharacterException() {}

      public UnexpectedCharacterException(String message) {
         super(message);
      }
 }
