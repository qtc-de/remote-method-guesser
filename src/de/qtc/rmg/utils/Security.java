package de.qtc.rmg.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.qtc.rmg.exceptions.UnexpectedCharacterException;
import de.qtc.rmg.internal.RMGOption;

/**
 * During sample creation, remote-method-guesser creates sample files with filenames and contents controlled by
 * the remote RMI server. Especially the bound names registered within the registry are dangerous, as they can
 * contain arbitrary characters. To prevent path traversal attacks or injections into the generated Java code,
 * the Security class implements some filtering mechanisms that restrict the allowed characters during sample
 * generation.
 *
 * The filtering is very restrictive and should cause problems with bound names that contain special characters.
 * After reviewing the exposed bound names and their class names carefully, one can run the sample creation
 * with the --trusted flag, which disables the Security filtering.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public abstract class Security {

    private static Pattern boundName = Pattern.compile("[a-zA-Z0-9_-]+");
    private static Pattern alphaNumeric = Pattern.compile("[a-zA-Z0-9_-]+");
    private static Pattern jarFile = Pattern.compile("([a-zA-Z0-9])+\\.jar");
    private static Pattern javaFile = Pattern.compile("([a-zA-Z0-9])+\\.java");
    private static Pattern packageName = Pattern.compile("([a-zA-Z0-9_-]\\.?)+");
    private static Pattern shellInjection = Pattern.compile(".*[ '\"#&;`|*?~<>^()\\[\\]{}$\\\\\n].*");

    public static void checkBoundName(String input) throws UnexpectedCharacterException
    {
        if( RMGOption.GUESS_TRUSTED.getBool()  )
            return;

        Matcher m = boundName.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Bound name '" + input + "' contains invalid characters.");
    }

    public static void checkAlphaNumeric(String input) throws UnexpectedCharacterException
    {
        if( RMGOption.GUESS_TRUSTED.getBool() )
            return;

        Matcher m = alphaNumeric.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' contains non alphanumeric characters.");
    }

    public static void checkPackageName(String input) throws UnexpectedCharacterException
    {
        if( RMGOption.GUESS_TRUSTED.getBool() )
            return;

        Matcher m = packageName.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Package name '" + input + "' contains invalid characters.");
    }

    public static void checkJavaFile(String input) throws UnexpectedCharacterException
    {
        if( RMGOption.GUESS_TRUSTED.getBool() )
            return;

        Matcher m = javaFile.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Filename '" + input + "' contains invalid characters.");
    }

    public static void checkJarFile(String input) throws UnexpectedCharacterException
    {
        if( RMGOption.GUESS_TRUSTED.getBool() )
            return;

        Matcher m = jarFile.matcher(input);
        if( !m.matches() )
            throw new UnexpectedCharacterException("Jar name '" + input + "' contains invalid characters.");
    }

    public static void checkShellInjection(String input) throws UnexpectedCharacterException
    {
        if( RMGOption.GUESS_TRUSTED.getBool() )
            return;

        Matcher m = shellInjection.matcher(input);
        if( m.matches() )
            throw new UnexpectedCharacterException("Input '" + input + "' contains shell injection characters.");
    }
}

