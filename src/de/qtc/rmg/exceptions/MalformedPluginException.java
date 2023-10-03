package de.qtc.rmg.exceptions;

/**
 * MalformedPluginExceptions are thrown then an rmg plugin was specified on the command
 * line that does not satisfy the plugin requirements. Usually, if that happens, then the
 * Manifest of the corresponding plugin does not contain a reference to the rmg plugin
 * class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MalformedPluginException extends Exception
{
    private static final long serialVersionUID = 1L;

    public MalformedPluginException() {}

    public MalformedPluginException(String message)
    {
       super(message);
    }
}
