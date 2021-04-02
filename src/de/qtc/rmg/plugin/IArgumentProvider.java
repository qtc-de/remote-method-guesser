package de.qtc.rmg.plugin;

/**
 * The IArgumentProvider interface is used during rmg's 'call' action to obtain the argument array that should be
 * used for the call. plugins can implement this class to obtain custom argument arrays that they want to use during
 * the 'call' operation. The getArgumentArray method is called with the user specified argument string and is expected
 * to return the Object array that should be used for the call.
 *
 * This interface is implemented by rmg's DefaultProvider class by default.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IArgumentProvider {
    Object[] getArgumentArray(String argumentString);
}
