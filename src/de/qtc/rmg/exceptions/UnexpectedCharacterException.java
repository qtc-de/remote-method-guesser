package de.qtc.rmg.exceptions;

/**
 * UnexpectedCharacterException may be thrown during the dynamic creation
 * of RMI code (guess action with --create-samples switch). It is caused by
 * the presence of dangerous characters within bound or class names. The
 * filtering in this regard is very strict, but can be disabled by using the
 * --trusted switch after reviewing the corresponding names.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("serial")
public class UnexpectedCharacterException extends Exception {
    public UnexpectedCharacterException() {}

    public UnexpectedCharacterException(String message) {
       super(message);
    }
}
