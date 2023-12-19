package eu.tneitzel.rmg.exceptions;

/**
 * UnexpectedCharacterException may be thrown during the dynamic creation
 * of RMI code (guess action with --create-samples switch). It is caused by
 * the presence of dangerous characters within bound or class names. The
 * filtering in this regard is very strict, but can be disabled by using the
 * --trusted switch after reviewing the corresponding names.
 *
 * The reason for this filtering is simple: rmg uses the bound names from the
 * RMI registry within of the file names for the sample files. Bound names can
 * contain arbitrary characters, which includes e.g. path traversal sequences.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("serial")
public class UnexpectedCharacterException extends Exception
{
    public UnexpectedCharacterException() {}

    public UnexpectedCharacterException(String message)
    {
       super(message);
    }
}
