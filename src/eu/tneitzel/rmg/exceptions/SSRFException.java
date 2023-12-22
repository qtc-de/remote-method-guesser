package eu.tneitzel.rmg.exceptions;

import java.io.Serializable;

/**
 * Custom Exception class used to generate SSRF payloads. When an
 * SSRFException is thrown, remote-method-guesser knows that the
 * --ssrf option was used.
 */
public class SSRFException extends Exception implements Serializable
{
    private static final long serialVersionUID = 1L;
}
