package de.qtc.rmg.exceptions;

@SuppressWarnings("serial")
public class UnexpectedCharacterException extends Exception {
    public UnexpectedCharacterException() {}

    public UnexpectedCharacterException(String message) {
       super(message);
    }
}
