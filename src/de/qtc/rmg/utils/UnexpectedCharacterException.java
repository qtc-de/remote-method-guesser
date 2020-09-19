package de.qtc.rmg.utils;

@SuppressWarnings("serial")
public class UnexpectedCharacterException extends Exception {
    public UnexpectedCharacterException() {}

    public UnexpectedCharacterException(String message) {
       super(message);
    }
}
