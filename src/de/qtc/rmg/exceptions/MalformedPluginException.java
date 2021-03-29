package de.qtc.rmg.exceptions;

public class MalformedPluginException extends Exception {

    private static final long serialVersionUID = 1L;

    public MalformedPluginException() {}

    public MalformedPluginException(String message) {
       super(message);
    }
}
