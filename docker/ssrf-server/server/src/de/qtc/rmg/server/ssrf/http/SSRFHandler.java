package de.qtc.rmg.server.ssrf.http;

import java.io.IOException;
import java.io.OutputStream;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import de.qtc.rmg.server.ssrf.utils.Logger;

import org.apache.commons.io.IOUtils;

/**
 * The SSRFHandler class is an HTTP handler that is vulnerable to SSRF attacks. It expects
 * a parameter with name url and attempts to query the corresponding value using curl. Notice
 * that in order to be usable for RMI based SSRF attacks, the operating system version of curl
 * needs to support gopher payloads containing null bytes. This is no longer possible with most
 * recent curl versions.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class SSRFHandler implements HttpHandler {

    private final static String error = "[-] The url parameter is missing!\n\r";

    /**
     * Handles the incoming HttpExchange. First attempts to parse a parameter with name
     * url from the request. Then attempts to query the resource specified in the url
     * parameter and returns the result as raw bytes.
     */
    public void handle(HttpExchange t) throws IOException
    {
        Logger.println("Obtained incoming request:");
        Logger.increaseIndent();

        String urlParam = getUrlParam(t);
        OutputStream response = t.getResponseBody();

        if(urlParam == null) {
            Logger.printlnMixedYellow("url parameter is", "null.", "Aborting.");
            Logger.printlnMixedBlue("Sending", "400 Bad Request", "response.");

            t.sendResponseHeaders(400, error.length());
            response.write(error.getBytes());

        } else {
            Logger.printlnMixedYellow("url parameter:", urlParam.substring(0, 50) + "[...]");
            Process p = Runtime.getRuntime().exec(new String[] {"curl", urlParam});

            try {
                p.wait();
            } catch( Exception e ) {};

            byte[] output = IOUtils.toByteArray(p.getInputStream());

            Logger.printlnMixedBlue("Sending", "200 OK", "response.");
            t.sendResponseHeaders(200, output.length);
            response.write(output);
        }

        response.close();
    }

    /**
     * Helper function for parsing the user supplied parameters. Attempts to find the url
     * parameter and returns it's value. Not a fail-save implementation, but sufficient ;)
     *
     * @param t Incoming HttpExchange
     * @return value of the url parameter if specified. null otherwise.
     */
    private String getUrlParam(HttpExchange t)
    {
        String query = t.getRequestURI().getQuery();

        if(query == null)
            return null;

        for(String p : query.split("&")) {

            if(p.startsWith("url=")) {

                String[] keyValue = p.split("=");
                if(keyValue.length == 2)
                    return keyValue[1];
            }
        }

        return null;
    }
}
