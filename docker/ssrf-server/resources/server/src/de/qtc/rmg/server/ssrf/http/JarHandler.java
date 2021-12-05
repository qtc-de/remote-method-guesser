package de.qtc.rmg.server.ssrf.http;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import de.qtc.rmg.server.ssrf.utils.Logger;

/**
 * The JarHandler handles requests to the codebase endpoint specified within the RMI server.
 * It is used to simulate a (poorly configured) RMI codebase that can be used to download
 * server side class definitions of remote objects.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class JarHandler implements HttpHandler {

    private final String jarFileName = "/opt/ssrf-server.jar";
    private final String fileNotFoundError = "File not found";

    /**
     * Returns the complete .jar file of the application server.
     */
    public void handle(HttpExchange t) throws IOException
    {
        Logger.println("");
        Logger.println("Obtained incoming JAR request:");
        Logger.increaseIndent();
        Logger.printlnMixedYellow("Serving file", jarFileName, "...");

        OutputStream response = t.getResponseBody();
        File jarFile = new File(jarFileName);

        if( !jarFile.exists() ) {
            Logger.printlnMixedBlue("File", jarFileName, "not found!");
            Logger.printlnYellow("Returning 404 response.");

            t.sendResponseHeaders(404, fileNotFoundError.length());
            response.write(fileNotFoundError.getBytes());
            return;
        }

        byte[] content = Files.readAllBytes(jarFile.toPath());
        Logger.printlnMixedBlue("Returning", String.valueOf(content.length), "bytes.");

        t.sendResponseHeaders(200, content.length);
        response.write(content);
    }
}
