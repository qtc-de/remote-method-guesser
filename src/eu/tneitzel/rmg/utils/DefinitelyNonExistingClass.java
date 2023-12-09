package eu.tneitzel.rmg.utils;

import java.io.Serializable;

/**
 * This class can be considered as a leftover. It was once used to determine the useCodebaseOnly
 * setting of RMI servers, but this is now done via malformed URLs within class annotations. The
 * class is still used in one DGC function (although it is not really required there), but could
 * theoretically be removed. We leave it for now, as it may be useful for future development.
 *
 * The initial idea of the class was just to have a default object that can be sent to server, that
 * is certainly not available within the server's class path.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DefinitelyNonExistingClass implements Serializable{
    private final static long serialVersionUID = 2L;
}
