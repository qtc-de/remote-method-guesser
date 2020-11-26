package <PACKAGE>;

import java.lang.reflect.Method;
import java.rmi.RemoteException;
import java.rmi.UnexpectedException;
import java.rmi.server.RemoteRef;
import java.rmi.server.RemoteStub;

import <INTERFACE_IMPORT>;
import <IMPORT>;

@SuppressWarnings("rawtypes")
public final class <CLASSNAME> extends RemoteStub implements <INTERFACE>
{
    private static final long serialVersionUID = 2L;
    private static Class intf;
    <METHOD_VAR>
    
    static {
    	try {
		    intf = Class.forName("<INTERFACE_IMPORT>");
    	} catch (ClassNotFoundException classNotFoundException) {
            throw new NoClassDefFoundError(classNotFoundException.getMessage());
        }

        try {
            <METHOD_LOOKUP>
        }
        catch (NoSuchMethodException noSuchMethodException) {
            throw new NoSuchMethodError("stub class initialization failed");
        }
    }

    <METHOD>
}
