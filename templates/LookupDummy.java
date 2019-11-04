package de.qtc.rmg;

import java.util.List;
import java.util.Arrays;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;


public class LookupDummy {
    
    public static Object rmiLookup(Registry rmiRegistry, String name) {

        Object returnValue = null;

        try {
            returnValue = rmiRegistry.lookup(name);
        } catch( Exception e ) {
            System.out.println(e.toString());
        }

        return returnValue;
    }
}
