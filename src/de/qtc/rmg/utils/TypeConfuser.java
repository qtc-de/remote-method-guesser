package de.qtc.rmg.utils;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.rmi.server.RemoteRef;

public class TypeConfuser implements InvocationHandler {
 
	private RemoteRef ref;
	private Field parameterTypes;
	
	public TypeConfuser(RemoteRef obj) throws NoSuchFieldException, SecurityException
	{
		this.ref = obj;
		this.parameterTypes = Method.class.getDeclaredField("parameterTypes");
		this.parameterTypes.setAccessible(true);
	}
	
    @SuppressWarnings("rawtypes")
    public Object invoke(Object proxy, Method method, Object[] args) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException
    {
    	Class[] originalTypes = ((Method)args[1]).getParameterTypes();
    	this.parameterTypes.set(args[1], confuseTypes(originalTypes, (Object[])args[2]));
    	
    	try {
    		Object result = method.invoke(ref, args);
    		return result;
    		
    	} finally {
    		/* 
    		 * This is required, as RemoteObjectInvocationHandler checks the method signature
    		 * after an exception occurred and overwrites the original (server) exception. One
    		 * could also catch the exception right here to prevent this.
    		 */
    		this.parameterTypes.set(args[1], originalTypes);
    	}
    }
    
    @SuppressWarnings({ "rawtypes" })
	private Class[] confuseTypes(Class[] originalTypes, Object[] args)
    {
    	Class[] confusedTypes = new Class[originalTypes.length];
    	
    	for(int ctr = 0; ctr < originalTypes.length; ctr++) {
    		
    		if(originalTypes[ctr].isPrimitive()) {
    			confusedTypes[ctr] = String.class;
    			args[ctr] = "";
    			
    		} else {
    			confusedTypes[ctr] = int.class;
    			args[ctr] = 0;
    		}
    	}
    	
    	return confusedTypes;
    }
}
