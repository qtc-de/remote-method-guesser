package de.qtc.rmg;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class Formatter {


	private boolean json = false;
	
	public Formatter(boolean json) {
		this.json = json;
	}
	
    public void listBoundNames(String[] boundNames) {
    	if( this.json ) {
    		this.listBoundNamesJson(boundNames, null, null);
    	} else {
    		this.listBoundNamesPlain(boundNames, null, null);
    	}
    }
    
    public void listBoundNames(String[] boundNames, ArrayList<HashMap<String,String>> classes) {
    	HashMap<String,String> knownClasses = null;
    	HashMap<String,String> unknownClasses = null;
    	
    	if(classes != null) {
    		knownClasses = classes.get(0);
    		unknownClasses = classes.get(1);
    	}
    	
    	if( this.json ) {
    		this.listBoundNamesJson(boundNames, knownClasses, unknownClasses);
    	} else {
    		this.listBoundNamesPlain(boundNames, knownClasses, unknownClasses);
    	}
    }

    public void listBoundNamesPlain(String[] boundNames, HashMap<String,String> knownClasses, HashMap<String,String> unknownClasses) {

        System.out.println("[+] Listing bound names in registry:");
        for( String name : boundNames ) {

            System.out.println("[+]\t• " + name);

            if( knownClasses == null || unknownClasses == null ) {
                continue;
            }

            if( knownClasses.containsKey(name) ) {
                System.out.println("[+]\t  --> " + knownClasses.get(name) + " (known class)");
            }

            if( unknownClasses.containsKey(name) ) {
                System.out.println("[+]\t  --> " + unknownClasses.get(name) + " (unknown class)");
            }
        }
    }
    
    @SuppressWarnings("unchecked")
	public void listBoundNamesJson(String[] boundNames, HashMap<String,String> knownClasses, HashMap<String,String> unknownClasses) {

    	JSONObject json = new JSONObject();
    	JSONArray knownArray = new JSONArray();
    	JSONArray unknownArray = new JSONArray();
     
    	for( String name : boundNames ) {

            if( knownClasses == null || unknownClasses == null ) {
                knownArray.add(name);
                continue;
            }

            if( knownClasses.containsKey(name) ) {
            	JSONObject subJson = new JSONObject(); 
            	subJson.put(name, knownClasses.get(name));
            	knownArray.add(subJson);
            }

            if( unknownClasses.containsKey(name) ) {
            	JSONObject subJson = new JSONObject(); 
            	subJson.put(name, unknownClasses.get(name));
            	unknownArray.add(subJson);
            }
        }
    	
    	if( knownClasses == null || unknownClasses == null ) {
    		json.put("bound-names", knownArray);
    	} else {
    		JSONObject subJson = new JSONObject();
    		subJson.put("known-classes", knownArray);
    		subJson.put("unknown-classes", unknownArray);
    		json.put("bound-names", subJson);
    	}
    	
    	System.out.println(json.toJSONString());
    }
    
    
    public void listGuessedMethods(HashMap<String,ArrayList<Method>> results) {
    	if(this.json) {
    		this.listGuessedMethodsJson(results);
    	} else {
    		this.listGuessedMethodsPlain(results);
    	}
    }
    
    
    @SuppressWarnings({ "rawtypes", "unchecked" })
	public void listGuessedMethodsPlain(HashMap<String,ArrayList<Method>> results) {
    	
        System.out.println("[+] Successfully guessed methods:");
        
    	java.util.Iterator<Entry<String, ArrayList<Method>>> it = results.entrySet().iterator();
        while(it.hasNext()) {
        	
            Map.Entry pair = (Map.Entry)it.next();
            String boundName = (String) pair.getKey();
            ArrayList<Method> methods = ((ArrayList<Method>) pair.getValue());
           
            System.out.println("[+]\t• " + boundName);
            
            for( Method m : methods ) {
            	System.out.println("[+]\t\t--> " + m.toGenericString());
            }
            
            it.remove();
        }
    }
    
    
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public void listGuessedMethodsJson(HashMap<String,ArrayList<Method>> results) {

    	JSONObject json = new JSONObject();
    	java.util.Iterator<Entry<String, ArrayList<Method>>> it = results.entrySet().iterator();
        while(it.hasNext()) {
        	
        	JSONArray methodArray = new JSONArray();
        	
            Map.Entry pair = (Map.Entry)it.next();
            String boundName = (String) pair.getKey();
            ArrayList<Method> methods = ((ArrayList<Method>) pair.getValue());
            
            for( Method method : methods) {
            	methodArray.add(method.toGenericString());
            }
            
            json.put(boundName, methodArray);
    	
        }
    	System.out.println(json.toJSONString());
    }
}