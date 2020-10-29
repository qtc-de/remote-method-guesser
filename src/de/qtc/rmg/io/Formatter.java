package de.qtc.rmg.io;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import de.qtc.rmg.internal.MethodCandidate;

@SuppressWarnings({ "unchecked", "rawtypes" })
public class Formatter {

    private boolean json = false;

    public Formatter(boolean json) {
        this.json = json;
    }

    public void listBoundNames(String[] boundNames)
    {
        if( this.json ) {
            this.listBoundNamesJson(boundNames, null, null);
        } else {
            this.listBoundNamesPlain(boundNames, null, null);
        }
    }

    public void listBoundNames(String[] boundNames, ArrayList<HashMap<String,String>> classes)
    {
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

    public void listBoundNamesPlain(String[] boundNames, HashMap<String,String> knownClasses, HashMap<String,String> unknownClasses)
    {
        Logger.println("Listing bound names in registry:");
        Logger.increaseIndent();

        for( String name : boundNames ) {

            Logger.printlnMixedYellow("•", name);

            if( knownClasses == null || unknownClasses == null ) {
                continue;
            }

            Logger.increaseIndent();

            if( knownClasses.containsKey(name) ) {
                Logger.printlnMixedBlue("-->", knownClasses.get(name), "(known class)");
            }

            if( unknownClasses.containsKey(name) ) {
                Logger.printlnMixedBlue("-->", unknownClasses.get(name), "(unknown class)");
            }

            Logger.decreaseIndent();
        }

        Logger.decreaseIndent();
    }

    public void listBoundNamesJson(String[] boundNames, HashMap<String,String> knownClasses, HashMap<String,String> unknownClasses)
    {
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


    public void listGuessedMethods(HashMap<String,ArrayList<MethodCandidate>> results)
    {
        if(this.json) {
            this.listGuessedMethodsJson(results);
        } else {
            this.listGuessedMethodsPlain(results);
        }
    }

    public void listGuessedMethodsPlain(HashMap<String,ArrayList<MethodCandidate>> results)
    {
        Logger.println("");
        Logger.println("Listing successfully guessed methods:");

        Logger.increaseIndent();
        Iterator<Entry<String, ArrayList<MethodCandidate>>> it = results.entrySet().iterator();

        while(it.hasNext()) {

            Map.Entry pair = (Map.Entry)it.next();
            String boundName = (String)pair.getKey();
            ArrayList<MethodCandidate> methods = ((ArrayList<MethodCandidate>)pair.getValue());

            Logger.printlnMixedBlue("• ", boundName);
            Logger.increaseIndent();

            for( MethodCandidate m : methods ) {
                Logger.printlnMixedYellow("-->", m.getSignature());
            }

            Logger.decreaseIndent();
            it.remove();
        }

        Logger.decreaseIndent();
    }

    public void listGuessedMethodsJson(HashMap<String,ArrayList<MethodCandidate>> results)
    {
        JSONObject json = new JSONObject();
        Iterator<Entry<String, ArrayList<MethodCandidate>>> it = results.entrySet().iterator();
        while(it.hasNext()) {

            JSONArray methodArray = new JSONArray();

            Map.Entry pair = (Map.Entry)it.next();
            String boundName = (String) pair.getKey();
            ArrayList<MethodCandidate> methods = ((ArrayList<MethodCandidate>) pair.getValue());

            for( MethodCandidate method : methods) {
                methodArray.add(method.getSignature());
            }

            json.put(boundName, methodArray);

        }
        System.out.println(json.toJSONString());
    }
}
