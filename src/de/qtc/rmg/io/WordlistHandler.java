package de.qtc.rmg.io;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import de.qtc.rmg.internal.MethodCandidate;
import javassist.CannotCompileException;
import javassist.NotFoundException;


public class WordlistHandler {

    private String wordlistFile;
    private String wordlistFolder;
    private boolean rewriteTemplates;
    private List<MethodCandidate> methods;

    public WordlistHandler(String wordlistFolder, String wordlistFile, boolean rewriteTemplates)
    {
        this.wordlistFile = wordlistFile;
        this.wordlistFolder = wordlistFolder;
        this.rewriteTemplates = rewriteTemplates;
    }

    public void initWordlistMethods() throws IOException
    {
        if( this.wordlistFile != null ) {
            initWordlistMethodsFromFile();
        } else {
            initWordlistMethodsFromFolder();
        }
    }

    public void initWordlistMethodsFromFile() throws IOException
    {
        File wordlistFile = new File(this.wordlistFile);
        this.methods.addAll(getWordlistMethods(wordlistFile));
    }

    public void initWordlistMethodsFromFolder() throws IOException
    {
        File wordlistFolder = new File(this.wordlistFolder);
        List<File> files = (List<File>)FileUtils.listFiles(wordlistFolder, TrueFileFilter.INSTANCE, TrueFileFilter.INSTANCE);

        Logger.printMixedBlueFirst(String.valueOf(files.size()), "wordlist files found.");
        Logger.increaseIndent();

        for(File file : files){
            this.methods.addAll(getWordlistMethods(file));
        }
    }


    public List<MethodCandidate> getWordlistMethods(File file) throws IOException
    {
        Logger.printMixedBlue("Reading method candidates from file", file.getAbsolutePath());
        List<String> content = FileUtils.readLines(file, StandardCharsets.UTF_8);

        List<MethodCandidate> methods = new ArrayList<MethodCandidate>();

        for(String line : content) {
            String[] split = line.split(";");

            try {
                if(split.length == 1)
                    methods.add(new MethodCandidate(split[0]));

                else if(split.length == 3)
                    methods.add(new MethodCandidate(split[0], split[1], split[2]));

                else
                    Logger.eprintlnMixedYellow("Encountered unknown method format:", line);

            } catch(CannotCompileException | NotFoundException e) {
                Logger.eprintlnMixedYellow("Caught Exception while processing", line);
                Logger.eprintln("Skipping this signature");
            }
        }

        if(rewriteTemplates) {
            updateWordlist(file, methods);
        }
        return methods;
    }


    public void updateWordlist(File file, List<MethodCandidate> methods) throws IOException
    {
        List<String> signatures = new ArrayList<String>();
        for(MethodCandidate method : methods) {
            signatures.add(method.convertToString());
        }

        FileUtils.writeLines(file, signatures);
    }
}
