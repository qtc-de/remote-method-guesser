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
    private boolean updateWordlists;

    public WordlistHandler(String wordlistFile, String wordlistFolder, boolean updateWordlists)
    {
        this.wordlistFile = wordlistFile;
        this.wordlistFolder = wordlistFolder;
        this.updateWordlists = updateWordlists;
    }

    public List<MethodCandidate> getWordlistMethods() throws IOException
    {
        if( this.wordlistFile != null && !this.wordlistFile.isEmpty() ) {
            return getWordlistMethodsFromFile();
        } else if( this.wordlistFolder != null && !this.wordlistFolder.isEmpty() ) {
            return getWordlistMethodsFromFolder();
        } else {
            throw new IOException("Neither wordlist-folder nor wordlist-file was specified.");
        }
    }

    public List<MethodCandidate> getWordlistMethodsFromFile() throws IOException
    {
        File wordlistFile = new File(this.wordlistFile);
        return getWordlistMethods(wordlistFile);
    }

    public List<MethodCandidate> getWordlistMethodsFromFolder() throws IOException
    {
        File wordlistFolder = new File(this.wordlistFolder);
        if( !wordlistFolder.isDirectory() ) {
            throw new IOException("wordlist-folder " + wordlistFolder.getCanonicalPath() + " is not a directory.");
        }

        List<File> files = (List<File>)FileUtils.listFiles(wordlistFolder, TrueFileFilter.INSTANCE, TrueFileFilter.INSTANCE);
        Logger.printlnMixedBlueFirst(String.valueOf(files.size()), "wordlist files found.");

        List<MethodCandidate> methods = new ArrayList<MethodCandidate>();
        for(File file : files){
            methods.addAll(getWordlistMethods(file));
        }

        return methods;
    }

    public List<MethodCandidate> getWordlistMethods(File file) throws IOException
    {
        Logger.printlnMixedBlue("Reading method candidates from file", file.getCanonicalPath());
        Logger.increaseIndent();

        List<String> content = FileUtils.readLines(file, StandardCharsets.UTF_8);
        List<MethodCandidate> methods = new ArrayList<MethodCandidate>();

        for(String line : content) {

            if( line.trim().startsWith("#") || line.trim().isEmpty() ) {
                continue;
            }

            String[] split = line.split(";");

            try {
                if(split.length == 1)
                    methods.add(new MethodCandidate(split[0].trim()));

                else if(split.length == 4)
                    methods.add(new MethodCandidate(split[0].trim(), split[1].trim(), split[2].trim(), split[3].trim()));

                else {
                    Logger.eprintlnMixedYellow("Encountered unknown method format:", line);
                    Logger.eprintln("Skipping this signature");
                }

            } catch(CannotCompileException | NotFoundException e) {
                Logger.eprintlnMixedYellow("Caught Exception while processing", line);
                Logger.eprintln("Skipping this signature");
            }
        }

        Logger.printlnMixedYellowFirst(String.valueOf(methods.size()), "methods were successfully parsed.");

        if(updateWordlists) {
            Logger.println("Updating template file.");
            updateWordlist(file, methods);
        }

        Logger.decreaseIndent();
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
