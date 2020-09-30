package <PACKAGENAME>;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;

public interface <CLASSNAME> extends Remote
{
    void call(String dummy, String dummy2, String dummy3) throws RemoteException;
    void call(String dummy, String dummy2) throws RemoteException;
    void call(String dummy, String[] dummy2) throws RemoteException;
    void call(String dummy) throws RemoteException;
    void call(String[] dummy) throws RemoteException;

    void cancel(int dummy1, String dummy2) throws RemoteException;
    void cancel(String dummy, String dummy2, String dummy3) throws RemoteException;
    void cancel(String dummy, String dummy2) throws RemoteException;
    void cancel(String dummy, String[] dummy2) throws RemoteException;
    void cancel(String[] dummy, String dummy2) throws RemoteException;
    void cancel(String dummy) throws RemoteException;
    void cancel(String[] dummy) throws RemoteException;

    void cmd(String dummy, String dummy2, String dummy3) throws RemoteException;
    void cmd(String dummy, String dummy2) throws RemoteException;
    void cmd(String dummy, String[] dummy2) throws RemoteException;
    void cmd(String dummy) throws RemoteException;
    void cmd(String[] dummy) throws RemoteException;

    void command(String dummy, String dummy2, String dummy3) throws RemoteException;
    void command(String dummy, String dummy2) throws RemoteException;
    void command(String dummy, String[] dummy2) throws RemoteException;
    void command(String dummy) throws RemoteException;
    void command(String[] dummy) throws RemoteException;

    void error(int dummy1, String dummy2) throws RemoteException;
    void error(int dummy1, Object dummy2) throws RemoteException;
    void error(Object dummy1, int dummy2) throws RemoteException;
    void error(String dummy1, Object dummy2) throws RemoteException;
    void error(Object dummy1, String dummy2) throws RemoteException;

    void execCmd(String dummy, String dummy2, String dummy3) throws RemoteException;
    void execCmd(String dummy, String dummy2) throws RemoteException;
    void execCmd(String dummy, String[] dummy2) throws RemoteException;
    void execCmd(String dummy) throws RemoteException;
    void execCmd(String[] dummy) throws RemoteException;

    void exec(String dummy, String dummy2, String dummy3) throws RemoteException;
    void exec(String dummy, String dummy2) throws RemoteException;
    void exec(String dummy, String[] dummy2) throws RemoteException;
    void exec(String dummy) throws RemoteException;
    void exec(String[] dummy) throws RemoteException;

    void execute(String dummy, String dummy2, String dummy3) throws RemoteException;
    void execute(String dummy, String dummy2) throws RemoteException;
    void execute(String dummy, String[] dummy2) throws RemoteException;
    void execute(String dummy) throws RemoteException;
    void execute(String[] dummy) throws RemoteException;

    void logEntry(int dummy1, Object dummy2) throws RemoteException;
    void logEntry(Object dummy1) throws RemoteException;
    void logEntry(Object dummy1, int dummy2) throws RemoteException;
    void logEntry(Object dummy1, String dummy2) throws RemoteException;
    void logEntry(String dummy1, Object dummy2) throws RemoteException;

    void login(ArrayList dummy1, String dummy2) throws RemoteException;
    void login(ArrayList dummy1) throws RemoteException;
    void login(HashMap dummy1, String dummy2) throws RemoteException;
    void login(HashMap dummy1) throws RemoteException;
    void login(String dummy1, ArrayList dummy2) throws RemoteException;
    void login(String dummy1, HashMap dummy2) throws RemoteException;
    void login(String dummy, String dummy2, String dummy3) throws RemoteException;
    void login(String dummy, String dummy2) throws RemoteException;
    void login(String dummy, String[] dummy2) throws RemoteException;
    void login(String[] dummy, String dummy2) throws RemoteException;
    void login(String dummy) throws RemoteException;
    void login(String[] dummy) throws RemoteException;

    void log(int dummy1, Object dummy2) throws RemoteException;
    void log(int dummy1, String dummy2) throws RemoteException;
    void log(Object dummy1) throws RemoteException;
    void log(Object dummy1, String dummy2) throws RemoteException;
    void log(Object dummy1, int dummy2) throws RemoteException;
    void log(String dummy1, int dummy2) throws RemoteException;
    void log(String dummy1, Object dummy2) throws RemoteException;
    void log(String dummy, String dummy2, String dummy3) throws RemoteException;
    void log(String dummy, String dummy2) throws RemoteException;
    void log(String dummy) throws RemoteException;

    void loginUser(String dummy, String dummy2, String dummy3) throws RemoteException;
    void loginUser(String dummy, String dummy2) throws RemoteException;
    void loginUser(String dummy, String[] dummy2) throws RemoteException;
    void loginUser(String[] dummy, String dummy2) throws RemoteException;
    void loginUser(String dummy) throws RemoteException;
    void loginUser(String[] dummy) throws RemoteException;

    void logMessage(int dummy1, Object dummy2) throws RemoteException;
    void logMessage(int dummy1, String dummy2) throws RemoteException;
    void logMessage(Object dummy1) throws RemoteException;
    void logMessage(Object dummy1, int dummy2) throws RemoteException;
    void logMessage(Object dummy1, String dummy2) throws RemoteException;
    void logMessage(String dummy1, Object dummy2) throws RemoteException;
    void logMessage(String dummy, String dummy2, String dummy3) throws RemoteException;
    void logMessage(String dummy, String dummy2) throws RemoteException;
    void logMessage(String dummy) throws RemoteException;

    void logout(String dummy, String dummy2, String dummy3) throws RemoteException;
    void logout(String dummy, String dummy2) throws RemoteException;
    void logout(String dummy, String[] dummy2) throws RemoteException;
    void logout(String[] dummy, String dummy2) throws RemoteException;
    void logout(String dummy) throws RemoteException;
    void logout(String[] dummy) throws RemoteException;

    void os(String dummy, String dummy2, String dummy3) throws RemoteException;
    void os(String dummy, String dummy2) throws RemoteException;
    void os(String dummy, String[] dummy2) throws RemoteException;
    void os(String dummy) throws RemoteException;
    void os(String[] dummy) throws RemoteException;

    void passthru(String dummy, String dummy2, String dummy3) throws RemoteException;
    void passthru(String dummy, String dummy2) throws RemoteException;
    void passthru(String dummy, String[] dummy2) throws RemoteException;
    void passthru(String dummy) throws RemoteException;
    void passthru(String[] dummy) throws RemoteException;

    void register(String dummy, String dummy2, String dummy3) throws RemoteException;
    void register(String dummy, String dummy2) throws RemoteException;
    void register(String dummy, String[] dummy2) throws RemoteException;
    void register(String[] dummy, String dummy2) throws RemoteException;
    void register(String dummy) throws RemoteException;
    void register(String[] dummy) throws RemoteException;
    void register(Object dummy) throws RemoteException;
    void register(String dummy1, Object dummy2) throws RemoteException;
    void register(Object dummy1, String dummy2) throws RemoteException;
    void register(HashMap dummy1) throws RemoteException;
    void register(String dummy1, HashMap dummy2) throws RemoteException;
    void register(HashMap dummy1, String dummy2) throws RemoteException;

    void request(String dummy, String dummy2, String dummy3) throws RemoteException;
    void request(String dummy, String dummy2) throws RemoteException;
    void request(String dummy, String[] dummy2) throws RemoteException;
    void request(String[] dummy, String dummy2) throws RemoteException;
    void request(String dummy) throws RemoteException;
    void request(String[] dummy) throws RemoteException;
    void request(Object dummy) throws RemoteException;
    void request(String dummy1, Object dummy2) throws RemoteException;
    void request(Object dummy1, String dummy2) throws RemoteException;

    void reset(int dummy1, String dummy2) throws RemoteException;
    void reset(String dummy, String dummy2, String dummy3) throws RemoteException;
    void reset(String dummy, String dummy2) throws RemoteException;
    void reset(String dummy, String dummy2[]) throws RemoteException;
    void reset(String[] dummy, String dummy2) throws RemoteException;
    void reset(String dummy) throws RemoteException;
    void reset(String[] dummy) throws RemoteException;

    void run(String dummy, String dummy2, String dummy3) throws RemoteException;
    void run(String dummy, String dummy2) throws RemoteException;
    void run(String dummy, String[] dummy2) throws RemoteException;
    void run(String dummy) throws RemoteException;
    void run(String[] dummy) throws RemoteException;

    void shellExec(String dummy, String dummy2, String dummy3) throws RemoteException;
    void shellExec(String dummy, String dummy2) throws RemoteException;
    void shellExec(String dummy, String[] dummy2) throws RemoteException;
    void shellExec(String dummy) throws RemoteException;
    void shellExec(String[] dummy) throws RemoteException;

    void start(String dummy, String dummy2, String dummy3) throws RemoteException;
    void start(String dummy, String dummy2) throws RemoteException;
    void start(String dummy, String[] dummy2) throws RemoteException;
    void start(String dummy) throws RemoteException;
    void start(String[] dummy) throws RemoteException;

    void sysCall(String dummy, String dummy2, String dummy3) throws RemoteException;
    void sysCall(String dummy, String dummy2) throws RemoteException;
    void sysCall(String dummy, String[] dummy2) throws RemoteException;
    void sysCall(String dummy) throws RemoteException;
    void sysCall(String[] dummy) throws RemoteException;

    void sys(String dummy, String dummy2, String dummy3) throws RemoteException;
    void sys(String dummy, String dummy2) throws RemoteException;
    void sys(String dummy, String[] dummy2) throws RemoteException;
    void sys(String dummy) throws RemoteException;
    void sys(String[] dummy) throws RemoteException;

    void system(String dummy, String dummy2, String dummy3) throws RemoteException;
    void system(String dummy, String dummy2) throws RemoteException;
    void system(String dummy, String[] dummy2) throws RemoteException;
    void system(String dummy) throws RemoteException;
    void system(String[] dummy) throws RemoteException;

    void update(String dummy, String dummy2, String dummy3) throws RemoteException;
    void update(String dummy, String dummy2) throws RemoteException;
    void update(String dummy, String[] dummy2) throws RemoteException;
    void update(String[] dummy, String dummy2) throws RemoteException;
    void update(String dummy) throws RemoteException;
    void update(String[] dummy) throws RemoteException;
    void update(Object dummy) throws RemoteException;
    void update(String dummy1, Object dummy2) throws RemoteException;
    void update(Object dummy1, String dummy2) throws RemoteException;
    void update(HashMap dummy1) throws RemoteException;
    void update(String dummy1, HashMap dummy2) throws RemoteException;
    void update(HashMap dummy1, String dummy2) throws RemoteException;
    void update(ArrayList dummy1) throws RemoteException;
    void update(String dummy1, ArrayList dummy2) throws RemoteException;
    void update(ArrayList dummy1, String dummy2) throws RemoteException;

    void updatePreferences(String dummy, String dummy2, String dummy3) throws RemoteException;
    void updatePreferences(String dummy, String dummy2) throws RemoteException;
    void updatePreferences(String dummy, String[] dummy2) throws RemoteException;
    void updatePreferences(String[] dummy, String dummy2) throws RemoteException;
    void updatePreferences(String dummy) throws RemoteException;
    void updatePreferences(String[] dummy) throws RemoteException;
    void updatePreferences(Object dummy) throws RemoteException;
    void updatePreferences(String dummy1, Object dummy2) throws RemoteException;
    void updatePreferences(Object dummy1, String dummy2) throws RemoteException;
    void updatePreferences(HashMap dummy1) throws RemoteException;
    void updatePreferences(String dummy1, HashMap dummy2) throws RemoteException;
    void updatePreferences(HashMap dummy1, String dummy2) throws RemoteException;
    void updatePreferences(ArrayList dummy1) throws RemoteException;
    void updatePreferences(String dummy1, ArrayList dummy2) throws RemoteException;
    void updatePreferences(ArrayList dummy1, String dummy2) throws RemoteException;
}
