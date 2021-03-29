package de.qtc.rmg.plugin;

import de.qtc.rmg.operations.Operation;

public interface IPayloadProvider {
    Object getPayloadObject(Operation action, String name, String args);
}
