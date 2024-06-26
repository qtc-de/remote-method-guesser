package eu.tneitzel.rmg.utils;

import java.rmi.Remote;

/**
 * IUnknown is a dummy interface that is used when performing method guessing with
 * a manually specified ObjID. The original implementation required an RemoteObjectWrapper,
 * which is basically a wrapper around a remote object. When guessing on ObjID, we only
 * have a remote ref. To make a wrapper out of it, we need to specify an interface that
 * the ref implements. IUnknown is used for this purpose.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IUnknown extends Remote
{
}
