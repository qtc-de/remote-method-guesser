    public <RETURN> <METHODNAME>(<ARGUMENTS>) throws RemoteException {
    	
        try {
            Object object = this.ref.invoke(this, <METHOD>, new Object[]{<ARGUMENT_ARRAY>}, <HASH>L);
            return (<CAST>)object;
        }
        
        catch (RuntimeException runtimeException) {
            throw runtimeException;
        }
        catch (RemoteException remoteException) {
            throw remoteException;
        }
        catch (Exception exception) {
            throw new UnexpectedException("undeclared checked exception", exception);
        }
    }
