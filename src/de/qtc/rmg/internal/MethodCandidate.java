package de.qtc.rmg.internal;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.utils.RMGUtils;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.NotFoundException;

public class MethodCandidate {

    private long hash;
    private String signature;
    private boolean isVoid;
    private boolean isPrimitive;
    private CtMethod method;;

    public MethodCandidate(String signature) throws CannotCompileException, NotFoundException
    {
        this.signature = signature;
        RMGUtils.createTypesFromSignature(signature);

        method = RMGUtils.makeMethod(signature);
        CtClass[] types = method.getParameterTypes();
        this.hash = getCtMethodHash(method);

        if( types.length == 0 ) {
            this.isVoid = true;
            this.isPrimitive = false;

        } else {
            this.isVoid = false;
            this.isPrimitive = types[0].isPrimitive();
        }
    }

    public MethodCandidate(String signature, String hash, String isPrimitive, String isVoid)
    {
        this.signature = signature;
        this.hash = Long.valueOf(hash);
        this.isPrimitive = Boolean.valueOf(isPrimitive);
        this.isVoid = Boolean.valueOf(isVoid);
    }

    public Object[] getConfusedArgument()
    {
        if( this.isPrimitive() ) {
            return new Object[] { "RMG" };
        } else {
            return new Object[] { 42 };
        }
    }

    public CtClass[] getParameterTypes() throws CannotCompileException, NotFoundException
    {
        return this.getMethod().getParameterTypes();
    }

    public String getName() throws CannotCompileException, NotFoundException
    {
        return this.getMethod().getName();
    }

    private long getCtMethodHash(CtMethod method)
    {
        String methodSignature = method.getName() + method.getSignature();
        return computeMethodHash(methodSignature);
    }

    private long computeMethodHash(String methodSignature) {
        long hash = 0;
        ByteArrayOutputStream sink = new ByteArrayOutputStream(127);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA");
            DataOutputStream out = new DataOutputStream(
                new DigestOutputStream(sink, md));

            out.writeUTF(methodSignature);

            // use only the first 64 bits of the digest for the hash
            out.flush();
            byte hasharray[] = md.digest();
            for (int i = 0; i < Math.min(8, hasharray.length); i++) {
                hash += ((long) (hasharray[i] & 0xFF)) << (i * 8);
            }
        } catch (IOException ignore) {
            /* can't happen, but be deterministic anyway. */
            hash = -1;
        } catch (NoSuchAlgorithmException complain) {
            throw new SecurityException(complain.getMessage());
        }
        return hash;
    }

    public int getPrimitive(int selected) throws NotFoundException, CannotCompileException
    {
        CtClass[] types = this.getParameterTypes();

        if(selected != -1) {

            if( selected >= types.length ) {
                Logger.eprintlnMixedYellow("Specified argument position", String.valueOf(selected), "is out of bounds.");
                return -1;
            }

            if( types[selected].isPrimitive() ) {
                Logger.eprintlnMixedYellow("Specified argument position", String.valueOf(selected), "is a primitive type.");
                return -1;
            }

            return selected;
        }

        int result = -1;
        for(int ctr = 0; ctr < types.length; ctr++) {

            if(!types[ctr].isPrimitive()) {

                if( types[ctr].getName().equals("java.lang.String") )
                    result = ctr;

                else
                    return ctr;
            }
        }
        return result;
    }

    public String getSignature()
    {
        return this.signature;
    }

    public long getHash()
    {
        return this.hash;
    }

    public boolean isPrimitive()
    {
        return this.isPrimitive;
    }

    public boolean isVoid()
    {
        return this.isVoid;
    }

    public CtMethod getMethod() throws CannotCompileException, NotFoundException
    {
        if( this.method == null ) {
            MethodCandidate tmp = new MethodCandidate(this.getSignature());
            this.method = tmp.getMethod();
        }

        return this.method;
    }

    public String convertToString()
    {
        return this.signature + "; " + this.hash + "; " + this.isPrimitive + "; " + this.isVoid;
    }
}
