package de.qtc.rmg.internal;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.qtc.rmg.utils.RMGUtils;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.NotFoundException;

public class MethodCandidate {

    private long hash;
    private String signature;
    private boolean primitive;

    public MethodCandidate(String signature) throws CannotCompileException, NotFoundException
    {
        this.signature = signature;

        RMGUtils.createTypesFromSignature(signature);
        CtMethod method = RMGUtils.makeMethod(signature);

        this.hash = getCtMethodHash(method);
        this.primitive = checkPrimitive(method);
    }


    public MethodCandidate(String signature, String hash, String isPrimitive)
    {
        this.signature = signature;
        this.hash = Long.valueOf(hash);
        this.primitive = Boolean.valueOf(isPrimitive);
    }


    private boolean checkPrimitive(CtMethod method) throws NotFoundException
    {
        CtClass[] types = method.getParameterTypes();
        return types[0].isPrimitive();
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
        return this.primitive;
    }

    public String convertToString()
    {
        return this.signature + "; " + this.hash + "; " + this.primitive;
    }
}
