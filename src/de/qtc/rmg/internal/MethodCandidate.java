package de.qtc.rmg.internal;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.qtc.rmg.io.Logger;
import de.qtc.rmg.io.RawObjectOutputStream;
import de.qtc.rmg.utils.RMGUtils;
import javassist.CannotCompileException;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.NotFoundException;

/**
 * A MethodCandidate represents a remote method that may exists on a remote endpoint. The
 * class is mainly used to compute the method hash from a method signature and to make
 * certain meta information easy accessible. Usually, MethodCandidates are created from a
 * user specified wordlist or function signature.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MethodCandidate
{
    private long hash;

    private CtMethod method;
    private String signature;

    private boolean isVoid;
    private int argumentCount;
    private int primitiveSize;

    /**
     * Creates a MethodCandidate from a method signature defined as String. The constructor first of all
     * checks for unknown types within the method signature and creates the dynamically. Afterwards, it
     * compiles the method signature to a CtMethod and initializes meta information containing variables
     * on demand.
     *
     * @param signature method signature to create the MethodCandidate from
     * @throws CannotCompileException is thrown when the method signature is invalid
     * @throws NotFoundException should not be thrown in practice
     */
    public MethodCandidate(String signature) throws CannotCompileException, NotFoundException
    {
        this.signature = signature;
        RMGUtils.createTypesFromSignature(signature);

        method = RMGUtils.makeMethod(signature);
        initialize(method);
    }

    /**
     * The advanced wordlist format of rmg allows storing methods right away with their corresponding
     * method hash and the required meta information. If such information is available within the
     * wordlist file, this constructor is used.
     *
     * @param signature method signature to create the MethodCandidate from.
     * @param hash method hash for the corresponding method.
     * @param primitiveSize number of bytes before the first non primitive argument
     * @param isVoid if true, the method does not take any arguments
     */
    public MethodCandidate(String signature, String hash, String primitiveSize, String isVoid)
    {
        this.signature = signature;
        this.hash = Long.valueOf(hash);
        this.primitiveSize = Integer.valueOf(primitiveSize);
        this.isVoid = Boolean.valueOf(isVoid);
    }

    /**
     * This constructor allows creating a MethodCandidate based on an already present CtMethod.
     * This is currently only used in the case of already known classes that are encountered
     * during method guessing.
     *
     * @param method CtMethod object
     * @throws NotFoundException
     */
    public MethodCandidate(CtMethod method) throws NotFoundException
    {
        this.signature = RMGUtils.getSimpleSignature(method);
        initialize(method);
    }

    /**
     * Takes the CtMethod that belongs to the MethodCandidate and initializes the object attributes
     * from it.
     *
     * @param method CtMethod that belongs to the MethodCandidate
     * @throws NotFoundException
     */
    private void initialize(CtMethod method) throws NotFoundException
    {
        CtClass[] types = method.getParameterTypes();

        this.argumentCount = types.length;
        this.hash = getCtMethodHash(method);

        if (argumentCount == 0)
        {
            this.isVoid = true;
            this.primitiveSize = -99;
        }

        else
        {
            this.isVoid = false;
            this.primitiveSize = RMGUtils.getPrimitiveSize(types);
        }
    }

    /**
     * Computes the RMI method hash over a CtMethod.
     *
     * @param method CtMethod to calculate the hash from
     * @return RMI method hash
     */
    private static long getCtMethodHash(CtMethod method)
    {
        String methodSignature = method.getName() + method.getSignature();
        return computeMethodHash(methodSignature);
    }

    /**
     * Computes the RMI method hash from a method signature. This function was basically
     * copied from https://github.com/waderwu/attackRmi and is therefore licensed under the
     * Apache-2.0 License.
     *
     * @param methodSignature signature to compute the hash on
     * @return RMI method hash
     */
    private static long computeMethodHash(String methodSignature)
    {
        long hash = 0;
        ByteArrayOutputStream sink = new ByteArrayOutputStream(127);

        try
        {
            MessageDigest md = MessageDigest.getInstance("SHA");
            DataOutputStream out = new DataOutputStream(new DigestOutputStream(sink, md));

            out.writeUTF(methodSignature);

            // use only the first 64 bits of the digest for the hash
            out.flush();
            byte hasharray[] = md.digest();

            for (int i = 0; i < Math.min(8, hasharray.length); i++)
            {
                hash += ((long) (hasharray[i] & 0xFF)) << (i * 8);
            }
        }

        catch (IOException ignore)
        {
            /* can't happen, but be deterministic anyway. */
            hash = -1;
        }

        catch (NoSuchAlgorithmException complain)
        {
            throw new SecurityException(complain.getMessage());
        }

        return hash;
    }

    /**
     * During guessing operations, we want to invoke methods with confused arguments. This means that:
     *
     * - If the function expects a primitive argument as first parameter, we should write an object
     * - If the function expects a non primitive argument as first parameter, we should write a primitive
     *
     * This function returns the corresponding argument type depending on the corresponding method definition.
     *
     * @return confused parameter for method invocation
     * @throws IOException
     */
    @SuppressWarnings("restriction")
    public void sendArguments(ObjectOutputStream oo) throws IOException
    {
        if (this.primitiveSize == -99)
        {
            oo.flush();
        }

        else if (this.primitiveSize == -1)
        {
            oo.flush();
            RawObjectOutputStream rout = new RawObjectOutputStream(oo);
            rout.writeRaw(sun.rmi.transport.TransportConstants.Ping);
        }

        else
        {
            oo.write(new byte[this.primitiveSize]);
            oo.writeByte(1);
        }
    }

    /**
     * Returns the parameter types of the method as obtained from the CtMethod.
     *
     * @return the parameter types for the method
     * @throws CannotCompileException should never occur
     * @throws NotFoundException should never occur
     */
    public CtClass[] getParameterTypes() throws CannotCompileException, NotFoundException
    {
        return this.getMethod().getParameterTypes();
    }

    /**
     * Obtain the name of the corresponding method. If the CtMethod was not created so far,
     * the function returns the placeholder "method".
     *
     * @return the name of the method
     * @throws CannotCompileException should never occur
     * @throws NotFoundException should never occur
     */
    public String getName() throws CannotCompileException, NotFoundException
    {
        if (this.method != null)
        {
            return this.getMethod().getName();
        }

        else
        {
            return "method";
        }
    }

    /**
     * Returns the expected argument count of the method candidate.
     *
     * @return expected argument count as int
     */
    public int getArgumentCount()
    {
        return argumentCount;
    }

    /**
     * Searches the current MethodCandidate for non primitive arguments (yes, the name is misleading).
     * Non primitive arguments are required for deserialization attacks. If a non primitive argument is
     * found, the method returns the corresponding argument position. If an error was found or no primitive
     * argument was found, the method returns -1.
     *
     * On invocation, a suggestion for a non primitive argument can be specified. In this case, the function
     * just checks whether the corresponding argument is a primitive and returns the corresponding position
     * if this is the case. Again, -1 is returned on error.
     *
     * @param selected suggestion for a primitive argument
     * @return position of a primitive argument within the parameter array
     * @throws NotFoundException should never occur
     * @throws CannotCompileException should never occur
     */
    public int getPrimitive(int selected) throws NotFoundException, CannotCompileException
    {
        CtClass[] types = this.getParameterTypes();

        if (selected != -1)
        {
            if (selected >= types.length)
            {
                Logger.eprintlnMixedYellow("Specified argument position", String.valueOf(selected), "is out of bounds.");
                return -1;
            }

            if (types[selected].isPrimitive())
            {
                Logger.eprintlnMixedYellow("Specified argument position", String.valueOf(selected), "is a primitive type.");
                return -1;
            }

            return selected;
        }

        int result = -1;
        for (int ctr = 0; ctr < types.length; ctr++)
        {
            if (!types[ctr].isPrimitive())
            {
                if (types[ctr].getName().equals("java.lang.String"))
                {
                    result = ctr;
                }

                else
                {
                    return ctr;
                }
            }
        }

        return result;
    }

    /**
     * Returns the current value of the signature attribute.
     *
     * @return The methods signature.
     */
    public String getSignature()
    {
        return this.signature;
    }

    /**
     * Returns the current value of the hash attribute.
     *
     * @return hash value of the method
     */
    public long getHash()
    {
        return this.hash;
    }

    /**
     * Returns the current value of the primitiveSize attribute.
     *
     * @return true if first argument within the method is a primitive
     */
    public int primitiveSize()
    {
        return this.primitiveSize;
    }

    /**
     * Returns the current value of the isVoid attribute.
     *
     * @return true if method does not take arguments, false otherwise
     */
    public boolean isVoid()
    {
        return this.isVoid;
    }

    /**
     * If not already done, creates a CtMethod from the stored method signature.
     *
     * @return CtMethod
     * @throws CannotCompileException if method signature was invalid
     * @throws NotFoundException if method signature was invalid
     */
    public CtMethod getMethod() throws CannotCompileException, NotFoundException
    {
        if (this.method == null)
        {
            MethodCandidate tmp = new MethodCandidate(this.getSignature());
            this.method = tmp.getMethod();
        }

        return this.method;
    }

    /**
     * @return the MethodCandidate as it should be stored in the advanced wordlist format.
     */
    public String convertToString()
    {
        return this.signature + "; " + this.hash + "; " + this.primitiveSize + "; " + this.isVoid;
    }

    /**
     * Returns the name of the parameter type in the specified position of the argument array.
     *
     * @param position Position in the argument array to obtain the type from
     * @return name of the requested type
     */
    public String getArgumentTypeName(int position)
    {
        String typeName = "None";

        try
        {
            typeName = this.method.getParameterTypes()[position].getName();
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "parameter type", "determination", true);
        }

        return typeName;
    }

    /**
     * Two MethodCandidates are equal when their method hash is equal.
     */
    @Override
    public boolean equals(Object o)
    {
        if (!(o instanceof MethodCandidate))
        {
            return false;
        }

        MethodCandidate other = (MethodCandidate)o;
        return this.hash == other.getHash();
    }

    /**
     * MethodCandidates are hashed according to their method hash.
     */
    @Override
    public int hashCode()
    {
       return Long.hashCode(this.hash);
    }
}
