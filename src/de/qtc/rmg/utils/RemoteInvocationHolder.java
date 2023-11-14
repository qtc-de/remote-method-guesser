package de.qtc.rmg.utils;

import java.util.Arrays;

import org.springframework.remoting.support.RemoteInvocation;

import de.qtc.rmg.internal.MethodCandidate;


/**
 * RemoteInvocation objects do not contain all information that MethodCandidates contain. When converting
 * a MethodCandidate to a RemoteInvocation, information like the signature or the return value get lost.
 * Moreover, two RemoteInvocations can be considered the same when they have a similar name and similar
 * method arguments. The return value does not matter.
 *
 * The RemoteInvocationHolder class is designed to overcome these problems. It tracks the associated
 * MethodCandidate to each RemoteInvocation and implements methods that allow to compare RemoteInvocations
 * and to filter duplicates.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RemoteInvocationHolder
{
    private RemoteInvocation invo;
    private MethodCandidate candidate;

    /**
     * An RemoteInvocationWrapper simply contains a RemoteInvocation and the associated MethodCandidate.
     *
     * @param invo  the RemoteInvocation
     * @param candidate  the associated MethodCandidate
     */
    public RemoteInvocationHolder(RemoteInvocation invo, MethodCandidate candidate)
    {
        this.invo = invo;
        this.candidate = candidate;
    }

    /**
     * Two RemoteInocationHolders are the same, if their contained RemoteInvocation uses the same
     * method name and the same argument types.
     *
     * @param other  Object to compare with
     * @return true if the objects can be considered the same
     */
    public boolean equals(Object other)
    {
        if (other instanceof RemoteInvocationHolder)
        {
            RemoteInvocationHolder otherInvocation = (RemoteInvocationHolder)other;

            if (otherInvocation.getName().equals(this.getName()))
            {
                if (Arrays.equals(otherInvocation.getTypes(), this.getTypes()))
                {
                    return true;
                }
            }
        }

        return false;
    }

    public int hashCode()
    {
        return invo.toString().hashCode();
    }

    public String getName()
    {
        return invo.getMethodName();
    }

    public Class<?>[] getTypes()
    {
        return invo.getParameterTypes();
    }

    public MethodCandidate getCandidate()
    {
        return candidate;
    }

    public RemoteInvocation getInvo()
    {
        return invo;
    }
}
