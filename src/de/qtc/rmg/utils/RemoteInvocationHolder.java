package de.qtc.rmg.utils;

import java.util.Arrays;

import org.springframework.remoting.support.RemoteInvocation;

import de.qtc.rmg.internal.MethodCandidate;

public class RemoteInvocationHolder
{
    private RemoteInvocation invo;
    private MethodCandidate candidate;

    public RemoteInvocationHolder(RemoteInvocation invo, MethodCandidate candidate)
    {
        this.invo = invo;
        this.candidate = candidate;
    }

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
