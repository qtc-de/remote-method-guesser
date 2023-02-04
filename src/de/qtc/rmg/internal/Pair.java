package de.qtc.rmg.internal;

/**
 * For the MethodArguments class, a Pair type is required. Unfortunately, Java 8 does not support such a
 * type natively. This class is a very basic implementation that fulfills the requirements.
 *
 * @author Tobias Neitzel (@qtc_de)
 *
 * @param <K> type of left
 * @param <V> type of right
 */
public class Pair<K, V> {

    private K left;
    private V right;

    public Pair(K left, V right)
    {
        this.left = left;
        this.right = right;
    }

    public K left()
    {
        return this.left;
    }

    public V right()
    {
        return this.right;
    }
}
