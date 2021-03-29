package de.qtc.rmg.internal;

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
