package com.atc.service;

public class LCG {
    private long seed;
    private final long a = 1664525; // Multiplier
    private final long c = 1013904223; // Increment
    private final long m = (long) Math.pow(2, 32); // Modulus

    public LCG(long seed) {
        this.seed = seed;
    }

    public long next() {
        seed = (a * seed + c) % m;
        return seed;
    }

    public String generateKey(int length) {
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append(next() % 10); // Generate digits for the key
        }
        return key.toString();
    }
}
