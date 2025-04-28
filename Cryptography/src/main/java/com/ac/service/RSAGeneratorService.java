package com.ac.service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class RSAGeneratorService {

    // GCD using Euclidean algorithm
    public static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    // Extended Euclidean Algorithm for modular inverse
    public static int modInverse(int e, int phi) {
        int x0 = 1, x1 = 0, a = e, b = phi;
        while (b != 0) {
            int q = a / b;
            int temp = a % b;
            a = b;
            b = temp;
            int tempX = x0 - q * x1;
            x0 = x1;
            x1 = tempX;
        }
        return x0 < 0 ? x0 + phi : x0;
    }

    // Prime checking using trial division
    public static boolean isPrime(int n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        for (int i = 5; i * i <= n; i += 6) {
            if (n % i == 0 || n % (i + 2) == 0) return false;
        }
        return true;
    }

    // Generate a prime number within a range using LCG
    public static int generatePrimeFromSeed(LCG lcg, int minBits, int maxBits) {
        int min = 1 << (minBits - 1);
        int max = (1 << maxBits) - 1;
        while (true) {
            int candidate = min + (int) (lcg.next() % (max - min + 1));
            if (candidate % 2 == 0) candidate++;
            if (candidate % 3 == 0 || candidate % 5 == 0 || candidate % 7 == 0) continue;
            if (isPrime(candidate)) return candidate;
        }
    }

    // Generate two distinct primes
    public static int[] generateTwoDistinctPrimes(long seed, int bits) {
        LCG lcg1 = new LCG(seed);
        int p = generatePrimeFromSeed(lcg1, bits - 1, bits);

        LCG lcg2 = new LCG((seed * 31) ^ (p * 17));
        int q;
        do {
            q = generatePrimeFromSeed(lcg2, bits - 1, bits);
        } while (p == q);

        return new int[]{p, q};
    }

    // Modular exponentiation
    public static int modPow(int base, int exp, int mod) {
        long result = 1, b = base % mod;
        while (exp > 0) {
            if ((exp & 1) == 1) result = (result * b) % mod;
            exp >>= 1;
            b = (b * b) % mod;
        }
        return (int) result;
    }

    // Convert int[] to byte[]
    public static byte[] numberArrayToBytes(int[] arr, int byteLength) {
        List<Byte> bytes = new ArrayList<>();
        for (int num : arr) {
            for (int i = byteLength - 1; i >= 0; i--) {
                bytes.add((byte) ((num >> (8 * i)) & 0xFF));
            }
        }
        byte[] result = new byte[bytes.size()];
        for (int i = 0; i < result.length; i++) result[i] = bytes.get(i);
        return result;
    }

    // Convert byte[] to int[]
    public static int[] bytesToNumberArray(byte[] bytes, int byteLength) {
        int[] result = new int[bytes.length / byteLength];
        for (int i = 0; i < result.length; i++) {
            int num = 0;
            for (int j = 0; j < byteLength; j++) {
                num = (num << 8) | (bytes[i * byteLength + j] & 0xFF);
            }
            result[i] = num;
        }
        return result;
    }

    // RSA Key Pair
    public static class RSAKeyPair {
        public int n, e, d;
        public RSAKeyPair(int n, int e, int d) {
            this.n = n;
            this.e = e;
            this.d = d;
        }
    }

    // Generate RSA keys with fixed e = 19
    public static RSAKeyPair generateRSAKeys() {
        int e = 19, bits = 10;
        long seed = System.currentTimeMillis();
        int p, q, n, phi;
        do {
            int[] primes = generateTwoDistinctPrimes(seed, bits);
            p = primes[0];
            q = primes[1];
            n = p * q;
            phi = (p - 1) * (q - 1);
            seed = (seed * 101) + 7919;
        } while (e >= phi || gcd(e, phi) != 1);

        int d = modInverse(e, phi);
        return new RSAKeyPair(n, e, d);
    }

    // Encrypt text and return Base64
    public static String encryptTextBase64(String text, int n, int e) {
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        if (textBytes.length > 53) {
            throw new IllegalArgumentException("Text too long for encryption block");
        }

        int[] encrypted = new int[textBytes.length];
        for (int i = 0; i < textBytes.length; i++) {
            encrypted[i] = modPow(textBytes[i] & 0xFF, e, n);
        }

        byte[] encryptedBytes = numberArrayToBytes(encrypted, 4);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt Base64 string to original text
    public static String decryptTextBase64(String base64, int n, int d) {
        byte[] encryptedBytes;
        try {
            encryptedBytes = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException("Base64 decoding failed. Invalid input.");
        }

        if (encryptedBytes.length % 4 != 0) {
            throw new RuntimeException("Invalid encrypted byte array length.");
        }

        int[] cipherNums = bytesToNumberArray(encryptedBytes, 4);
        byte[] decryptedBytes = new byte[cipherNums.length];
        for (int i = 0; i < cipherNums.length; i++) {
            decryptedBytes[i] = (byte) (modPow(cipherNums[i], d, n) & 0xFF);
        }

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
