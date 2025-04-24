package com.atc.service;


import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;

public class RSAGeneratorService {

    //  Helper Function: GCD using Euclidean algorithm
    public static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    //  Extended Euclidean Algorithm to get modular inverse
    public static int modInverse(int e, int phi) {
        int a = e, b = phi;
        int x0 = 1, x1 = 0;
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

    //  Check if number is prime using improved trial division
    public static boolean isPrime(int n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;

        // Check divisibility by numbers of form 6k±1 up to sqrt(n)
        for (int i = 5; i * i <= n; i += 6) {
            if (n % i == 0 || n % (i + 2) == 0)
                return false;
        }
        return true;
    }

    //  Generate a prime number within a range using seed
    public static int generatePrimeFromSeed(long seed, int minBits, int maxBits) {
        // Custom linear congruential generator with better parameters
        final long a = 6364136223846793005L;
        final long c = 1442695040888963407L;
        final long m = 1L << 48;

        long x = seed;
        int min = 1 << (minBits - 1);
        int max = (1 << maxBits) - 1;

        // Generate random numbers and test for primality
        while (true) {
            // Update the LCG state
            x = (a * x + c) % m;

            // Map to the desired range and ensure it's odd
            int candidate = min + (int)(x % (max - min + 1));
            if (candidate % 2 == 0) candidate++;

            // Skip if divisible by small primes
            if (candidate % 3 == 0 || candidate % 5 == 0 || candidate % 7 == 0) continue;

            // Test if the number is prime
            if (isPrime(candidate)) {
                return candidate;
            }
        }
    }

    //  Generate two distinct primes
    public static int[] generateTwoDistinctPrimes(long seed, int bits) {
        int p = generatePrimeFromSeed(seed, bits - 1, bits);
        int q;

        // Use a different seed for the second prime
        long secondSeed = (seed * 31) ^ (p * 17);
        do {
            q = generatePrimeFromSeed(secondSeed, bits - 1, bits);
            secondSeed = (secondSeed * 37) ^ (q * 41);
        } while (p == q);

        return new int[] {p, q};
    }

    //  Modular exponentiation
    public static int modPow(int base, int exp, int mod) {
        if (mod == 1) return 0;
        long result = 1;
        long b = base % mod;

        while (exp > 0) {
            if ((exp & 1) == 1) {
                result = (result * b) % mod;
            }
            exp >>= 1;
            b = (b * b) % mod;
        }

        return (int) result;
    }

    //  Convert int[] to byte[]
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

    //  Convert byte[] to int[]
    public static int[] bytesToNumberArray(byte[] bytes, int byteLength) {
        int count = bytes.length / byteLength;
        int[] result = new int[count];
        for (int i = 0; i < count; i++) {
            int num = 0;
            for (int j = 0; j < byteLength; j++) {
                num = (num << 8) | (bytes[i * byteLength + j] & 0xFF);
            }
            result[i] = num;
        }
        return result;
    }

    //  RSA Key Pair Class
    public static class RSAKeyPair {
        public int n;
        public int e;
        public int d;

        public RSAKeyPair(int n, int e, int d) {
            this.n = n;
            this.e = e;
            this.d = d;
        }
    }

    //  Generate RSA Keys with fixed e value
    public static RSAKeyPair generateRSAKeys() {
        // Keep e fixed at 19 as requested
        int e = 19;

        // Use current time as seed for better randomness
        long seed = System.currentTimeMillis();

        // Using 10-bit primes for this example to stay within int range
        int bits = 10;

        int[] primes;
        int p, q, n, phi;

        // Keep generating primes until we find ones compatible with e=19
        do {
            primes = generateTwoDistinctPrimes(seed, bits);
            p = primes[0];
            q = primes[1];
            n = p * q;
            phi = (p - 1) * (q - 1);

            // Change seed for next attempt if needed
            seed = (seed * 101) + 7919;
        } while (e >= phi || gcd(e, phi) != 1);

        int d = modInverse(e, phi);
        return new RSAKeyPair(n, e, d);
    }

    //  Encrypt text and return base64
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

    //  Decrypt base64 string to original text
    public static String decryptTextBase64(String base64, int n, int d) {
        byte[] encryptedBytes;
        try {
            encryptedBytes = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Base64 decoding failed. Invalid input.");
        }

        if (encryptedBytes.length % 4 != 0) {
            throw new RuntimeException("Invalid encrypted byte array length.");
        }

        int[] cipherNums = bytesToNumberArray(encryptedBytes, 4);
        byte[] decryptedBytes = new byte[cipherNums.length];
        for (int i = 0; i < cipherNums.length; i++) {
            int m = modPow(cipherNums[i], d, n);
            decryptedBytes[i] = (byte) (m & 0xFF);
        }

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // Main
//    public static void main(String[] args) {
//        RSAKeyPair keys = generateRSAKeys();
//
//        System.out.println("Public Key: (" + keys.n + ", " + keys.e + ")");
//        System.out.println("Private Key: (" + keys.n + ", " + keys.d + ")");
//
//        String message = "Lorem ipsum dolor sit, amet consectetur s";
//
//        String encrypted = encryptTextBase64(message, keys.n, keys.e);
//        String decrypted = decryptTextBase64(encrypted, keys.n, keys.d);
//
//        System.out.println("Original Message: " + message);
//        System.out.println("Encrypted (base64): " + encrypted);
//        System.out.println("Decrypted Message: " + decrypted);
//    }
}