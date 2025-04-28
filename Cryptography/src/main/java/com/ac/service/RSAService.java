package com.ac.service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class RSAService {
    private BigInteger p, q, n, phi, publicKeyE, privateKeyD;
    private final int bitLength = 512;

    public RSAService() {
        generateKeys();
    }

    private void generateKeys() {
        Random rand = new Random();
        p = BigInteger.probablePrime(bitLength, rand);
        q = BigInteger.probablePrime(bitLength, rand);
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Common value for e
        publicKeyE = BigInteger.valueOf(65537);

        // Generate private key using LCG
        privateKeyD = findPrivateKeyUsingLCG(publicKeyE, phi);
    }

    // Find private key d using LCG to generate candidates
    private BigInteger findPrivateKeyUsingLCG(BigInteger e, BigInteger phi) {
        LCG lcg = new LCG(System.currentTimeMillis());

        // Number of candidates to try before falling back to direct calculation
        int maxCandidates = 100;

        for (int i = 0; i < maxCandidates; i++) {
            // Generate candidate using LCG
            String keyDigits = lcg.generateKey(bitLength / 4);
            BigInteger d = new BigInteger(keyDigits);

            // Ensure d is within valid range [2, phi-1]
            d = d.mod(phi.subtract(BigInteger.ONE)).add(BigInteger.valueOf(2));

            // Check if d is valid: (e * d) mod phi = 1
            if (e.multiply(d).mod(phi).equals(BigInteger.ONE)) {
                return d;
            }
        }

        // If LCG method fails, fall back to direct calculation
        System.out.println("LCG method failed to find valid key, falling back to direct calculation.");
        return e.modInverse(phi);
    }

    // Encrypt a message using the public key (e, n)
    public String encryptWithPublicKey(String text, BigInteger e, BigInteger n) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        BigInteger message = new BigInteger(1, bytes);

        // Ensure the message is smaller than n
        if (message.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Message too large for the given key size");
        }

        // Apply RSA encryption: c = m^e mod n
        BigInteger encrypted = message.modPow(e, n);
        return base64Encode(encrypted.toByteArray());
    }

    // Decrypt a message using the private key (d, n)
    public String decryptWithPrivateKey(String base64EncryptedText, BigInteger d, BigInteger n) {
        try {
            byte[] encryptedBytes = base64Decode(base64EncryptedText);
            BigInteger encrypted = new BigInteger(1, encryptedBytes);

            // Apply RSA decryption: m = c^d mod n
            BigInteger decrypted = encrypted.modPow(d, n);
            byte[] decryptedBytes = decrypted.toByteArray();

            // Handle leading zero byte if present (sign bit)
            if (decryptedBytes[0] == 0) {
                byte[] temp = new byte[decryptedBytes.length - 1];
                System.arraycopy(decryptedBytes, 1, temp, 0, temp.length);
                decryptedBytes = temp;
            }

            // Convert bytes back to string
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Decryption Error: " + e.getMessage();
        }
    }

    // Get the public key as a Base64 encoded string
    public String getPublicKey() {
        return "n:" + base64Encode(n.toByteArray()) + ",e:" + base64Encode(publicKeyE.toByteArray());
    }

    // Get the private key as a Base64 encoded string
    public String getPrivateKey() {
        return "n:" + base64Encode(n.toByteArray()) + ",d:" + base64Encode(privateKeyD.toByteArray());
    }

    // Custom Base64 encoding implementation
    private String base64Encode(byte[] data) {
        final char[] base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        StringBuilder result = new StringBuilder();

        int paddingCount = (3 - data.length % 3) % 3;
        int fullGroups = data.length / 3;

        // Process all complete groups of 3 bytes
        for (int i = 0; i < fullGroups * 3; i += 3) {
            int b = ((data[i] & 0xff) << 16) |
                    ((data[i + 1] & 0xff) << 8) |
                    (data[i + 2] & 0xff);

            result.append(base64Chars[(b >> 18) & 0x3f]);
            result.append(base64Chars[(b >> 12) & 0x3f]);
            result.append(base64Chars[(b >> 6) & 0x3f]);
            result.append(base64Chars[b & 0x3f]);
        }

        // Handle remaining bytes and padding
        if (paddingCount > 0) {
            int b = 0;
            int i = fullGroups * 3;
            for (int j = 0; j < 3 - paddingCount; j++) {
                b |= (data[i + j] & 0xff) << (16 - (j * 8));
            }

            result.append(base64Chars[(b >> 18) & 0x3f]);
            result.append(base64Chars[(b >> 12) & 0x3f]);

            if (paddingCount == 1) {
                result.append(base64Chars[(b >> 6) & 0x3f]);
                result.append("=");
            } else {
                result.append("==");
            }
        }

        return result.toString();
    }

    // Custom Base64 decoding implementation
    public byte[] base64Decode(String input) {
        final String base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int padding = input.endsWith("==") ? 2 : (input.endsWith("=") ? 1 : 0);
        input = input.replaceAll("=", ""); // Remove padding for processing
        byte[] bytes = new byte[(input.length() * 3 / 4) - padding];
        int byteIndex = 0;

        try {
            for (int i = 0; i < input.length(); i += 4) {
                int b = 0;
                for (int j = 0; j < 4 && (i + j) < input.length(); j++) {
                    int index = base64Chars.indexOf(input.charAt(i + j));
                    if (index == -1)
                        throw new IllegalArgumentException("Invalid Base64 character at position " + (i + j));
                    b |= index << (18 - (j * 6));
                }

                if (byteIndex < bytes.length) bytes[byteIndex++] = (byte) ((b >> 16) & 0xff);
                if (byteIndex < bytes.length) bytes[byteIndex++] = (byte) ((b >> 8) & 0xff);
                if (byteIndex < bytes.length) bytes[byteIndex++] = (byte) (b & 0xff);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Base64 decoding failed: " + e.getMessage());
        }

        return bytes;
    }

}