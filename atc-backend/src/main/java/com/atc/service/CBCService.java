package com.atc.service;

import java.util.Base64;

public class CBCService {

    private static final int BLOCK_SIZE = 16;

    // Encrypt and return both encrypted text and IV (encoded)
    public String encrypt(String text, String key) {
        byte[] keyBytes = key.getBytes();
        byte[] iv = generateIV(key.hashCode()); // Use key hash for consistent IV generation

        byte[] padded = pad(text.getBytes());
        byte[] encrypted = new byte[padded.length];

        byte[] previous = iv;
        for (int i = 0; i < padded.length; i += BLOCK_SIZE) {
            byte[] block = xor(slice(padded, i, BLOCK_SIZE), previous);
            byte[] encryptedBlock = simpleEncrypt(block, keyBytes);
            System.arraycopy(encryptedBlock, 0, encrypted, i, BLOCK_SIZE);
            previous = encryptedBlock;
        }

        // Combine encrypted data and IV with separator
        return Base64.getEncoder().encodeToString(encrypted) + ":" + Base64.getEncoder().encodeToString(iv);
    }

    // Decrypt using encrypted text and IV string (base64 encoded)
    public String decrypt(String encryptedData, String key) {
        // Split the combined string into encrypted text and IV
        String[] parts = encryptedData.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid encrypted format. Expected format: 'encrypted:iv'");
        }

        byte[] encryptedBytes = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] keyBytes = key.getBytes();
        byte[] decrypted = new byte[encryptedBytes.length];

        byte[] previous = iv;
        for (int i = 0; i < encryptedBytes.length; i += BLOCK_SIZE) {
            byte[] block = slice(encryptedBytes, i, BLOCK_SIZE);
            byte[] decryptedBlock = xor(simpleEncrypt(block, keyBytes), previous);
            System.arraycopy(decryptedBlock, 0, decrypted, i, BLOCK_SIZE);
            previous = block;
        }
        System.out.println(new String(unpad(decrypted)));
        return new String(unpad(decrypted));
    }

    private byte[] simpleEncrypt(byte[] block, byte[] key) {
        byte[] result = new byte[block.length];
        for (int i = 0; i < block.length; i++) {
            result[i] = (byte) (block[i] ^ key[i % key.length]);
        }
        return result;
    }

    private byte[] pad(byte[] data) {
        int padLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = new byte[data.length + padLen];
        System.arraycopy(data, 0, padded, 0, data.length);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) padLen;
        }
        return padded;
    }

    private byte[] unpad(byte[] data) {
        int padLen = data[data.length - 1];
        byte[] unpadded = new byte[data.length - padLen];
        System.arraycopy(data, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }

    private byte[] slice(byte[] data, int start, int length) {
        byte[] result = new byte[length];
        int availableLength = Math.min(length, data.length - start);
        System.arraycopy(data, start, result, 0, availableLength);
        return result;
    }

    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    // Standard Base64 encoding
    private String encodeBase64(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    // Standard Base64 decoding
    private byte[] decodeBase64(String input) {
        return Base64.getDecoder().decode(input);
    }

    // Generate a random IV using LCG
    private byte[] generateIV(long seed) {
        LCG lcg = new LCG(seed);
        return lcg.generateKey(16).getBytes();
    }
}
