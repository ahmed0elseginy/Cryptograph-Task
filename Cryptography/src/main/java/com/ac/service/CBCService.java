package com.ac.service;

public class CBCService {

    private static final int BLOCK_SIZE = 16;

    public String encrypt(String text, String key) {
        byte[] keyBytes = key.getBytes();
        byte[] iv = generateIV(key.hashCode());
        byte[] paddedData = pad(text.getBytes());
        byte[] encrypted = new byte[paddedData.length];

        byte[] previous = iv;
        for (int i = 0; i < paddedData.length; i += BLOCK_SIZE) {
            byte[] block = xor(slice(paddedData, i, BLOCK_SIZE), previous);
            byte[] encryptedBlock = simpleEncrypt(block, keyBytes);
            System.arraycopy(encryptedBlock, 0, encrypted, i, BLOCK_SIZE);
            previous = encryptedBlock;
        }

        return encodeBase64(encrypted) + ":" + encodeBase64(iv);
    }

    public String decrypt(String encryptedData, String key) {
        String[] parts = encryptedData.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid encrypted format. Expected format: 'encrypted:iv'");
        }

        byte[] encryptedBytes = decodeBase64(parts[0]);
        byte[] iv = decodeBase64(parts[1]);
        byte[] keyBytes = key.getBytes();
        byte[] decrypted = new byte[encryptedBytes.length];

        byte[] previous = iv;
        for (int i = 0; i < encryptedBytes.length; i += BLOCK_SIZE) {
            byte[] block = slice(encryptedBytes, i, BLOCK_SIZE);
            byte[] decryptedBlock = xor(simpleEncrypt(block, keyBytes), previous);
            System.arraycopy(decryptedBlock, 0, decrypted, i, BLOCK_SIZE);
            previous = block;
        }

        byte[] unpadded = unpad(decrypted);
        return new String(unpadded);
    }

    private byte[] simpleEncrypt(byte[] block, byte[] key) {
        byte[] result = new byte[block.length];
        for (int i = 0; i < block.length; i++) {
            result[i] = (byte) (block[i] ^ key[i % key.length]);
        }
        return result;
    }

    private byte[] pad(byte[] data) {
        int padLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = new byte[data.length + padLength];
        System.arraycopy(data, 0, padded, 0, data.length);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) padLength;
        }
        return padded;
    }

    private byte[] unpad(byte[] data) {
        int padLength = data[data.length - 1];
        byte[] unpadded = new byte[data.length - padLength];
        System.arraycopy(data, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }

    private byte[] slice(byte[] data, int start, int length) {
        byte[] result = new byte[length];
        int available = Math.min(length, data.length - start);
        System.arraycopy(data, start, result, 0, available);
        return result;
    }

    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    private String encodeBase64(byte[] input) {
        return java.util.Base64.getEncoder().encodeToString(input);
    }

    private byte[] decodeBase64(String input) {
        return java.util.Base64.getDecoder().decode(input);
    }

    private byte[] generateIV(long seed) {
        LCG lcg = new LCG(seed);
        return lcg.generateKey(16).getBytes();
    }
}
