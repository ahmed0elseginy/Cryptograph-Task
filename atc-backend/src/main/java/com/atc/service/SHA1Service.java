package com.atc.service;
import java.security.MessageDigest;

public class SHA1Service {
    public String hash(String text) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hashBytes = digest.digest(text.getBytes());
        return bytesToHex(hashBytes);
    }

    public boolean verify(String text, String hash) throws Exception {
        String computedHash = hash(text);
        return computedHash.equals(hash);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}