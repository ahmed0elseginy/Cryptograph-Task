package com.atc.controller;

import com.atc.service.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@Controller
public class CryptoController {

    private final CBCService cbcService = new CBCService();
    private final RSAService rsaService = new RSAService();
    private final SHA1Service sha1Service = new SHA1Service();
    private RSAGeneratorService.RSAKeyPair currentKeyPair;

    public CryptoController() {
        this.currentKeyPair = RSAGeneratorService.generateRSAKeys();
    }

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @PostMapping("/encrypt/cbc")
    @ResponseBody
    public Map<String, String> encryptCBC(@RequestBody Map<String, String> requestBody) {
        String inputText = requestBody.get("inputText");
        if (inputText == null || inputText.isEmpty()) {
            throw new IllegalArgumentException("Input text cannot be empty");
        }

        LCG lcg = new LCG(System.currentTimeMillis());
        String key = lcg.generateKey(16);
        String encryptedText = cbcService.encrypt(inputText, key);

        Map<String, String> response = new HashMap<>();
        response.put("cbcKey", key);
        response.put("cbcEncryptedText", encryptedText);
        return response;
    }

    @PostMapping("/decrypt/cbc")
    @ResponseBody
    public Map<String, String> decryptCBC(@RequestBody Map<String, String> requestBody) {
        String inputCipher = requestBody.get("inputCipher");
        String key = requestBody.get("key");

        if (inputCipher == null || inputCipher.isEmpty()) {
            throw new IllegalArgumentException("Input cipher cannot be empty");
        }
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be empty");
        }

        String decryptedText = cbcService.decrypt(inputCipher, key);

        Map<String, String> response = new HashMap<>();
        response.put("cbcDecryptedText", decryptedText);
        return response;
    }

    @PostMapping("/encrypt/rsa")
    @ResponseBody
    public Map<String, String> encryptRSA(@RequestBody Map<String, String> requestBody) {
        String inputText = requestBody.get("inputText");
        if (inputText == null || inputText.isEmpty()) {
            throw new IllegalArgumentException("Input text cannot be empty");
        }

        try {
            String publicKey = rsaService.getPublicKey();
            String[] publicKeyParts = publicKey.split(",e:");
            if (publicKeyParts.length != 2) {
                throw new IllegalStateException("Invalid public key format");
            }

            String nStr = publicKeyParts[0].substring(2); // Remove "n:" prefix
            String eStr = publicKeyParts[1];

            BigInteger n = new BigInteger(1, rsaService.base64Decode(nStr));
            BigInteger e = new BigInteger(1, rsaService.base64Decode(eStr));

            String encryptedText = rsaService.encryptWithPublicKey(inputText, e, n);

            Map<String, String> response = new HashMap<>();
            response.put("rsaPublicKey", publicKey);
            response.put("rsaPrivateKey", rsaService.getPrivateKey());
            response.put("rsaEncryptedText", encryptedText);
            return response;
        } catch (Exception e) {
            throw new RuntimeException("RSA encryption failed: " + e.getMessage(), e);
        }
    }

    @PostMapping("/decrypt/rsa")
    @ResponseBody
    public Map<String, String> decryptRSA(@RequestBody Map<String, String> requestBody) {
        String inputCipher = requestBody.get("inputCipher");
        String privateKey = requestBody.get("privateKey");

        if (inputCipher == null || inputCipher.isEmpty()) {
            throw new IllegalArgumentException("Input cipher cannot be empty");
        }
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("Private key cannot be empty");
        }

        try {
            String[] privateKeyParts = privateKey.split(",d:");
            if (privateKeyParts.length != 2) {
                throw new IllegalArgumentException("Invalid private key format");
            }

            String nStr = privateKeyParts[0].substring(2); // Remove "n:" prefix
            String dStr = privateKeyParts[1];

            BigInteger n = new BigInteger(1, rsaService.base64Decode(nStr));
            BigInteger d = new BigInteger(1, rsaService.base64Decode(dStr));

            String result = rsaService.decryptWithPrivateKey(inputCipher, d, n);

            Map<String, String> response = new HashMap<>();
            response.put("rsaDecryptedText", result);
            return response;
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
        }
    }

    @PostMapping("/encrypt/rsa-generator")
    @ResponseBody
    public Map<String, String> encryptRSAGenerator(@RequestBody Map<String, String> requestBody) {
        String inputText = requestBody.get("inputText");
        if (inputText == null || inputText.isEmpty()) {
            throw new IllegalArgumentException("Input text cannot be empty");
        }

        try {
            // Generate new keys for each encryption
            currentKeyPair = RSAGeneratorService.generateRSAKeys();
            String encrypted = RSAGeneratorService.encryptTextBase64(inputText, currentKeyPair.n, currentKeyPair.e);

            Map<String, String> response = new HashMap<>();
            response.put("rsaPublicKey", "n:" + currentKeyPair.n + ",e:" + currentKeyPair.e);
            response.put("rsaPrivateKey", "n:" + currentKeyPair.n + ",d:" + currentKeyPair.d);
            response.put("rsaEncryptedText", encrypted);
            return response;
        } catch (Exception e) {
            throw new RuntimeException("RSA Generator encryption failed: " + e.getMessage(), e);
        }
    }

    @PostMapping("/decrypt/rsa-generator")
    @ResponseBody
    public Map<String, String> decryptRSAGenerator(@RequestBody Map<String, String> requestBody) {
        String inputCipher = requestBody.get("inputCipher");
        String privateKey = requestBody.get("privateKey");

        if (inputCipher == null || inputCipher.isEmpty()) {
            throw new IllegalArgumentException("Input cipher cannot be empty");
        }
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("Private key cannot be empty");
        }

        try {
            // Parse private key components
            String[] privateKeyParts = privateKey.split(",d:");
            if (privateKeyParts.length != 2) {
                throw new IllegalArgumentException("Invalid private key format");
            }

            int n = Integer.parseInt(privateKeyParts[0].substring(2)); // Remove "n:" prefix
            int d = Integer.parseInt(privateKeyParts[1]);

            String decrypted = RSAGeneratorService.decryptTextBase64(inputCipher, n, d);

            Map<String, String> response = new HashMap<>();
            response.put("rsaDecryptedText", decrypted);
            return response;
        } catch (Exception e) {
            throw new RuntimeException("RSA Generator decryption failed: " + e.getMessage(), e);
        }
    }

    @PostMapping("/encrypt/sha1")
    @ResponseBody
    public Map<String, String> hashSHA1(@RequestBody Map<String, String> requestBody) {
        String inputText = requestBody.get("inputText");
        if (inputText == null || inputText.isEmpty()) {
            throw new IllegalArgumentException("Input text cannot be empty");
        }

        try {
            String hash = sha1Service.hash(inputText);

            Map<String, String> response = new HashMap<>();
            response.put("sha1HashedText", hash);
            return response;
        } catch (Exception e) {
            throw new RuntimeException("SHA-1 hashing failed: " + e.getMessage(), e);
        }
    }

    @PostMapping("/verify/sha1")
    @ResponseBody
    public Map<String, Boolean> verifySHA1(@RequestBody Map<String, String> requestBody) {
        String inputText = requestBody.get("inputText");
        String inputHash = requestBody.get("inputHash");

        if (inputText == null || inputText.isEmpty()) {
            throw new IllegalArgumentException("Input text cannot be empty");
        }
        if (inputHash == null || inputHash.isEmpty()) {
            throw new IllegalArgumentException("Input hash cannot be empty");
        }

        try {
            boolean isValid = sha1Service.verify(inputText, inputHash);

            Map<String, Boolean> response = new HashMap<>();
            response.put("isValid", isValid);
            return response;
        } catch (Exception e) {
            throw new RuntimeException("SHA-1 verification failed: " + e.getMessage(), e);
        }
    }
}