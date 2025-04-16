package com.atc;

//import com.atc.service.CBCAlgorithm;
//import com.atc.service.LCG;
//import com.atc.service.RSAAlgorithm;
//import com.atc.service.SHA1HashService;

import java.util.Base64;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AtcBackendApplication {

    public static void main(String[] args) throws Exception {
        // Seed for LCG
//        long seed = System.currentTimeMillis();
//        long lcgKey = LCG.generateLCG(seed);
//        System.out.println("Generated LCG Key: " + lcgKey);
//
//        // CBC Encryption
//        CBCAlgorithm cbc = new CBCAlgorithm(Long.toString(lcgKey).getBytes());
//        String originalText = "Hello CBC!";
//        String encryptedCBC = cbc.encrypt(originalText);
//        String decryptedCBC = cbc.decrypt(encryptedCBC);
//
//        System.out.println("\n--- CBC ---");
//        System.out.println("Original: " + originalText);
//        System.out.println("Encrypted: " + encryptedCBC);
//        System.out.println("Decrypted: " + decryptedCBC);
//
//        // RSA Encryption
//        RSAAlgorithm rsa = new RSAAlgorithm(lcgKey);
//        String rsaEncrypted = rsa.encrypt("Hello RSA!");
//        String rsaDecrypted = rsa.decrypt(rsaEncrypted);
//
//        System.out.println("\n--- RSA ---");
//        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(rsa.getPublicKey().getEncoded()));
//        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(rsa.getPrivateKey().getEncoded()));
//        System.out.println("Encrypted: " + rsaEncrypted);
//        System.out.println("Decrypted: " + rsaDecrypted);
//
//        // SHA-1 Hash
//        String inputText = "Hello SHA-1!";
//        String sha1Hash = SHA1HashService.hash(inputText);
//        System.out.println("\n--- SHA-1 ---");
//        System.out.println("Input: " + inputText);
//        System.out.println("Hash: " + sha1Hash);

        SpringApplication.run(AtcBackendApplication.class, args);
    }
}
