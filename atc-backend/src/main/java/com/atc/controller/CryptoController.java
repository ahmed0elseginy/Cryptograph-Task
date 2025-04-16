package com.atc.controller;

import com.atc.service.CBCService;
import com.atc.service.LCG;
import com.atc.service.RSAService;
import com.atc.service.SHA1Service;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Controller
public class CryptoController {

    private final CBCService cbcService = new CBCService();
    private final RSAService rsaService = new RSAService();
    private final SHA1Service sha1Service = new SHA1Service();

    public CryptoController() throws Exception {
    }

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @PostMapping("/encrypt/cbc")
    @ResponseBody
    public Map<String, String> encryptCBC(@RequestBody Map<String, String> requestBody) throws Exception {
        String inputText = requestBody.get("inputText");

        LCG lcg = new LCG(System.currentTimeMillis());
        String key = lcg.generateKey(16);
        String encryptedText = cbcService.encrypt(inputText, key);

        Map<String, String> response = new HashMap<>();
        response.put("cbcKey", key);
        response.put("cbcEncryptedText", encryptedText);
        return response;
    }

    @PostMapping("/encrypt/rsa")
    @ResponseBody
    public Map<String, String> encryptRSA(@RequestBody Map<String, String> requestBody) throws Exception {
        String inputText = requestBody.get("inputText");

        String encryptedText = rsaService.encrypt(inputText);

        Map<String, String> response = new HashMap<>();
        response.put("rsaPublicKey", rsaService.getPublicKey());
        response.put("rsaPrivateKey", rsaService.getPrivateKey());
        response.put("rsaEncryptedText", encryptedText);
        return response;
    }

    @PostMapping("/encrypt/sha1")
    @ResponseBody
    public Map<String, String> hashSHA1(@RequestBody Map<String, String> requestBody) throws Exception {
        String inputText = requestBody.get("inputText");

        String hash = sha1Service.hash(inputText);

        Map<String, String> response = new HashMap<>();
        response.put("sha1HashedText", hash);
        return response;
    }
}