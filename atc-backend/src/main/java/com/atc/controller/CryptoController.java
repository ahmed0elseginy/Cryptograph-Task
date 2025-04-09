package com.atc.controller;

import com.atc.service.CryptoService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CryptoController {

  private final CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @GetMapping("/")
    public String showForm() {
        return "index";
    }

    @PostMapping("/encrypt")
    public String encryptText(@RequestParam("inputText") String inputText, Model model) {
        String encryptedText = cryptoService.encrypt(inputText);
        model.addAttribute("originalText", inputText);
        model.addAttribute("encryptedText", encryptedText);
        return "index";
    }

    @PostMapping("/decrypt")
    public String decryptText(@RequestParam("encryptedText") String encryptedText, Model model) {
        String decryptedText = cryptoService.decrypt(encryptedText);
        model.addAttribute("encryptedText", encryptedText);
        model.addAttribute("decryptedText", decryptedText);
        return "index";
    }
}
