package com.cybershield.controller;

import com.cybershield.model.PhishingKeyword;
import com.cybershield.service.layer1.KeywordDetectionService;
import com.cybershield.service.supabase.SupabaseClientService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/keywords")
@CrossOrigin(origins = "*")
public class KeywordController {

    private final SupabaseClientService supabaseService;
    private final KeywordDetectionService keywordService;

    public KeywordController(SupabaseClientService supabaseService, KeywordDetectionService keywordService) {
        this.supabaseService = supabaseService;
        this.keywordService = keywordService;
    }

    @GetMapping
    public ResponseEntity<List<PhishingKeyword>> listKeywords() {
        return ResponseEntity.ok(supabaseService.fetchKeywords());
    }

    @PostMapping
    public ResponseEntity<PhishingKeyword> addKeyword(@RequestBody PhishingKeyword keyword) {
        PhishingKeyword saved = supabaseService.addKeyword(keyword);
        keywordService.reloadKeywords();
        return ResponseEntity.ok(saved);
    }

    @PostMapping("/reload")
    public ResponseEntity<Map<String, Object>> reloadEngine() {
        keywordService.reloadKeywords();
        return ResponseEntity.ok(Map.of(
                "status", "SUCCESS",
                "message", "Aho-Corasick Trie rebuilt successfully",
                "totalKeywords", supabaseService.fetchKeywords().size()
        ));
    }

    @GetMapping("/supabase-status")
    public ResponseEntity<Map<String, Object>> getSupabaseStatus() {
        return ResponseEntity.ok(supabaseService.getStatus());
    }
}
