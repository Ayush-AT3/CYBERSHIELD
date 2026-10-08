package com.cybershield.controller;

import com.cybershield.model.EmailScanRequest;
import com.cybershield.model.ScanResult;
import com.cybershield.model.UrlScanRequest;
import com.cybershield.service.PhishingDetectionEngine;
import com.cybershield.service.cache.CacheService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scan")
@CrossOrigin(origins = "*")
public class ScanController {

    private final PhishingDetectionEngine engine;
    private final CacheService cacheService;
    private final com.cybershield.service.EmlParserService emlParserService;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.cybershield.service.database.DatabaseService databaseService;

    public ScanController(PhishingDetectionEngine engine, CacheService cacheService,
                          com.cybershield.service.EmlParserService emlParserService) {
        this.engine = engine;
        this.cacheService = cacheService;
        this.emlParserService = emlParserService;
    }

    @PostMapping("/email")
    public ResponseEntity<ScanResult> scanEmail(@RequestBody EmailScanRequest request) {
        ScanResult result = engine.scanEmail(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/eml")
    public ResponseEntity<ScanResult> scanEmlFile(@RequestParam("file") org.springframework.web.multipart.MultipartFile file) {
        try {
            EmailScanRequest request = emlParserService.parseEml(file);
            ScanResult result = engine.scanEmail(request);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            ScanResult errorResult = new ScanResult();
            errorResult.setScanType("EMAIL_EML");
            errorResult.setSummary("Failed to parse .eml file: " + e.getMessage());
            errorResult.setClassification(com.cybershield.model.RiskClassification.SAFE);
            return ResponseEntity.badRequest().body(errorResult);
        }
    }

    @PostMapping("/url")
    public ResponseEntity<ScanResult> scanUrl(@RequestBody UrlScanRequest request) {
        ScanResult result = engine.scanUrl(request);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScanResult> getScanById(@PathVariable String id) {
        return cacheService.getScanById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/history")
    public ResponseEntity<List<ScanResult>> getRecentScans() {
        return ResponseEntity.ok(cacheService.getRecentScans());
    }

    @GetMapping("/db-history")
    public ResponseEntity<?> getDatabaseScanHistory() {
        if (databaseService != null) {
            return ResponseEntity.ok(databaseService.getRecentScans());
        }
        return ResponseEntity.ok(cacheService.getRecentScans());
    }
}
