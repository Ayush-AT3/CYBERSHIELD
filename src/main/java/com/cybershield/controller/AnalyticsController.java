package com.cybershield.controller;

import com.cybershield.model.RiskClassification;
import com.cybershield.model.ScanResult;
import com.cybershield.service.cache.CacheService;
import com.cybershield.service.supabase.SupabaseClientService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/analytics")
@CrossOrigin(origins = "*")
public class AnalyticsController {

    private final CacheService cacheService;
    private final SupabaseClientService supabaseService;

    public AnalyticsController(CacheService cacheService, SupabaseClientService supabaseService) {
        this.cacheService = cacheService;
        this.supabaseService = supabaseService;
    }

    @GetMapping("/summary")
    public ResponseEntity<Map<String, Object>> getSummary() {
        List<ScanResult> scans = cacheService.getRecentScans();

        long safeCount = scans.stream().filter(s -> s.getClassification() == RiskClassification.SAFE).count();
        long suspiciousCount = scans.stream().filter(s -> s.getClassification() == RiskClassification.SUSPICIOUS).count();
        long dangerousCount = scans.stream().filter(s -> s.getClassification() == RiskClassification.DANGEROUS).count();

        double avgScore = scans.isEmpty() ? 0.0 :
                scans.stream().mapToDouble(ScanResult::getOverallRiskScore).average().orElse(0.0);
        avgScore = Math.round(avgScore * 10.0) / 10.0;

        Map<String, Object> summary = new HashMap<>();
        summary.put("totalScans", scans.size());
        summary.put("safeCount", safeCount);
        summary.put("suspiciousCount", suspiciousCount);
        summary.put("dangerousCount", dangerousCount);
        summary.put("averageRiskScore", avgScore);
        summary.put("cacheStats", cacheService.getCacheStats());
        summary.put("supabaseStatus", supabaseService.getStatus());

        return ResponseEntity.ok(summary);
    }
}
