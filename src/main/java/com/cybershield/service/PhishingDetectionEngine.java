package com.cybershield.service;

import com.cybershield.model.*;
import com.cybershield.service.cache.CacheService;
import com.cybershield.service.layer1.KeywordDetectionService;
import com.cybershield.service.layer1.SenderVerificationService;
import com.cybershield.service.layer2.RegexPatternAnalysisService;
import com.cybershield.service.layer3.HeuristicUrlAnalysisService;
import com.cybershield.service.layer4.AttachmentAnalysisService;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class PhishingDetectionEngine {

    private final KeywordDetectionService keywordService;
    private final SenderVerificationService senderService;
    private final RegexPatternAnalysisService regexService;
    private final HeuristicUrlAnalysisService urlService;
    private final AttachmentAnalysisService attachmentService;
    private final CacheService cacheService;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.cybershield.service.database.DatabaseService databaseService;

    public PhishingDetectionEngine(KeywordDetectionService keywordService,
                                   SenderVerificationService senderService,
                                   RegexPatternAnalysisService regexService,
                                   HeuristicUrlAnalysisService urlService,
                                   AttachmentAnalysisService attachmentService,
                                   CacheService cacheService) {
        this.keywordService = keywordService;
        this.senderService = senderService;
        this.regexService = regexService;
        this.urlService = urlService;
        this.attachmentService = attachmentService;
        this.cacheService = cacheService;
    }

    public ScanResult scanEmail(EmailScanRequest request) {
        long startTime = System.currentTimeMillis();
        ScanResult result = new ScanResult();
        result.setScanType("EMAIL");
        result.setSender(request.getSender());
        result.setSubject(request.getSubject());
        result.setInputTarget(request.getSubject() != null && !request.getSubject().isEmpty() ?
                request.getSubject() : (request.getSender() != null ? request.getSender() : "Email Message"));

        // ==========================================
        // LAYER 1: Aho-Corasick Keywords & Sender Verification
        // ==========================================
        long l1Start = System.currentTimeMillis();
        LayerResult l1Result = new LayerResult(1, "Layer 1: Aho-Corasick Keywords & Sender Verification");

        // 1A: Sender verification
        List<ThreatIndicator> senderIndicators = senderService.verifySender(request.getSender());
        senderIndicators.forEach(l1Result::addIndicator);

        // 1B: Keyword matching in Subject and Body via Aho-Corasick Automaton
        String combinedContent = (request.getSubject() != null ? request.getSubject() + " " : "") +
                (request.getBody() != null ? request.getBody() : "");
        List<ThreatIndicator> keywordIndicators = keywordService.detectKeywords(combinedContent, "Email Content");
        keywordIndicators.forEach(l1Result::addIndicator);

        l1Result.setExecutionTimeMs(System.currentTimeMillis() - l1Start);
        l1Result.setSummary(String.format("Identified %d sender indicators and %d keyword matches.",
                senderIndicators.size(), keywordIndicators.size()));
        result.addLayerResult(l1Result);

        // ==========================================
        // LAYER 2: Regex Suspicious Language Analysis
        // ==========================================
        long l2Start = System.currentTimeMillis();
        LayerResult l2Result = new LayerResult(2, "Layer 2: Regex-Based Linguistic & Behavioral Analysis");

        List<ThreatIndicator> regexIndicators = regexService.analyze(combinedContent);
        regexIndicators.forEach(l2Result::addIndicator);

        l2Result.setExecutionTimeMs(System.currentTimeMillis() - l2Start);
        l2Result.setSummary(String.format("Identified %d suspicious linguistic pattern triggers.", regexIndicators.size()));
        result.addLayerResult(l2Result);

        // ==========================================
        // LAYER 3: Heuristic URL Analysis & VirusTotal Intelligence
        // ==========================================
        long l3Start = System.currentTimeMillis();
        LayerResult l3Result = new LayerResult(3, "Layer 3: Heuristic URL Analysis & Threat Intelligence");

        Set<String> allUrls = new LinkedHashSet<>();
        if (request.getUrls() != null) {
            allUrls.addAll(request.getUrls());
        }
        allUrls.addAll(urlService.extractUrls(combinedContent));

        int analyzedUrlCount = 0;
        for (String url : allUrls) {
            List<ThreatIndicator> urlIndicators = urlService.analyzeUrl(url, request.isTriggerVirusTotal());
            urlIndicators.forEach(l3Result::addIndicator);
            analyzedUrlCount++;
        }

        l3Result.setExecutionTimeMs(System.currentTimeMillis() - l3Start);
        l3Result.setSummary(String.format("Extracted and evaluated %d embedded URLs.", analyzedUrlCount));
        result.addLayerResult(l3Result);

        // ==========================================
        // LAYER 4: Email Attachment Threat Analysis
        // ==========================================
        long l4Start = System.currentTimeMillis();
        LayerResult l4Result = new LayerResult(4, "Layer 4: Attachment & Payload Analysis");

        List<ThreatIndicator> attachmentIndicators = attachmentService.analyzeAttachments(request.getAttachments());
        attachmentIndicators.forEach(l4Result::addIndicator);

        l4Result.setExecutionTimeMs(System.currentTimeMillis() - l4Start);
        l4Result.setSummary(String.format("Inspected %d attachment files.",
                request.getAttachments() != null ? request.getAttachments().size() : 0));
        result.addLayerResult(l4Result);

        // ==========================================
        // CUMULATIVE RISK SCORING & CLASSIFICATION (Capped at 15.0 max)
        // ==========================================
        double cumulativeScore = l1Result.getScore() + l2Result.getScore() + l3Result.getScore() + l4Result.getScore();
        cumulativeScore = Math.min(15.0, cumulativeScore);
        cumulativeScore = Math.round(cumulativeScore * 10.0) / 10.0;
        result.setOverallRiskScore(cumulativeScore);

        RiskClassification classification = RiskClassification.fromScore(cumulativeScore);
        result.setClassification(classification);

        // Security recommendations
        generateRecommendations(result);

        result.setTotalExecutionTimeMs(System.currentTimeMillis() - startTime);

        // Cache scan result
        cacheService.recordScan(result);

        // Persist to H2 Database
        if (databaseService != null) {
            databaseService.saveScanResult(result);
        }

        return result;
    }

    public ScanResult scanUrl(UrlScanRequest request) {
        long startTime = System.currentTimeMillis();
        ScanResult result = new ScanResult();
        result.setScanType("URL");
        result.setInputTarget(request.getUrl());

        LayerResult l3Result = new LayerResult(3, "Layer 3: Heuristic URL Analysis & Threat Intelligence");
        List<ThreatIndicator> indicators = urlService.analyzeUrl(request.getUrl(), request.isForceVirusTotal());
        indicators.forEach(l3Result::addIndicator);

        double score = Math.min(15.0, l3Result.getScore());
        score = Math.round(score * 10.0) / 10.0;
        l3Result.setSummary(String.format("Heuristic analysis produced %d threat indicators.", indicators.size()));
        l3Result.setExecutionTimeMs(System.currentTimeMillis() - startTime);
        result.addLayerResult(l3Result);

        result.setOverallRiskScore(score);
        result.setClassification(RiskClassification.fromScore(score));
        generateRecommendations(result);
        result.setTotalExecutionTimeMs(System.currentTimeMillis() - startTime);

        cacheService.recordScan(result);

        // Persist to H2 Database
        if (databaseService != null) {
            databaseService.saveScanResult(result);
        }

        return result;
    }

    private void generateRecommendations(ScanResult result) {
        List<String> recs = new ArrayList<>();
        RiskClassification c = result.getClassification();

        if (c == RiskClassification.DANGEROUS) {
            recs.add("QUARANTINE IMMEDIATELY: High threat confidence. Block sender domain at gateway.");
            recs.add("Do NOT click any hyperlinks or navigate to embedded destinations.");
            recs.add("Do NOT open or download any attached payloads; submit to sandbox analysis.");
            recs.add("If credentials were submitted, initiate emergency password resets and revoke active sessions.");
        } else if (c == RiskClassification.SUSPICIOUS) {
            recs.add("CAUTION: Message exhibits multiple characteristics typical of social engineering.");
            recs.add("Independently verify sender identity via a secondary trusted channel (e.g. phone or known intranet).");
            recs.add("Inspect destination URLs carefully for typosquatting before entering sensitive information.");
        } else {
            recs.add("PASSED: No prominent phishing indicators detected.");
            recs.add("Standard security precautions still apply for unexpected attachments or requests.");
        }

        result.setRecommendations(recs);
        result.setSummary(String.format("Scan completed with cumulative risk score of %.1f (%s).",
                result.getOverallRiskScore(), c.getLabel()));
    }
}
