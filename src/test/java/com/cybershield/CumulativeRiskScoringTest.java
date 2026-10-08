package com.cybershield;

import com.cybershield.model.*;
import com.cybershield.service.PhishingDetectionEngine;
import com.cybershield.service.cache.CacheService;
import com.cybershield.service.layer1.KeywordDetectionService;
import com.cybershield.service.layer1.SenderVerificationService;
import com.cybershield.service.layer2.RegexPatternAnalysisService;
import com.cybershield.service.layer3.BrandImpersonationDetector;
import com.cybershield.service.layer3.HeuristicUrlAnalysisService;
import com.cybershield.service.layer3.ShannonEntropyCalculator;
import com.cybershield.service.layer3.VirusTotalIntegrationService;
import com.cybershield.service.layer4.AttachmentAnalysisService;
import com.cybershield.service.supabase.SupabaseClientService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class CumulativeRiskScoringTest {

    private PhishingDetectionEngine engine;

    @BeforeEach
    public void setUp() {
        CacheService cacheService = new CacheService();
        SupabaseClientService supabaseService = new SupabaseClientService();
        KeywordDetectionService keywordService = new KeywordDetectionService(supabaseService, cacheService);
        SenderVerificationService senderService = new SenderVerificationService();
        RegexPatternAnalysisService regexService = new RegexPatternAnalysisService();
        ShannonEntropyCalculator entropyCalculator = new ShannonEntropyCalculator();
        BrandImpersonationDetector brandDetector = new BrandImpersonationDetector();
        VirusTotalIntegrationService vtService = new VirusTotalIntegrationService(cacheService);
        HeuristicUrlAnalysisService urlService = new HeuristicUrlAnalysisService(entropyCalculator, brandDetector, vtService);
        AttachmentAnalysisService attachmentService = new AttachmentAnalysisService();

        engine = new PhishingDetectionEngine(
                keywordService, senderService, regexService, urlService, attachmentService, cacheService
        );
    }

    @Test
    public void testBenignEmailIsClassifiedAsSafe() {
        EmailScanRequest request = new EmailScanRequest(
                "\"Alice Project Manager\" <alice@techcorp-internal.com>",
                "Sprint Planning Meeting Tomorrow",
                "Hi team, please find the agenda for tomorrow's standup. We will discuss Q4 milestones."
        );
        ScanResult result = engine.scanEmail(request);

        assertTrue(result.getOverallRiskScore() < 5.0, "Score should be < 5.0 but was " + result.getOverallRiskScore());
        assertEquals(RiskClassification.SAFE, result.getClassification());
    }

    @Test
    public void testMildlySuspiciousEmailIsClassifiedAsSuspicious() {
        // Triggers display name spoofing using brand name with free webmail (+8.5)
        EmailScanRequest request = new EmailScanRequest(
                "\"PayPal Notifications\" <billing-department@gmail.com>",
                "Account Security Notice",
                "Hello customer, this is an automated notification regarding your recent login."
        );
        ScanResult result = engine.scanEmail(request);

        double score = result.getOverallRiskScore();
        assertTrue(score >= 5.0 && score < 10.0, "Score should be in [5.0, 9.9] but was " + score);
        assertEquals(RiskClassification.SUSPICIOUS, result.getClassification());
    }

    @Test
    public void testSophisticatedPhishingAttackIsClassifiedAsDangerous() {
        // High urgency, credential theft, spoofed sender, IP link, malicious attachment
        EmailScanRequest request = new EmailScanRequest(
                "\"PayPal Support\" <security-alert@scam-server-paypa1.xyz>",
                "URGENT: Your account will be suspended within 24 hours!",
                "Unauthorized login attempt detected! Click here to verify your account credentials immediately: http://192.168.1.100/paypal/login.php"
        );
        request.setAttachments(List.of(
                new AttachmentInfo("Account_Security_Patch.exe", 102400, "application/x-msdownload")
        ));

        ScanResult result = engine.scanEmail(request);

        double score = result.getOverallRiskScore();
        assertTrue(score >= 10.0, "Score should be >= 10.0 but was " + score);
        assertEquals(RiskClassification.DANGEROUS, result.getClassification());
    }
}
