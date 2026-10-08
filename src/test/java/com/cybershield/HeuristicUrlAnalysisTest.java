package com.cybershield;

import com.cybershield.model.ThreatIndicator;
import com.cybershield.service.cache.CacheService;
import com.cybershield.service.layer3.BrandImpersonationDetector;
import com.cybershield.service.layer3.HeuristicUrlAnalysisService;
import com.cybershield.service.layer3.ShannonEntropyCalculator;
import com.cybershield.service.layer3.VirusTotalIntegrationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class HeuristicUrlAnalysisTest {

    private HeuristicUrlAnalysisService urlService;
    private ShannonEntropyCalculator entropyCalculator;

    @BeforeEach
    public void setUp() {
        entropyCalculator = new ShannonEntropyCalculator();
        BrandImpersonationDetector brandDetector = new BrandImpersonationDetector();
        CacheService cacheService = new CacheService();
        VirusTotalIntegrationService vtService = new VirusTotalIntegrationService(cacheService);
        urlService = new HeuristicUrlAnalysisService(entropyCalculator, brandDetector, vtService);
    }

    @Test
    public void testIpBasedUrlDetection() {
        String ipUrl = "http://192.168.1.50/login.php";
        List<ThreatIndicator> indicators = urlService.analyzeUrl(ipUrl, false);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("IP_BASED_URL")));
    }

    @Test
    public void testHighEntropyHostDetection() {
        String randomDga = "http://xkj94k3nd029flskam2094kf.com/index";
        double entropy = entropyCalculator.calculateEntropy("xkj94k3nd029flskam2094kf.com");
        assertTrue(entropy > 3.8);

        List<ThreatIndicator> indicators = urlService.analyzeUrl(randomDga, false);
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("HIGH_ENTROPY_HOST")));
    }

    @Test
    public void testBrandImpersonationInSubdomain() {
        String spoofedUrl = "https://paypal.com.verify-account-security.xyz/login";
        List<ThreatIndicator> indicators = urlService.analyzeUrl(spoofedUrl, false);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("BRAND_SUBDOMAIN_SPOOF")));
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("ABUSIVE_TLD"))); // .xyz
    }

    @Test
    public void testUserInfoAtSignObfuscation() {
        String obfuscated = "http://www.google.com@attacker-server.com/malicious";
        List<ThreatIndicator> indicators = urlService.analyzeUrl(obfuscated, false);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("USERINFO_SPOOFING")));
    }
}
