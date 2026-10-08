package com.cybershield;

import com.cybershield.model.ThreatIndicator;
import com.cybershield.service.layer2.RegexPatternAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RegexPatternAnalysisTest {

    private RegexPatternAnalysisService regexService;

    @BeforeEach
    public void setUp() {
        regexService = new RegexPatternAnalysisService();
    }

    @Test
    public void testUrgencyAndAccountThreatDetection() {
        String input = "Your account will be suspended within 24 hours unless you act now!";
        List<ThreatIndicator> indicators = regexService.analyze(input);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("URGENCY")));
    }

    @Test
    public void testCredentialHarvestingPattern() {
        String input = "Please click here to verify your account credentials and enter your password.";
        List<ThreatIndicator> indicators = regexService.analyze(input);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("CREDENTIAL_REQUEST")));
    }

    @Test
    public void testFinancialFraudPattern() {
        String input = "Congratulations, you have won $5,000,000! Wire transfer will be initiated today.";
        List<ThreatIndicator> indicators = regexService.analyze(input);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("FINANCIAL_FRAUD")));
    }

    @Test
    public void testDefenseEvasionPattern() {
        String input = "Please enable macros to view the encrypted invoice details.";
        List<ThreatIndicator> indicators = regexService.analyze(input);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("BEHAVIORAL")));
    }
}
