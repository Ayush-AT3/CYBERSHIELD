package com.cybershield;

import com.cybershield.model.ThreatIndicator;
import com.cybershield.service.layer1.SenderVerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SenderVerificationTest {

    private SenderVerificationService senderService;

    @BeforeEach
    public void setUp() {
        senderService = new SenderVerificationService();
    }

    @Test
    public void testDisplayNameSpoofingDetection() {
        String spoofedSender = "\"PayPal Security\" <alert@suspicious-domain-123.com>";
        List<ThreatIndicator> indicators = senderService.verifySender(spoofedSender);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("DISPLAY_NAME_SPOOFING")));
        assertEquals("CRITICAL", indicators.get(0).getSeverity());
    }

    @Test
    public void testTyposquattedSenderDomain() {
        String typosquatted = "support@paypa1.com";
        List<ThreatIndicator> indicators = senderService.verifySender(typosquatted);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().contains("TYPOSQUATTING")));
    }

    @Test
    public void testDisposableEmailProvider() {
        String burner = "hacker@tempmail.com";
        List<ThreatIndicator> indicators = senderService.verifySender(burner);

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("DISPOSABLE_EMAIL")));
    }

    @Test
    public void testLegitimateSenderProducesNoAlerts() {
        String legitimate = "\"PayPal Support\" <service@paypal.com>";
        List<ThreatIndicator> indicators = senderService.verifySender(legitimate);

        assertTrue(indicators.isEmpty());
    }
}
