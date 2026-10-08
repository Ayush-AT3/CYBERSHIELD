package com.cybershield;

import com.cybershield.model.PhishingKeyword;
import com.cybershield.service.layer1.AhoCorasickEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AhoCorasickEngineTest {

    private AhoCorasickEngine engine;

    @BeforeEach
    public void setUp() {
        engine = new AhoCorasickEngine();
        List<PhishingKeyword> keywords = List.of(
                new PhishingKeyword("account suspended", "URGENCY", 5.0),
                new PhishingKeyword("verify your password", "CREDENTIAL", 5.0),
                new PhishingKeyword("within 24 hours", "URGENCY", 3.5),
                new PhishingKeyword("wire transfer", "FINANCIAL", 4.5)
        );
        engine.buildTrie(keywords);
    }

    @Test
    public void testKeywordMatchFound() {
        String input = "Urgent notice: Your account suspended alert! Please take action within 24 hours.";
        List<AhoCorasickEngine.Match> matches = engine.search(input);

        assertFalse(matches.isEmpty());
        assertTrue(matches.stream().anyMatch(m -> m.getKeyword().getKeyword().equals("account suspended")));
        assertTrue(matches.stream().anyMatch(m -> m.getKeyword().getKeyword().equals("within 24 hours")));
    }

    @Test
    public void testCleanTextProducesNoMatches() {
        String cleanInput = "Hello team, let's meet tomorrow at 10 AM to discuss the quarterly project roadmap.";
        List<AhoCorasickEngine.Match> matches = engine.search(cleanInput);

        assertTrue(matches.isEmpty());
    }

    @Test
    public void testCaseInsensitiveMatching() {
        String mixedCase = "PLEASE VERIFY YOUR PASSWORD IMMEDIATELY.";
        List<AhoCorasickEngine.Match> matches = engine.search(mixedCase);

        assertEquals(1, matches.size());
        assertEquals("verify your password", matches.get(0).getKeyword().getKeyword());
    }
}
