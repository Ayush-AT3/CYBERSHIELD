package com.cybershield.service.layer2;

import com.cybershield.model.ThreatIndicator;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

@Service
public class RegexPatternAnalysisService {

    private final List<PatternRule> rules = new ArrayList<>();

    public RegexPatternAnalysisService() {
        initDefaultRules();
    }

    private void initDefaultRules() {
        // --- 1. URGENCY & THREAT COERCION PATTERNS ---
        rules.add(new PatternRule(
                "URG-01",
                "Punitive Account Action Threat",
                "URGENCY",
                "\\b(account\\s+(?:will\\s+be|has\\s+been|is\\s+being|is)\\s*(?:permanently\\s+)?(?:suspended|terminated|deactivated|frozen|restricted|locked|closed|disabled))\\b",
                5.5,
                "HIGH",
                "Detects coercive language threatening immediate punitive action on user accounts."
        ));

        rules.add(new PatternRule(
                "URG-02",
                "Strict Time Deadline Pressure",
                "URGENCY",
                "\\b(?:within|in)\\s+(?:24|48|12|1|few)\\s*(?:hours|hrs|minutes|mins)\\b|\\b(?:immediate|urgent)\\s+action\\s+required\\b|\\bact\\s+now\\s+or\\s+(?:lose|face)\\b",
                4.5,
                "HIGH",
                "Detects artificial time urgency engineered to bypass user skepticism."
        ));

        rules.add(new PatternRule(
                "URG-03",
                "Fabricated Security Breach Warning",
                "URGENCY",
                "\\b(?:unauthorized\\s+(?:login|access|device|transaction|activity)|suspicious\\s+(?:sign-in|activity|attempt)\\s+detected)\\b",
                4.0,
                "MEDIUM",
                "Detects fake security alert pretexts designed to induce panic."
        ));

        // --- 2. CREDENTIAL HARVESTING PATTERNS ---
        rules.add(new PatternRule(
                "CRED-01",
                "Direct Account Verification Call-To-Action",
                "CREDENTIAL_REQUEST",
                "\\b(?:click\\s+(?:here|below|this\\s+link)|tap\\s+here)\\s+to\\s+(?:verify|confirm|validate|unlock|update|reactivate|restore)\\s+(?:your\\s+)?(?:account|identity|email|password|profile|credentials|access)\\b",
                5.0,
                "CRITICAL",
                "Identifies classic phishing calls-to-action directing the user to input credentials."
        ));

        rules.add(new PatternRule(
                "CRED-02",
                "Sensitive Credential / PII Solicitation",
                "CREDENTIAL_REQUEST",
                "\\b(?:enter|provide|input|submit)\\s+(?:your\\s+)?(?:current\\s+)?(?:password|pin|security\\s+code|ssn|social\\s+security|credit\\s+card|cvv|cvc|otp|passcode)\\b",
                6.0,
                "CRITICAL",
                "Detects explicit solicitations for sensitive credentials or security codes."
        ));

        rules.add(new PatternRule(
                "CRED-03",
                "Password Expiration / Reset Demand",
                "CREDENTIAL_REQUEST",
                "\\b(?:password\\s+(?:will\\s+expire|has\\s+expired|expiry\\s+notice)|reset\\s+your\\s+password\\s+immediately)\\b",
                4.2,
                "MEDIUM",
                "Flags urgent password expiration notifications frequently used in enterprise phishing."
        ));

        // --- 3. FINANCIAL FRAUD & EXPLOITATION PATTERNS ---
        rules.add(new PatternRule(
                "FIN-01",
                "Wire Transfer / Irreversible Payment Request",
                "FINANCIAL_FRAUD",
                "\\b(?:wire\\s+transfer|send\\s+(?:funds|money|cryptocurrency|crypto|bitcoin|usdt)|western\\s+union|moneygram|zelle|cash\\s*app)\\b",
                5.0,
                "HIGH",
                "Detects references to non-reversible money transfers typical of 419 and BEC scams."
        ));

        rules.add(new PatternRule(
                "FIN-02",
                "Fraudulent Winnings or Government Refund Lure",
                "FINANCIAL_FRAUD",
                "\\b(?:you\\s+(?:have\\s+won|are\\s+selected\\s+for|are\\s+entitled\\s+to)|claim\\s+your\\s+(?:lottery|prize|grant|inheritance|compensation|tax\\s+refund|stimulus))\\b",
                5.5,
                "HIGH",
                "Detects monetary reward hooks used in advance-fee fraud schemes."
        ));

        rules.add(new PatternRule(
                "FIN-03",
                "Fake Overdue Invoice / Billing Penalty",
                "FINANCIAL_FRAUD",
                "\\b(?:overdue\\s+(?:invoice|payment|balance)|remittance\\s+advice|payment\\s+(?:pending|failed|declined)|unpaid\\s+bill\\s+attached)\\b",
                4.0,
                "MEDIUM",
                "Detects invoice and billing lures common in business email compromise attacks."
        ));

        // --- 4. BEHAVIORAL & DEFENSE EVASION PATTERNS ---
        rules.add(new PatternRule(
                "BEH-01",
                "Concealment & Secrecy Mandate",
                "BEHAVIORAL",
                "\\b(?:keep\\s+this\\s+(?:confidential|secret|private|strictly\\s+between\\s+us)|do\\s+not\\s+(?:tell|share|contact|inform|discuss\\s+with)\\s+(?:anyone|support|your\\s+bank|manager|it\\s+department))\\b",
                6.0,
                "CRITICAL",
                "Flags psychological isolation attempts instructing victims not to consult security staff."
        ));

        rules.add(new PatternRule(
                "BEH-02",
                "Security Evasion / Macro Execution Prompt",
                "BEHAVIORAL",
                "\\b(?:disable\\s+(?:your\\s+)?(?:antivirus|firewall|defender|windows\\s+security)|enable\\s+(?:macros|content|editing)\\s+to\\s+(?:view|read|decrypt|access))\\b",
                7.5,
                "CRITICAL",
                "Detects direct requests to bypass host endpoint security or execute weaponized macros."
        ));
    }

    public List<ThreatIndicator> analyze(String text) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        if (text == null || text.trim().isEmpty()) {
            return indicators;
        }

        for (PatternRule rule : rules) {
            Matcher matcher = rule.getPattern().matcher(text);
            if (matcher.find()) {
                String matchedSnippet = matcher.group();
                indicators.add(new ThreatIndicator(
                        "Layer 2",
                        rule.getCategory(),
                        rule.getName(),
                        rule.getDescription(),
                        rule.getSeverity(),
                        rule.getWeight(),
                        "Matched: \"" + matchedSnippet + "\""
                ));
            }
        }

        return indicators;
    }

    public List<PatternRule> getRules() {
        return new ArrayList<>(rules);
    }
}
