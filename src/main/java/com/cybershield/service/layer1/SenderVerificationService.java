package com.cybershield.service.layer1;

import com.cybershield.model.ThreatIndicator;
import org.apache.commons.text.similarity.LevenshteinDistance;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SenderVerificationService {

    private static final Pattern EMAIL_HEADER_PATTERN = Pattern.compile("^(?:\"?([^\"]*)\"?\\s*)?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})>?$");

    private static final Set<String> FREE_EMAIL_PROVIDERS = Set.of(
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "mail.com", "zoho.com", "proton.me", "protonmail.com"
    );

    private static final Set<String> DISPOSABLE_PROVIDERS = Set.of(
            "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com", "sharklasers.com",
            "yopmail.com", "trashmail.com", "throwawaymail.com", "dispostable.com", "fakeinbox.com"
    );

    private static final Map<String, String> TARGETED_BRANDS = Map.ofEntries(
            Map.entry("paypal", "paypal.com"),
            Map.entry("microsoft", "microsoft.com"),
            Map.entry("google", "google.com"),
            Map.entry("apple", "apple.com"),
            Map.entry("amazon", "amazon.com"),
            Map.entry("netflix", "netflix.com"),
            Map.entry("chase", "chase.com"),
            Map.entry("bank of america", "bankofamerica.com"),
            Map.entry("wells fargo", "wellsfargo.com"),
            Map.entry("dhl", "dhl.com"),
            Map.entry("fedex", "fedex.com"),
            Map.entry("docusign", "docusign.com"),
            Map.entry("dropbox", "dropbox.com"),
            Map.entry("facebook", "facebook.com"),
            Map.entry("instagram", "instagram.com"),
            Map.entry("coinbase", "coinbase.com"),
            Map.entry("binance", "binance.com")
    );

    private final LevenshteinDistance levenshtein = new LevenshteinDistance();

    public static class SenderDetails {
        public String displayName = "";
        public String email = "";
        public String domain = "";
    }

    public SenderDetails parseSender(String rawSender) {
        SenderDetails details = new SenderDetails();
        if (rawSender == null || rawSender.trim().isEmpty()) {
            return details;
        }

        String trimmed = rawSender.trim();
        Matcher matcher = EMAIL_HEADER_PATTERN.matcher(trimmed);
        if (matcher.find()) {
            details.displayName = matcher.group(1) != null ? matcher.group(1).trim() : "";
            details.email = matcher.group(2) != null ? matcher.group(2).trim().toLowerCase() : "";
        } else {
            // Fallback for simple address
            if (trimmed.contains("@")) {
                int atIdx = trimmed.lastIndexOf("@");
                details.email = trimmed.replaceAll("[<>]", "").trim().toLowerCase();
            }
        }

        if (details.email.contains("@")) {
            details.domain = details.email.substring(details.email.indexOf("@") + 1);
        }

        return details;
    }

    public List<ThreatIndicator> verifySender(String rawSender) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        if (rawSender == null || rawSender.trim().isEmpty()) {
            indicators.add(new ThreatIndicator(
                    "Layer 1",
                    "MISSING_SENDER",
                    "Missing or Empty Sender Header",
                    "The email does not specify a valid sender header, typical of automated spam injection.",
                    "MEDIUM",
                    4.0,
                    "Sender is empty"
            ));
            return indicators;
        }

        SenderDetails details = parseSender(rawSender);

        // Check 1: RFC Format
        if (details.email.isEmpty() || !details.email.contains("@")) {
            indicators.add(new ThreatIndicator(
                    "Layer 1",
                    "INVALID_EMAIL_FORMAT",
                    "Malformed Sender Address",
                    "The sender address fails standard RFC 5322 syntax validation.",
                    "HIGH",
                    6.0,
                    rawSender
            ));
            return indicators;
        }

        // Check 2: Disposable Email Provider
        if (DISPOSABLE_PROVIDERS.contains(details.domain)) {
            indicators.add(new ThreatIndicator(
                    "Layer 1",
                    "DISPOSABLE_EMAIL",
                    "Disposable / Burner Email Service",
                    "Sender domain '" + details.domain + "' is a known disposable temporary mailbox provider.",
                    "HIGH",
                    6.5,
                    details.domain
            ));
        }

        // Check 3: Display Name Spoofing
        if (!details.displayName.isEmpty()) {
            String lowerDisplayName = details.displayName.toLowerCase();
            for (Map.Entry<String, String> entry : TARGETED_BRANDS.entrySet()) {
                String brandName = entry.getKey();
                String legitimateDomain = entry.getValue();

                if (lowerDisplayName.contains(brandName)) {
                    if (!details.domain.equalsIgnoreCase(legitimateDomain) &&
                        !details.domain.endsWith("." + legitimateDomain)) {

                        boolean isFreemail = FREE_EMAIL_PROVIDERS.contains(details.domain);
                        double score = isFreemail ? 8.5 : 7.5;
                        String severity = "CRITICAL";

                        indicators.add(new ThreatIndicator(
                                "Layer 1",
                                "DISPLAY_NAME_SPOOFING",
                                "Display Name Brand Impersonation",
                                String.format("Sender display name claims to be '%s' but message was sent from unrelated domain '%s' (%s).",
                                        details.displayName, details.domain, isFreemail ? "Free Public Webmail" : "Unverified Domain"),
                                severity,
                                score,
                                String.format("Name: \"%s\" <Domain: %s>", details.displayName, details.domain)
                        ));
                        break;
                    }
                }
            }
        }

        // Check 4: Lookalike / Typosquatted Domain in Sender Address
        for (String legitimateDomain : TARGETED_BRANDS.values()) {
            String cleanLegit = legitimateDomain.replace(".com", "");
            String senderDomainClean = details.domain.replace(".com", "").replace(".net", "").replace(".org", "");

            if (!details.domain.equalsIgnoreCase(legitimateDomain)) {
                // If contains brand name + hyphens/extra words e.g. "paypal-security" or "apple-support"
                if (details.domain.contains(cleanLegit) && !details.domain.endsWith("." + legitimateDomain)) {
                    indicators.add(new ThreatIndicator(
                            "Layer 1",
                            "TYPOSQUATTING_DOMAIN",
                            "Lookalike Domain / Brand Piggybacking",
                            String.format("Sender domain '%s' incorporates trusted brand keyword '%s' to deceive recipients.",
                                    details.domain, cleanLegit),
                            "HIGH",
                            7.0,
                            details.domain
                    ));
                    break;
                }

                // Check Levenshtein distance for typosquatting (e.g. paypa1, micros0ft)
                int dist = levenshtein.apply(cleanLegit, senderDomainClean);
                if (dist == 1 || (cleanLegit.length() > 6 && dist == 2)) {
                    indicators.add(new ThreatIndicator(
                            "Layer 1",
                            "HOMOGLYPH_TYPOSQUATTING",
                            "Typosquatted Brand Sender Domain",
                            String.format("Sender domain '%s' is an intentional typosquatting variant of legitimate domain '%s'.",
                                    details.domain, legitimateDomain),
                            "CRITICAL",
                            8.0,
                            details.domain
                    ));
                    break;
                }
            }
        }

        return indicators;
    }
}
