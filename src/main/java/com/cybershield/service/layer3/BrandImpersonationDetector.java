package com.cybershield.service.layer3;

import com.cybershield.model.ThreatIndicator;
import org.apache.commons.text.similarity.LevenshteinDistance;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.*;

@Component
public class BrandImpersonationDetector {

    private final LevenshteinDistance levenshtein = new LevenshteinDistance();

    private static final Map<String, String> TARGETED_BRANDS = Map.ofEntries(
            Map.entry("paypal", "paypal.com"),
            Map.entry("microsoft", "microsoft.com"),
            Map.entry("google", "google.com"),
            Map.entry("apple", "apple.com"),
            Map.entry("amazon", "amazon.com"),
            Map.entry("netflix", "netflix.com"),
            Map.entry("chase", "chase.com"),
            Map.entry("bankofamerica", "bankofamerica.com"),
            Map.entry("wellsfargo", "wellsfargo.com"),
            Map.entry("docusign", "docusign.com"),
            Map.entry("dropbox", "dropbox.com"),
            Map.entry("facebook", "facebook.com"),
            Map.entry("instagram", "instagram.com"),
            Map.entry("coinbase", "coinbase.com"),
            Map.entry("binance", "binance.com")
    );

    public List<ThreatIndicator> detectImpersonation(String rawUrl, String host, String path) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        if (host == null || host.isEmpty()) return indicators;

        String lowerHost = host.toLowerCase();
        String lowerPath = path != null ? path.toLowerCase() : "";

        // Extract registered base domain (rough approximation: last two segments e.g. domain.tld)
        String[] hostParts = lowerHost.split("\\.");
        String registeredDomain = hostParts.length >= 2 ?
                hostParts[hostParts.length - 2] + "." + hostParts[hostParts.length - 1] : lowerHost;
        String registeredName = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : lowerHost;

        for (Map.Entry<String, String> entry : TARGETED_BRANDS.entrySet()) {
            String brand = entry.getKey();
            String legitimateDomain = entry.getValue();

            // Skip if it IS the legitimate brand domain
            if (lowerHost.equals(legitimateDomain) || lowerHost.endsWith("." + legitimateDomain)) {
                continue;
            }

            // Case 1: Subdomain Brand Spoofing (e.g., login.paypal.com.scam-server.xyz)
            if (lowerHost.contains(brand) && !registeredDomain.equals(legitimateDomain)) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "BRAND_SUBDOMAIN_SPOOF",
                        String.format("Brand Impersonation in Subdomain: %s", brand.toUpperCase()),
                        String.format("The trusted brand name '%s' appears in the subdomain prefix of non-affiliated domain '%s'.",
                                brand, registeredDomain),
                        "CRITICAL",
                        7.5,
                        lowerHost
                ));
                break;
            }

            // Case 2: Typosquatting / Homoglyph in Domain (e.g., paypa1, micros0ft)
            int dist = levenshtein.apply(brand, registeredName);
            if (dist == 1 || (brand.length() > 6 && dist == 2)) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "BRAND_TYPOSQUATTING",
                        String.format("Typosquatted Brand Domain: %s (Targeting %s)", registeredName, legitimateDomain),
                        String.format("Domain '%s' is an intentional typosquatting variation of '%s'.",
                                lowerHost, legitimateDomain),
                        "CRITICAL",
                        8.0,
                        lowerHost
                ));
                break;
            }

            // Case 3: Brand Phishing Kit in URL Path (e.g., /paypal/login/ or /microsoft-auth/)
            if (lowerPath.contains("/" + brand + "/") || lowerPath.contains("-" + brand + "-") ||
                lowerPath.endsWith("/" + brand) || lowerPath.contains("/" + brand + ".php")) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "BRAND_PATH_PHISHING",
                        String.format("Brand Harvesting Kit in URL Path: %s", brand.toUpperCase()),
                        String.format("Host '%s' hosts a suspicious path mimicking the brand '%s' authentication portal.",
                                lowerHost, brand),
                        "HIGH",
                        6.0,
                        lowerPath
                ));
                break;
            }
        }

        return indicators;
    }
}
