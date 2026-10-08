package com.cybershield.service.layer3;

import com.cybershield.model.ThreatIndicator;
import com.cybershield.model.VirusTotalResponse;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class HeuristicUrlAnalysisService {

    private static final Pattern IPV4_PATTERN = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?$");
    private static final Pattern URL_EXTRACTOR = Pattern.compile("(?i)\\b((?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’]))");

    private static final Set<String> RISKY_TLDS = Set.of(
            "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "work",
            "click", "zip", "mov", "icu", "monster", "country", "live", "stream", "cam"
    );

    private final ShannonEntropyCalculator entropyCalculator;
    private final BrandImpersonationDetector brandDetector;
    private final VirusTotalIntegrationService virusTotalService;

    public HeuristicUrlAnalysisService(ShannonEntropyCalculator entropyCalculator,
                                      BrandImpersonationDetector brandDetector,
                                      VirusTotalIntegrationService virusTotalService) {
        this.entropyCalculator = entropyCalculator;
        this.brandDetector = brandDetector;
        this.virusTotalService = virusTotalService;
    }

    public List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        if (text == null || text.isEmpty()) return urls;

        Matcher matcher = URL_EXTRACTOR.matcher(text);
        while (matcher.find()) {
            String url = matcher.group(1);
            if (!urls.contains(url)) {
                urls.add(url);
            }
        }
        return urls;
    }

    public List<ThreatIndicator> analyzeUrl(String rawUrl, boolean forceVirusTotal) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return indicators;
        }

        String urlString = rawUrl.trim();
        if (!urlString.startsWith("http://") && !urlString.startsWith("https://")) {
            urlString = "http://" + urlString;
        }

        try {
            URI uri = URI.create(urlString);
            String host = uri.getHost();
            String path = uri.getPath();
            int port = uri.getPort();

            if (host == null) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "INVALID_URL_SYNTAX",
                        "Malformed URL Hostname",
                        "The URL structure could not be parsed into a valid network hostname.",
                        "MEDIUM",
                        3.0,
                        rawUrl
                ));
                return indicators;
            }

            // --- 1. IP-Based URL Check ---
            if (IPV4_PATTERN.matcher(host).matches()) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "IP_BASED_URL",
                        "Dotted-Decimal IP Address URL",
                        String.format("The destination '%s' uses a direct numerical IP address instead of a domain name.", host),
                        "CRITICAL",
                        7.5,
                        host
                ));
            }

            // --- 2. Shannon Entropy of Host & Path ---
            double hostEntropy = entropyCalculator.calculateEntropy(host);
            if (hostEntropy >= 3.85 && !IPV4_PATTERN.matcher(host).matches()) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "HIGH_ENTROPY_HOST",
                        String.format("High Hostname Shannon Entropy (%.2f bits)", hostEntropy),
                        "High character unpredictability indicates algorithmic domain generation (DGA) or anti-filtering evasion.",
                        "HIGH",
                        4.5,
                        String.format("Entropy: %.2f on host '%s'", hostEntropy, host)
                ));
            }

            // --- 3. URL Structure: UserInfo / '@' Symbol Trick ---
            if (rawUrl.contains("@")) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "USERINFO_SPOOFING",
                        "UserInfo '@' Symbol Domain Concealment",
                        "The URL uses '@' to mislead victims by prepending a legitimate brand before the actual malicious host.",
                        "CRITICAL",
                        8.5,
                        rawUrl
                ));
            }

            // --- 4. Subdomain Depth ---
            String[] hostSegments = host.split("\\.");
            if (hostSegments.length > 4) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "EXCESSIVE_SUBDOMAINS",
                        String.format("Excessive Subdomain Depth (%d Levels)", hostSegments.length),
                        "Phishing kits frequently employ deep nested subdomains to impersonate legitimate brand hierarchies.",
                        "MEDIUM",
                        3.5,
                        host
                ));
            }

            // --- 5. URL Length Anomaly ---
            if (rawUrl.length() > 95) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "EXCESSIVE_URL_LENGTH",
                        String.format("Suspicious URL Length (%d Chars)", rawUrl.length()),
                        "Unusually long URLs are frequently used to conceal target parameters and bypass simple filters.",
                        "LOW",
                        2.5,
                        String.format("Length: %d characters", rawUrl.length())
                ));
            }

            // --- 6. Risky / Abusive Top-Level Domain (TLD) ---
            String tld = hostSegments.length > 0 ? hostSegments[hostSegments.length - 1].toLowerCase() : "";
            if (RISKY_TLDS.contains(tld)) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "ABUSIVE_TLD",
                        String.format("High-Risk / Abusive Top-Level Domain: .%s", tld),
                        String.format("The .%s TLD exhibits disproportionately high frequencies of spam, malware, and credential theft.", tld),
                        "HIGH",
                        4.5,
                        "." + tld
                ));
            }

            // --- 7. Non-standard Web Port ---
            if (port != -1 && port != 80 && port != 443 && port != 8080) {
                indicators.add(new ThreatIndicator(
                        "Layer 3",
                        "SUSPICIOUS_PORT",
                        String.format("Non-Standard Web Port: %d", port),
                        "Web links running on atypical service ports are characteristic of compromised consumer devices and short-lived proxies.",
                        "HIGH",
                        4.0,
                        "Port " + port
                ));
            }

            // --- 8. Brand Impersonation & Typosquatting in URL ---
            indicators.addAll(brandDetector.detectImpersonation(rawUrl, host, path));

            // --- 9. Conditional VirusTotal API Threat Intelligence ---
            double currentLayerScore = indicators.stream().mapToDouble(ThreatIndicator::getScoreContribution).sum();
            boolean shouldQueryVt = forceVirusTotal || virusTotalService.isThresholdExceeded(currentLayerScore);

            if (shouldQueryVt) {
                VirusTotalResponse vtResponse = virusTotalService.scanUrl(urlString);
                virusTotalService.createIndicatorFromVt(vtResponse).ifPresent(indicators::add);
            }

        } catch (Exception e) {
            indicators.add(new ThreatIndicator(
                    "Layer 3",
                    "URL_PARSE_ERROR",
                    "Error Parsing Target URL",
                    e.getMessage(),
                    "LOW",
                    1.0,
                    rawUrl
            ));
        }

        return indicators;
    }
}
