package com.cybershield.service.supabase;

import com.cybershield.model.PhishingKeyword;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SupabaseClientService {
    private static final Logger log = LoggerFactory.getLogger(SupabaseClientService.class);

    @Value("${supabase.url:}")
    private String supabaseUrl;

    @Value("${supabase.key:}")
    private String supabaseKey;

    @Value("${supabase.enabled:false}")
    private boolean supabaseEnabled;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    // In-memory fallback and seed storage
    private final Map<String, PhishingKeyword> inMemoryKeywords = new ConcurrentHashMap<>();

    public SupabaseClientService() {
        initDefaultSeedKeywords();
    }

    private void initDefaultSeedKeywords() {
        List<PhishingKeyword> seeds = List.of(
                // Urgency & Pressure
                new PhishingKeyword("urgent action required", "URGENCY", 4.5),
                new PhishingKeyword("immediate action required", "URGENCY", 4.5),
                new PhishingKeyword("account suspended", "URGENCY", 5.0),
                new PhishingKeyword("account will be locked", "URGENCY", 4.8),
                new PhishingKeyword("within 24 hours", "URGENCY", 3.5),
                new PhishingKeyword("within 48 hours", "URGENCY", 3.2),
                new PhishingKeyword("unauthorized login attempt", "URGENCY", 4.5),
                new PhishingKeyword("security breach detected", "URGENCY", 4.5),
                new PhishingKeyword("act immediately", "URGENCY", 4.0),
                new PhishingKeyword("final notice", "URGENCY", 4.2),
                new PhishingKeyword("limited time offer", "URGENCY", 2.5),
                new PhishingKeyword("failure to comply", "URGENCY", 4.0),

                // Credential Harvesting
                new PhishingKeyword("verify your password", "CREDENTIAL", 5.0),
                new PhishingKeyword("confirm your account", "CREDENTIAL", 4.5),
                new PhishingKeyword("reset your password", "CREDENTIAL", 3.8),
                new PhishingKeyword("update your credentials", "CREDENTIAL", 4.8),
                new PhishingKeyword("enter your pin", "CREDENTIAL", 5.0),
                new PhishingKeyword("social security number", "CREDENTIAL", 5.0),
                new PhishingKeyword("confirm your identity", "CREDENTIAL", 4.5),
                new PhishingKeyword("validate your email", "CREDENTIAL", 3.5),
                new PhishingKeyword("log in here", "CREDENTIAL", 3.0),
                new PhishingKeyword("update payment information", "CREDENTIAL", 4.8),
                new PhishingKeyword("billing information update", "CREDENTIAL", 4.5),

                // Financial Fraud
                new PhishingKeyword("wire transfer", "FINANCIAL", 4.5),
                new PhishingKeyword("cryptocurrency payout", "FINANCIAL", 4.8),
                new PhishingKeyword("bitcoin transaction", "FINANCIAL", 4.2),
                new PhishingKeyword("inheritance fund", "FINANCIAL", 5.0),
                new PhishingKeyword("claim your prize", "FINANCIAL", 4.5),
                new PhishingKeyword("lottery winner", "FINANCIAL", 5.0),
                new PhishingKeyword("tax refund approved", "FINANCIAL", 4.8),
                new PhishingKeyword("unpaid invoice attached", "FINANCIAL", 4.2),
                new PhishingKeyword("compensation fund", "FINANCIAL", 4.5),
                new PhishingKeyword("gift card reward", "FINANCIAL", 4.0),

                // Coercion & Behavioral
                new PhishingKeyword("do not contact support", "THREAT", 4.8),
                new PhishingKeyword("keep this confidential", "THREAT", 4.2),
                new PhishingKeyword("enable macros to view", "THREAT", 5.0),
                new PhishingKeyword("disable your antivirus", "THREAT", 5.0),
                new PhishingKeyword("click the link below", "GENERAL", 2.5),
                new PhishingKeyword("open attached document", "GENERAL", 3.0),
                new PhishingKeyword("suspicious activity detected", "URGENCY", 4.0),
                new PhishingKeyword("session expired", "CREDENTIAL", 3.5)
        );

        for (PhishingKeyword pk : seeds) {
            pk.setId(UUID.randomUUID().toString());
            inMemoryKeywords.put(pk.getKeyword().toLowerCase(), pk);
        }
    }

    public List<PhishingKeyword> fetchKeywords() {
        if (isSupabaseConfigured()) {
            try {
                String endpoint = supabaseUrl.replaceAll("/+$", "") + "/rest/v1/keywords?select=*";
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(endpoint))
                        .header("apikey", supabaseKey)
                        .header("Authorization", "Bearer " + supabaseKey)
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    List<PhishingKeyword> remoteKeywords = objectMapper.readValue(
                            response.body(), new TypeReference<List<PhishingKeyword>>() {});

                    // Merge remote with local memory
                    for (PhishingKeyword kw : remoteKeywords) {
                        kw.setSource("SUPABASE");
                        inMemoryKeywords.put(kw.getKeyword().toLowerCase(), kw);
                    }
                    log.info("Successfully fetched {} keywords from Supabase", remoteKeywords.size());
                    return new ArrayList<>(inMemoryKeywords.values());
                } else {
                    log.warn("Supabase returned status {}: {}. Falling back to cached memory.",
                            response.statusCode(), response.body());
                }
            } catch (Exception e) {
                log.error("Failed to query Supabase REST API: {}. Using in-memory dataset.", e.getMessage());
            }
        }

        return new ArrayList<>(inMemoryKeywords.values());
    }

    public PhishingKeyword addKeyword(PhishingKeyword keyword) {
        if (keyword.getId() == null) {
            keyword.setId(UUID.randomUUID().toString());
        }
        keyword.setKeyword(keyword.getKeyword().trim().toLowerCase());
        inMemoryKeywords.put(keyword.getKeyword(), keyword);

        if (isSupabaseConfigured()) {
            try {
                String endpoint = supabaseUrl.replaceAll("/+$", "") + "/rest/v1/keywords";
                String payload = objectMapper.writeValueAsString(keyword);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(endpoint))
                        .header("apikey", supabaseKey)
                        .header("Authorization", "Bearer " + supabaseKey)
                        .header("Content-Type", "application/json")
                        .header("Prefer", "return=representation")
                        .POST(HttpRequest.BodyPublishers.ofString(payload))
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 201) {
                    keyword.setSource("SUPABASE");
                    log.info("Saved keyword '{}' to Supabase successfully", keyword.getKeyword());
                }
            } catch (Exception e) {
                log.warn("Could not persist keyword to Supabase: {}. Preserved in-memory.", e.getMessage());
            }
        }

        return keyword;
    }

    public boolean isSupabaseConfigured() {
        return supabaseEnabled && supabaseUrl != null && !supabaseUrl.isBlank() &&
                supabaseKey != null && !supabaseKey.isBlank();
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("configured", isSupabaseConfigured());
        status.put("url", isSupabaseConfigured() ? supabaseUrl : "Not Configured (Using In-Memory Database)");
        status.put("totalKeywords", inMemoryKeywords.size());
        status.put("backendMode", isSupabaseConfigured() ? "SUPABASE_POSTGREST" : "IN_MEMORY_CACHE");
        return status;
    }
}
