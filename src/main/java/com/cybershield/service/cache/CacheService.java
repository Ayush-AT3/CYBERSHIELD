package com.cybershield.service.cache;

import com.cybershield.model.ScanResult;
import com.cybershield.model.VirusTotalResponse;
import com.cybershield.service.layer1.AhoCorasickEngine;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.TimeUnit;

@Service
public class CacheService {

    // Cache for compiled Aho-Corasick Trie (avoids rebuilding on every scan)
    private final Cache<String, AhoCorasickEngine> trieCache = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .maximumSize(10)
            .build();

    // Cache for VirusTotal API lookups (prevents repeated external API hits, 24h TTL)
    private final Cache<String, VirusTotalResponse> virusTotalCache = Caffeine.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .maximumSize(1000)
            .build();

    // Cache for domain lookups / reputations
    private final Cache<String, Object> domainReputationCache = Caffeine.newBuilder()
            .expireAfterWrite(12, TimeUnit.HOURS)
            .maximumSize(5000)
            .build();

    // In-memory circular buffer for recent scans (for dashboard analytics)
    private final Deque<ScanResult> recentScans = new ConcurrentLinkedDeque<>();
    private static final int MAX_RECENT_SCANS = 100;

    public void cacheTrie(String key, AhoCorasickEngine engine) {
        trieCache.put(key, engine);
    }

    public AhoCorasickEngine getCachedTrie(String key) {
        return trieCache.getIfPresent(key);
    }

    public void invalidateTrieCache() {
        trieCache.invalidateAll();
    }

    public void cacheVirusTotal(String url, VirusTotalResponse response) {
        if (url != null && response != null) {
            virusTotalCache.put(url.trim().toLowerCase(), response);
        }
    }

    public VirusTotalResponse getCachedVirusTotal(String url) {
        if (url == null) return null;
        return virusTotalCache.getIfPresent(url.trim().toLowerCase());
    }

    public void recordScan(ScanResult scanResult) {
        if (scanResult == null) return;
        recentScans.addFirst(scanResult);
        while (recentScans.size() > MAX_RECENT_SCANS) {
            recentScans.pollLast();
        }
    }

    public List<ScanResult> getRecentScans() {
        return new ArrayList<>(recentScans);
    }

    public Optional<ScanResult> getScanById(String scanId) {
        return recentScans.stream()
                .filter(s -> s.getScanId().equalsIgnoreCase(scanId))
                .findFirst();
    }

    public Map<String, Object> getCacheStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("virusTotalCacheEntries", virusTotalCache.estimatedSize());
        stats.put("recentScansCount", recentScans.size());
        stats.put("trieCached", trieCache.estimatedSize() > 0);
        return stats;
    }
}
