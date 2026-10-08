package com.cybershield.service.layer1;

import com.cybershield.model.PhishingKeyword;
import com.cybershield.model.ThreatIndicator;
import com.cybershield.service.cache.CacheService;
import com.cybershield.service.supabase.SupabaseClientService;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class KeywordDetectionService {

    private static final String TRIE_CACHE_KEY = "CYBERSHIELD_AHO_CORASICK_TRIE";
    private final SupabaseClientService supabaseService;
    private final CacheService cacheService;

    public KeywordDetectionService(SupabaseClientService supabaseService, CacheService cacheService) {
        this.supabaseService = supabaseService;
        this.cacheService = cacheService;
    }

    public synchronized AhoCorasickEngine getOrBuildEngine() {
        AhoCorasickEngine cachedEngine = cacheService.getCachedTrie(TRIE_CACHE_KEY);
        if (cachedEngine != null) {
            return cachedEngine;
        }

        List<PhishingKeyword> keywords = supabaseService.fetchKeywords();
        AhoCorasickEngine engine = new AhoCorasickEngine();
        engine.buildTrie(keywords);
        cacheService.cacheTrie(TRIE_CACHE_KEY, engine);
        return engine;
    }

    public void reloadKeywords() {
        cacheService.invalidateTrieCache();
        getOrBuildEngine();
    }

    public List<ThreatIndicator> detectKeywords(String text, String sourceField) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        if (text == null || text.trim().isEmpty()) {
            return indicators;
        }

        AhoCorasickEngine engine = getOrBuildEngine();
        List<AhoCorasickEngine.Match> matches = engine.search(text);

        // Group matches by keyword to avoid duplicate indicators and calculate frequency
        Map<String, List<AhoCorasickEngine.Match>> groupedMatches = new LinkedHashMap<>();
        for (AhoCorasickEngine.Match match : matches) {
            String kwKey = match.getKeyword().getKeyword().toLowerCase();
            groupedMatches.computeIfAbsent(kwKey, k -> new ArrayList<>()).add(match);
        }

        for (Map.Entry<String, List<AhoCorasickEngine.Match>> entry : groupedMatches.entrySet()) {
            List<AhoCorasickEngine.Match> matchList = entry.getValue();
            PhishingKeyword kw = matchList.get(0).getKeyword();
            int count = matchList.size();

            // Calculate score with frequency decay
            double baseWeight = kw.getWeight();
            double finalScore = baseWeight + (count > 1 ? Math.min(2.0, (count - 1) * 0.5) : 0.0);

            String severity = finalScore >= 4.5 ? "CRITICAL" : (finalScore >= 3.5 ? "HIGH" : "MEDIUM");

            indicators.add(new ThreatIndicator(
                    "Layer 1",
                    "AHO_CORASICK_KEYWORD",
                    String.format("Phishing Keyword Match: \"%s\" (x%d)", kw.getKeyword(), count),
                    String.format("Matched high-confidence phishing keyword categorized under [%s] in %s.",
                            kw.getCategory(), sourceField),
                    severity,
                    finalScore,
                    String.format("\"%s\" detected %d time(s)", kw.getKeyword(), count)
            ));
        }

        return indicators;
    }
}
