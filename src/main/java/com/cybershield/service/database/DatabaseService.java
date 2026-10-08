package com.cybershield.service.database;

import com.cybershield.entity.KeywordEntity;
import com.cybershield.entity.ScanRecordEntity;
import com.cybershield.entity.ThreatIndicatorEntity;
import com.cybershield.model.LayerResult;
import com.cybershield.model.PhishingKeyword;
import com.cybershield.model.ScanResult;
import com.cybershield.model.ThreatIndicator;
import com.cybershield.repository.KeywordRepository;
import com.cybershield.repository.ScanRecordRepository;
import com.cybershield.service.supabase.SupabaseClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class DatabaseService implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DatabaseService.class);

    private final KeywordRepository keywordRepository;
    private final ScanRecordRepository scanRecordRepository;
    private final SupabaseClientService supabaseClientService;

    public DatabaseService(KeywordRepository keywordRepository,
                           ScanRecordRepository scanRecordRepository,
                           SupabaseClientService supabaseClientService) {
        this.keywordRepository = keywordRepository;
        this.scanRecordRepository = scanRecordRepository;
        this.supabaseClientService = supabaseClientService;
    }

    @Override
    public void run(String... args) {
        seedInitialKeywords();
    }

    /**
     * Seeds default keywords into H2 database on application startup if table is empty.
     */
    @Transactional
    public void seedInitialKeywords() {
        try {
            long count = keywordRepository.count();
            if (count == 0) {
                log.info("H2 Database KEYWORDS table is empty. Seeding with 41 security keywords...");
                List<PhishingKeyword> seedKeywords = supabaseClientService.fetchKeywords();
                List<KeywordEntity> entities = new ArrayList<>();

                for (PhishingKeyword pk : seedKeywords) {
                    KeywordEntity entity = new KeywordEntity(
                            pk.getKeyword(),
                            pk.getCategory(),
                            pk.getWeight(),
                            "SEED_H2"
                    );
                    entities.add(entity);
                }

                keywordRepository.saveAll(entities);
                log.info("Successfully seeded {} keywords into H2 Database table 'KEYWORDS'.", entities.size());
            } else {
                log.info("H2 Database KEYWORDS table already contains {} records.", count);
            }
        } catch (Exception e) {
            log.error("Failed to seed keywords into H2 database: {}", e.getMessage(), e);
        }
    }

    /**
     * Saves a completed ScanResult into H2 Database.
     */
    @Transactional
    public ScanRecordEntity saveScanResult(ScanResult result) {
        if (result == null) {
            return null;
        }

        try {
            ScanRecordEntity record = new ScanRecordEntity();
            record.setScanId(result.getScanId());
            record.setScanType(result.getScanType());
            record.setInputTarget(result.getInputTarget());
            record.setSender(result.getSender());
            record.setSubject(result.getSubject());
            record.setOverallRiskScore(result.getOverallRiskScore());
            record.setClassification(result.getClassification() != null ? result.getClassification().name() : "SAFE");
            record.setSummary(result.getSummary());
            record.setTotalExecutionTimeMs(result.getTotalExecutionTimeMs());
            record.setCreatedAt(result.getTimestamp() != null ? result.getTimestamp() : Instant.now());

            // Extract all threat indicators from all layers
            if (result.getLayerResults() != null) {
                for (LayerResult lr : result.getLayerResults()) {
                    if (lr.getIndicators() != null) {
                        for (ThreatIndicator ti : lr.getIndicators()) {
                            ThreatIndicatorEntity tie = new ThreatIndicatorEntity(
                                    ti.getLayer(),
                                    ti.getType(),
                                    ti.getTitle(),
                                    ti.getDescription(),
                                    ti.getSeverity() != null ? ti.getSeverity() : "LOW",
                                    ti.getScoreContribution(),
                                    ti.getEvidence()
                            );
                            record.addIndicator(tie);
                        }
                    }
                }
            }

            ScanRecordEntity saved = scanRecordRepository.save(record);
            log.info("Saved scan to H2 database: id={}, target={}, score={}, verdict={}",
                    saved.getId(), saved.getInputTarget(), saved.getOverallRiskScore(), saved.getClassification());
            return saved;
        } catch (Exception e) {
            log.error("Error saving scan result to H2 database: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Retrieves recent scans from H2 database.
     */
    @Transactional(readOnly = true)
    public List<ScanRecordEntity> getRecentScans() {
        return scanRecordRepository.findTop20ByOrderByCreatedAtDesc();
    }

    /**
     * Retrieves all keywords from H2 database.
     */
    @Transactional(readOnly = true)
    public List<KeywordEntity> getAllKeywords() {
        return keywordRepository.findAll();
    }

    /**
     * Total scan counts.
     */
    public long getTotalScanCount() {
        return scanRecordRepository.count();
    }
}
