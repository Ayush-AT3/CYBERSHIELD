package com.cybershield.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scans", indexes = {
        @Index(name = "idx_scans_created_at", columnList = "createdAt"),
        @Index(name = "idx_scans_classification", columnList = "classification")
})
public class ScanRecordEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String scanId;

    @Column(nullable = false, length = 20)
    private String scanType; // EMAIL, URL

    @Column(length = 2000)
    private String inputTarget;

    @Column(length = 500)
    private String sender;

    @Column(length = 1000)
    private String subject;

    private double overallRiskScore;

    @Column(length = 20)
    private String classification; // SAFE, SUSPICIOUS, DANGEROUS

    @Column(length = 3000)
    private String summary;

    private long totalExecutionTimeMs;

    private Instant createdAt = Instant.now();

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, orphanRemoval = true)
    @JoinColumn(name = "scan_record_id")
    private List<ThreatIndicatorEntity> indicators = new ArrayList<>();

    public ScanRecordEntity() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getScanId() {
        return scanId;
    }

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    public String getScanType() {
        return scanType;
    }

    public void setScanType(String scanType) {
        this.scanType = scanType;
    }

    public String getInputTarget() {
        return inputTarget;
    }

    public void setInputTarget(String inputTarget) {
        this.inputTarget = inputTarget;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public double getOverallRiskScore() {
        return overallRiskScore;
    }

    public void setOverallRiskScore(double overallRiskScore) {
        this.overallRiskScore = overallRiskScore;
    }

    public String getClassification() {
        return classification;
    }

    public void setClassification(String classification) {
        this.classification = classification;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public long getTotalExecutionTimeMs() {
        return totalExecutionTimeMs;
    }

    public void setTotalExecutionTimeMs(long totalExecutionTimeMs) {
        this.totalExecutionTimeMs = totalExecutionTimeMs;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public List<ThreatIndicatorEntity> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<ThreatIndicatorEntity> indicators) {
        this.indicators = indicators;
    }

    public void addIndicator(ThreatIndicatorEntity indicator) {
        if (this.indicators == null) {
            this.indicators = new ArrayList<>();
        }
        this.indicators.add(indicator);
    }
}
