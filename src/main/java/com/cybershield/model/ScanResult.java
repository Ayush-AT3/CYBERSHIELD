package com.cybershield.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ScanResult {
    private String scanId;
    private String scanType; // EMAIL, URL
    private String inputTarget;
    private String sender;
    private String subject;
    private double overallRiskScore;
    private RiskClassification classification;
    private List<LayerResult> layerResults = new ArrayList<>();
    private String summary;
    private List<String> recommendations = new ArrayList<>();
    private Instant timestamp;
    private long totalExecutionTimeMs;

    public ScanResult() {
        this.scanId = UUID.randomUUID().toString();
        this.timestamp = Instant.now();
    }

    public void addLayerResult(LayerResult layerResult) {
        if (layerResult != null) {
            this.layerResults.add(layerResult);
        }
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

    public RiskClassification getClassification() {
        return classification;
    }

    public void setClassification(RiskClassification classification) {
        this.classification = classification;
    }

    public List<LayerResult> getLayerResults() {
        return layerResults;
    }

    public void setLayerResults(List<LayerResult> layerResults) {
        this.layerResults = layerResults;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<String> getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(List<String> recommendations) {
        this.recommendations = recommendations;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public long getTotalExecutionTimeMs() {
        return totalExecutionTimeMs;
    }

    public void setTotalExecutionTimeMs(long totalExecutionTimeMs) {
        this.totalExecutionTimeMs = totalExecutionTimeMs;
    }
}
