package com.cybershield.model;

import java.util.ArrayList;
import java.util.List;

public class LayerResult {
    private int layerNumber;
    private String layerName;
    private double score;
    private List<ThreatIndicator> indicators = new ArrayList<>();
    private String summary;
    private long executionTimeMs;

    public LayerResult() {}

    public LayerResult(int layerNumber, String layerName) {
        this.layerNumber = layerNumber;
        this.layerName = layerName;
    }

    public void addIndicator(ThreatIndicator indicator) {
        if (indicator != null) {
            indicators.add(indicator);
            this.score += indicator.getScoreContribution();
        }
    }

    public int getLayerNumber() {
        return layerNumber;
    }

    public void setLayerNumber(int layerNumber) {
        this.layerNumber = layerNumber;
    }

    public String getLayerName() {
        return layerName;
    }

    public void setLayerName(String layerName) {
        this.layerName = layerName;
    }

    public double getScore() {
        return score;
    }

    public void setScore(double score) {
        this.score = score;
    }

    public List<ThreatIndicator> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<ThreatIndicator> indicators) {
        this.indicators = indicators;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public long getExecutionTimeMs() {
        return executionTimeMs;
    }

    public void setExecutionTimeMs(long executionTimeMs) {
        this.executionTimeMs = executionTimeMs;
    }
}
