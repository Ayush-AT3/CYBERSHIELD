package com.cybershield.model;

public class ThreatIndicator {
    private String layer;
    private String type;
    private String title;
    private String description;
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL
    private double scoreContribution;
    private String evidence;

    public ThreatIndicator() {}

    public ThreatIndicator(String layer, String type, String title, String description,
                           String severity, double scoreContribution, String evidence) {
        this.layer = layer;
        this.type = type;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.scoreContribution = scoreContribution;
        this.evidence = evidence;
    }

    public String getLayer() {
        return layer;
    }

    public void setLayer(String layer) {
        this.layer = layer;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public double getScoreContribution() {
        return scoreContribution;
    }

    public void setScoreContribution(double scoreContribution) {
        this.scoreContribution = scoreContribution;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }
}
