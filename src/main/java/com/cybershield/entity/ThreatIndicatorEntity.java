package com.cybershield.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "threat_indicators")
public class ThreatIndicatorEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 50)
    private String layer;

    @Column(length = 100)
    private String type;

    @Column(length = 255)
    private String title;

    @Column(length = 3000)
    private String description;

    @Column(length = 20)
    private String severity;

    private double scoreContribution;

    @Column(length = 3000)
    private String evidence;

    public ThreatIndicatorEntity() {
    }

    public ThreatIndicatorEntity(String layer, String type, String title, String description,
                                 String severity, double scoreContribution, String evidence) {
        this.layer = layer;
        this.type = type;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.scoreContribution = scoreContribution;
        this.evidence = evidence;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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
