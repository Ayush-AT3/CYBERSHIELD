package com.cybershield.model;

public enum RiskClassification {
    SAFE("Safe", "Normal communication with no critical phishing indicators detected.", "#10b981", "badge-safe"),
    SUSPICIOUS("Suspicious", "Multiple warning indicators present. Exercise caution before clicking links or downloading attachments.", "#f59e0b", "badge-suspicious"),
    DANGEROUS("Dangerous", "High-probability phishing attempt or malicious payload detected. Do not interact.", "#ef4444", "badge-dangerous");

    private final String label;
    private final String description;
    private final String colorHex;
    private final String cssClass;

    RiskClassification(String label, String description, String colorHex, String cssClass) {
        this.label = label;
        this.description = description;
        this.colorHex = colorHex;
        this.cssClass = cssClass;
    }

    public static RiskClassification fromScore(double score) {
        if (score < 5.0) {
            return SAFE;
        } else if (score < 10.0) {
            return SUSPICIOUS;
        } else {
            return DANGEROUS;
        }
    }

    public String getLabel() {
        return label;
    }

    public String getDescription() {
        return description;
    }

    public String getColorHex() {
        return colorHex;
    }

    public String getCssClass() {
        return cssClass;
    }
}
