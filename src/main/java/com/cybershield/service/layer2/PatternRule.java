package com.cybershield.service.layer2;

import java.util.regex.Pattern;

public class PatternRule {
    private final String id;
    private final String name;
    private final String category; // URGENCY, CREDENTIAL_REQUEST, FINANCIAL_FRAUD, BEHAVIORAL
    private final Pattern pattern;
    private final double weight;
    private final String severity; // LOW, MEDIUM, HIGH, CRITICAL
    private final String description;

    public PatternRule(String id, String name, String category, String regex, double weight, String severity, String description) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
        this.weight = weight;
        this.severity = severity;
        this.description = description;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getCategory() {
        return category;
    }

    public Pattern getPattern() {
        return pattern;
    }

    public double getWeight() {
        return weight;
    }

    public String getSeverity() {
        return severity;
    }

    public String getDescription() {
        return description;
    }
}
