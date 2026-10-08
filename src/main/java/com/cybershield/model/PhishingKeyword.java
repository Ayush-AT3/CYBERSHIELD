package com.cybershield.model;

import java.time.Instant;
import java.util.Objects;

public class PhishingKeyword {
    private String id;
    private String keyword;
    private String category;
    private double weight;
    private String source;
    private Instant createdAt;

    public PhishingKeyword() {
        this.createdAt = Instant.now();
    }

    public PhishingKeyword(String keyword, String category, double weight) {
        this(keyword, category, weight, "BUILTIN");
    }

    public PhishingKeyword(String keyword, String category, double weight, String source) {
        this.keyword = keyword;
        this.category = category;
        this.weight = weight;
        this.source = source;
        this.createdAt = Instant.now();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public double getWeight() {
        return weight;
    }

    public void setWeight(double weight) {
        this.weight = weight;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PhishingKeyword that)) return false;
        return Objects.equals(keyword != null ? keyword.toLowerCase() : null,
                that.keyword != null ? that.keyword.toLowerCase() : null);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyword != null ? keyword.toLowerCase() : null);
    }
}
