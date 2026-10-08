package com.cybershield.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "keywords", indexes = {
        @Index(name = "idx_keywords_category", columnList = "category"),
        @Index(name = "idx_keywords_keyword", columnList = "keyword")
})
public class KeywordEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String keyword;

    @Column(nullable = false, length = 50)
    private String category;

    @Column(nullable = false)
    private double weight;

    @Column(length = 50)
    private String source;

    private Instant createdAt = Instant.now();

    public KeywordEntity() {
    }

    public KeywordEntity(String keyword, String category, double weight, String source) {
        this.keyword = keyword;
        this.category = category;
        this.weight = weight;
        this.source = source != null ? source : "H2_DATABASE";
        this.createdAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
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
}
