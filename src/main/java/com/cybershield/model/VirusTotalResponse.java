package com.cybershield.model;

public class VirusTotalResponse {
    private String url;
    private int maliciousCount;
    private int suspiciousCount;
    private int harmlessCount;
    private int undetectedCount;
    private int totalEngines;
    private String scanDate;
    private int reputationScore;
    private boolean cached;
    private String permalink;
    private String analysisSummary;

    public VirusTotalResponse() {}

    public VirusTotalResponse(String url, int maliciousCount, int suspiciousCount, int harmlessCount, int undetectedCount) {
        this.url = url;
        this.maliciousCount = maliciousCount;
        this.suspiciousCount = suspiciousCount;
        this.harmlessCount = harmlessCount;
        this.undetectedCount = undetectedCount;
        this.totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount;
        this.analysisSummary = String.format("%d security vendors flagged this URL as malicious (out of %d)",
                maliciousCount, this.totalEngines);
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getMaliciousCount() {
        return maliciousCount;
    }

    public void setMaliciousCount(int maliciousCount) {
        this.maliciousCount = maliciousCount;
    }

    public int getSuspiciousCount() {
        return suspiciousCount;
    }

    public void setSuspiciousCount(int suspiciousCount) {
        this.suspiciousCount = suspiciousCount;
    }

    public int getHarmlessCount() {
        return harmlessCount;
    }

    public void setHarmlessCount(int harmlessCount) {
        this.harmlessCount = harmlessCount;
    }

    public int getUndetectedCount() {
        return undetectedCount;
    }

    public void setUndetectedCount(int undetectedCount) {
        this.undetectedCount = undetectedCount;
    }

    public int getTotalEngines() {
        return totalEngines;
    }

    public void setTotalEngines(int totalEngines) {
        this.totalEngines = totalEngines;
    }

    public String getScanDate() {
        return scanDate;
    }

    public void setScanDate(String scanDate) {
        this.scanDate = scanDate;
    }

    public int getReputationScore() {
        return reputationScore;
    }

    public void setReputationScore(int reputationScore) {
        this.reputationScore = reputationScore;
    }

    public boolean isCached() {
        return cached;
    }

    public void setCached(boolean cached) {
        this.cached = cached;
    }

    public String getPermalink() {
        return permalink;
    }

    public void setPermalink(String permalink) {
        this.permalink = permalink;
    }

    public String getAnalysisSummary() {
        return analysisSummary;
    }

    public void setAnalysisSummary(String analysisSummary) {
        this.analysisSummary = analysisSummary;
    }
}
