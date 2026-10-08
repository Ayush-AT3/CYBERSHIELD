package com.cybershield.model;

public class UrlScanRequest {
    private String url;
    private boolean forceVirusTotal;

    public UrlScanRequest() {}

    public UrlScanRequest(String url) {
        this.url = url;
    }

    public UrlScanRequest(String url, boolean forceVirusTotal) {
        this.url = url;
        this.forceVirusTotal = forceVirusTotal;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isForceVirusTotal() {
        return forceVirusTotal;
    }

    public void setForceVirusTotal(boolean forceVirusTotal) {
        this.forceVirusTotal = forceVirusTotal;
    }
}
