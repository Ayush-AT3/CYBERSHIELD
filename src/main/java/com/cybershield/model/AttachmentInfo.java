package com.cybershield.model;

public class AttachmentInfo {
    private String filename;
    private long sizeBytes;
    private String contentType;
    private String sha256Hash;

    public AttachmentInfo() {}

    public AttachmentInfo(String filename, long sizeBytes, String contentType) {
        this.filename = filename;
        this.sizeBytes = sizeBytes;
        this.contentType = contentType;
    }

    public AttachmentInfo(String filename, long sizeBytes, String contentType, String sha256Hash) {
        this.filename = filename;
        this.sizeBytes = sizeBytes;
        this.contentType = contentType;
        this.sha256Hash = sha256Hash;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public void setSizeBytes(long sizeBytes) {
        this.sizeBytes = sizeBytes;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public void setSha256Hash(String sha256Hash) {
        this.sha256Hash = sha256Hash;
    }
}
