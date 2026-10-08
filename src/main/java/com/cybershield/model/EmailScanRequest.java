package com.cybershield.model;

import java.util.ArrayList;
import java.util.List;

public class EmailScanRequest {
    private String sender;
    private String subject;
    private String body;
    private List<String> urls = new ArrayList<>();
    private List<AttachmentInfo> attachments = new ArrayList<>();
    private boolean triggerVirusTotal;

    public EmailScanRequest() {}

    public EmailScanRequest(String sender, String subject, String body) {
        this.sender = sender;
        this.subject = subject;
        this.body = body;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public List<String> getUrls() {
        return urls;
    }

    public void setUrls(List<String> urls) {
        this.urls = urls != null ? urls : new ArrayList<>();
    }

    public List<AttachmentInfo> getAttachments() {
        return attachments;
    }

    public void setAttachments(List<AttachmentInfo> attachments) {
        this.attachments = attachments != null ? attachments : new ArrayList<>();
    }

    public boolean isTriggerVirusTotal() {
        return triggerVirusTotal;
    }

    public void setTriggerVirusTotal(boolean triggerVirusTotal) {
        this.triggerVirusTotal = triggerVirusTotal;
    }
}
