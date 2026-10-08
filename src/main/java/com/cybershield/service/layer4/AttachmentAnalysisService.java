package com.cybershield.service.layer4;

import com.cybershield.model.AttachmentInfo;
import com.cybershield.model.ThreatIndicator;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class AttachmentAnalysisService {

    private static final Pattern DOUBLE_EXTENSION_PATTERN =
            Pattern.compile(".*\\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|csv)\\.([a-zA-Z0-9]+)$", Pattern.CASE_INSENSITIVE);

    public List<ThreatIndicator> analyzeAttachments(List<AttachmentInfo> attachments) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        if (attachments == null || attachments.isEmpty()) {
            return indicators;
        }

        for (AttachmentInfo attachment : attachments) {
            String filename = attachment.getFilename() != null ? attachment.getFilename().trim() : "";
            if (filename.isEmpty()) continue;

            String lowerName = filename.toLowerCase();
            String extension = extractExtension(lowerName);

            // --- 1. Double Extension Masquerade Detection ---
            Matcher doubleExtMatcher = DOUBLE_EXTENSION_PATTERN.matcher(lowerName);
            if (doubleExtMatcher.find()) {
                String disguisedAs = doubleExtMatcher.group(1);
                String actualExt = doubleExtMatcher.group(2);

                indicators.add(new ThreatIndicator(
                        "Layer 4",
                        "DOUBLE_EXTENSION_ATTACK",
                        String.format("Double Extension Deception: .%s.%s", disguisedAs, actualExt),
                        String.format("Attachment '%s' masquerades as benign .%s format while retaining executable .%s payload.",
                                filename, disguisedAs, actualExt),
                        "CRITICAL",
                        9.5,
                        filename
                ));
            }

            // --- 2. Dangerous Standalone Executable Extensions ---
            if (FileTypeRiskRegistry.HIGH_RISK_EXECUTABLES.contains(extension)) {
                indicators.add(new ThreatIndicator(
                        "Layer 4",
                        "EXECUTABLE_ATTACHMENT",
                        String.format("High-Risk Executable Payload: .%s", extension),
                        String.format("File '%s' is an executable or script type directly associated with malware delivery.", filename),
                        "CRITICAL",
                        9.0,
                        filename
                ));
            }

            // --- 3. Container Disk Image Payloads (.iso, .img, .vhd) ---
            if (FileTypeRiskRegistry.CONTAINER_DISK_IMAGES.contains(extension)) {
                indicators.add(new ThreatIndicator(
                        "Layer 4",
                        "CONTAINER_IMAGE_PAYLOAD",
                        String.format("Container Image Attachment: .%s", extension),
                        String.format("File '%s' uses a virtual disk format commonly leveraged to bypass Mark-of-the-Web (MOTW) security controls.", filename),
                        "HIGH",
                        7.5,
                        filename
                ));
            }

            // --- 4. Macro-Enabled Document Formats (.docm, .xlsm, .pptm) ---
            if (FileTypeRiskRegistry.MACRO_ENABLED_DOCUMENTS.contains(extension)) {
                indicators.add(new ThreatIndicator(
                        "Layer 4",
                        "MACRO_DOCUMENT",
                        String.format("Macro-Enabled Office Document: .%s", extension),
                        String.format("Document '%s' contains embedded Visual Basic for Applications (VBA) macro capabilities.", filename),
                        "HIGH",
                        7.0,
                        filename
                ));
            }

            // --- 5. Archive with Financial / Lure Keywords ---
            if (FileTypeRiskRegistry.ARCHIVE_EXTENSIONS.contains(extension)) {
                boolean hasLure = FileTypeRiskRegistry.FINANCIAL_LURE_KEYWORDS.stream().anyMatch(lowerName::contains);
                if (hasLure) {
                    indicators.add(new ThreatIndicator(
                            "Layer 4",
                            "SUSPICIOUS_ARCHIVE_LURE",
                            "Compressed Archive with Financial Lure Name",
                            String.format("Archive '%s' pairs archive compression with financial lure naming to conceal malicious contents.", filename),
                            "MEDIUM",
                            5.0,
                            filename
                    ));
                }
            }

            // --- 6. MIME Type Inconsistency / Discrepancy ---
            String reportedMime = attachment.getContentType() != null ? attachment.getContentType().toLowerCase().trim() : "";
            if (!reportedMime.isEmpty() && reportedMime.contains("dosexec") && !extension.equals("exe")) {
                indicators.add(new ThreatIndicator(
                        "Layer 4",
                        "MIME_EXTENSION_MISMATCH",
                        "Binary Executable MIME Type Mismatch",
                        String.format("Attachment '%s' claims to be .%s but exhibits an executable (PE/MZ) MIME profile: %s.",
                                filename, extension, reportedMime),
                        "CRITICAL",
                        8.5,
                        String.format("Reported: %s, Extension: .%s", reportedMime, extension)
                ));
            }

            // --- 7. Zero-Byte or Suspicious File Size Anomaly ---
            if (attachment.getSizeBytes() > 0 && attachment.getSizeBytes() < 100 &&
                    (extension.equals("exe") || extension.equals("bat") || extension.equals("vbs"))) {
                indicators.add(new ThreatIndicator(
                        "Layer 4",
                        "STAGER_FILE_ANOMALY",
                        "Suspiciously Small Dropper / Stager Binary",
                        String.format("Attachment '%s' has an anomalously small size (%d bytes), indicative of download stagers.",
                                filename, attachment.getSizeBytes()),
                        "HIGH",
                        5.5,
                        attachment.getSizeBytes() + " bytes"
                ));
            }
        }

        return indicators;
    }

    private String extractExtension(String filename) {
        int dotIdx = filename.lastIndexOf('.');
        if (dotIdx >= 0 && dotIdx < filename.length() - 1) {
            return filename.substring(dotIdx + 1);
        }
        return "";
    }
}
