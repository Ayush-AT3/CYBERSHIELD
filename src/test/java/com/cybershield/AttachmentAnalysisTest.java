package com.cybershield;

import com.cybershield.model.AttachmentInfo;
import com.cybershield.model.ThreatIndicator;
import com.cybershield.service.layer4.AttachmentAnalysisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AttachmentAnalysisTest {

    private AttachmentAnalysisService attachmentService;

    @BeforeEach
    public void setUp() {
        attachmentService = new AttachmentAnalysisService();
    }

    @Test
    public void testDoubleExtensionAttackDetection() {
        AttachmentInfo attachment = new AttachmentInfo("Invoice_Q3.pdf.exe", 45000, "application/octet-stream");
        List<ThreatIndicator> indicators = attachmentService.analyzeAttachments(List.of(attachment));

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("DOUBLE_EXTENSION_ATTACK")));
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("EXECUTABLE_ATTACHMENT")));
    }

    @Test
    public void testContainerDiskImagePayload() {
        AttachmentInfo attachment = new AttachmentInfo("Payment_Confirmation.iso", 1200000, "application/x-iso9660-image");
        List<ThreatIndicator> indicators = attachmentService.analyzeAttachments(List.of(attachment));

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("CONTAINER_IMAGE_PAYLOAD")));
    }

    @Test
    public void testMacroEnabledOfficeDocument() {
        AttachmentInfo attachment = new AttachmentInfo("Salary_Report.xlsm", 85000, "application/vnd.ms-excel.sheet.macroEnabled.12");
        List<ThreatIndicator> indicators = attachmentService.analyzeAttachments(List.of(attachment));

        assertFalse(indicators.isEmpty());
        assertTrue(indicators.stream().anyMatch(i -> i.getType().equals("MACRO_DOCUMENT")));
    }

    @Test
    public void testBenignAttachmentProducesNoAlerts() {
        AttachmentInfo attachment = new AttachmentInfo("Meeting_Minutes.pdf", 32000, "application/pdf");
        List<ThreatIndicator> indicators = attachmentService.analyzeAttachments(List.of(attachment));

        assertTrue(indicators.isEmpty());
    }
}
