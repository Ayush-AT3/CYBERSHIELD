package com.cybershield;

import com.cybershield.model.EmailScanRequest;
import com.cybershield.service.EmlParserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class EmlParserServiceTest {

    private EmlParserService parser;

    @BeforeEach
    public void setUp() {
        parser = new EmlParserService();
    }

    @Test
    public void testParseSimpleEml() throws Exception {
        String rawEml = "From: \"PayPal Security\" <alert@paypa1-update.xyz>\r\n" +
                "To: victim@example.com\r\n" +
                "Subject: URGENT: Your account suspended within 24 hours!\r\n" +
                "Content-Type: text/plain; charset=utf-8\r\n" +
                "\r\n" +
                "Dear customer, please verify your credentials immediately at http://192.168.1.1/login\r\n";

        ByteArrayInputStream is = new ByteArrayInputStream(rawEml.getBytes(StandardCharsets.UTF_8));
        EmailScanRequest request = parser.parseEmlStream(is);

        assertEquals("\"PayPal Security\" <alert@paypa1-update.xyz>", request.getSender());
        assertEquals("URGENT: Your account suspended within 24 hours!", request.getSubject());
        assertTrue(request.getBody().contains("verify your credentials immediately"));
    }

    @Test
    public void testParseMultipartEmlWithAttachment() throws Exception {
        String boundary = "----=_Part_123456";
        String rawEml = "From: \"Finance Officer\" <accounting@fake-invoice.top>\r\n" +
                "Subject: Overdue Invoice Remittance\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n" +
                "\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Type: text/plain; charset=utf-8\r\n" +
                "\r\n" +
                "Please find your overdue invoice attached. Immediate wire transfer required.\r\n" +
                "--" + boundary + "\r\n" +
                "Content-Type: application/octet-stream; name=\"Invoice_Sept.pdf.exe\"\r\n" +
                "Content-Disposition: attachment; filename=\"Invoice_Sept.pdf.exe\"\r\n" +
                "Content-Transfer-Encoding: base64\r\n" +
                "\r\n" +
                "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n" +
                "--" + boundary + "--\r\n";

        ByteArrayInputStream is = new ByteArrayInputStream(rawEml.getBytes(StandardCharsets.UTF_8));
        EmailScanRequest request = parser.parseEmlStream(is);

        assertEquals("\"Finance Officer\" <accounting@fake-invoice.top>", request.getSender());
        assertEquals("Overdue Invoice Remittance", request.getSubject());
        assertTrue(request.getBody().contains("wire transfer required"));
        assertEquals(1, request.getAttachments().size());
        assertEquals("Invoice_Sept.pdf.exe", request.getAttachments().get(0).getFilename());
    }
}
