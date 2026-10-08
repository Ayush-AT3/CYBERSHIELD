package com.cybershield.service;

import com.cybershield.model.AttachmentInfo;
import com.cybershield.model.EmailScanRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class EmlParserService {

    private static final Pattern BOUNDARY_PATTERN = Pattern.compile("boundary=[\"']?([^\"';\\s]+)[\"']?", Pattern.CASE_INSENSITIVE);
    private static final Pattern FILENAME_PATTERN = Pattern.compile("filename=[\"']?([^\"';\\r\\n]+)[\"']?", Pattern.CASE_INSENSITIVE);
    private static final Pattern CONTENT_TYPE_PATTERN = Pattern.compile("Content-Type:\\s*([^;\\r\\n]+)", Pattern.CASE_INSENSITIVE);

    public EmailScanRequest parseEml(MultipartFile file) throws Exception {
        try (InputStream is = file.getInputStream()) {
            return parseEmlStream(is);
        }
    }

    public EmailScanRequest parseEmlStream(InputStream inputStream) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        Map<String, String> headers = new LinkedHashMap<>();
        StringBuilder rawHeaderBlock = new StringBuilder();
        String line;

        // Step 1: Parse RFC 822 Header Block
        String currentHeaderName = null;
        StringBuilder currentHeaderValue = new StringBuilder();

        while ((line = reader.readLine()) != null) {
            if (line.isEmpty()) {
                // Empty line signifies end of header block
                if (currentHeaderName != null) {
                    headers.put(currentHeaderName.toLowerCase(), currentHeaderValue.toString().trim());
                }
                break;
            }
            rawHeaderBlock.append(line).append("\n");

            // Check for multiline header unfolding (starts with space or tab)
            if ((line.startsWith(" ") || line.startsWith("\t")) && currentHeaderName != null) {
                currentHeaderValue.append(" ").append(line.trim());
            } else {
                if (currentHeaderName != null) {
                    headers.put(currentHeaderName.toLowerCase(), currentHeaderValue.toString().trim());
                }
                int colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    currentHeaderName = line.substring(0, colonIdx).trim();
                    currentHeaderValue = new StringBuilder(line.substring(colonIdx + 1).trim());
                } else {
                    currentHeaderName = null;
                }
            }
        }

        // Step 2: Read Remaining Body
        StringBuilder bodyContent = new StringBuilder();
        List<AttachmentInfo> attachments = new ArrayList<>();

        String contentType = headers.getOrDefault("content-type", "text/plain");
        Matcher boundaryMatcher = BOUNDARY_PATTERN.matcher(contentType);

        if (boundaryMatcher.find()) {
            String boundary = boundaryMatcher.group(1).trim();
            parseMultipartBody(reader, boundary, bodyContent, attachments);
        } else {
            // Simple single-part message
            while ((line = reader.readLine()) != null) {
                bodyContent.append(line).append("\n");
            }
        }

        // Clean extracted values
        String sender = headers.getOrDefault("from", "Unknown Sender");
        String subject = headers.getOrDefault("subject", "No Subject");
        String body = bodyContent.toString().trim();

        // If body is HTML, strip basic tags for text matching
        String cleanBody = stripHtml(body);

        EmailScanRequest request = new EmailScanRequest();
        request.setSender(sender);
        request.setSubject(subject);
        request.setBody(cleanBody);
        request.setAttachments(attachments);

        return request;
    }

    private void parseMultipartBody(BufferedReader reader, String boundary,
                                   StringBuilder bodyText, List<AttachmentInfo> attachments) throws Exception {
        String line;
        String boundaryMarker = "--" + boundary;
        String endBoundaryMarker = "--" + boundary + "--";

        boolean inPart = false;
        Map<String, String> partHeaders = new HashMap<>();
        StringBuilder partBody = new StringBuilder();

        while ((line = reader.readLine()) != null) {
            if (line.startsWith(boundaryMarker)) {
                if (inPart) {
                    processPart(partHeaders, partBody.toString(), bodyText, attachments);
                }

                if (line.startsWith(endBoundaryMarker)) {
                    inPart = false;
                    break;
                }

                inPart = true;
                partHeaders.clear();
                partBody.setLength(0);

                // Read part headers
                String partHeaderLine;
                while ((partHeaderLine = reader.readLine()) != null && !partHeaderLine.isEmpty()) {
                    int colonIdx = partHeaderLine.indexOf(':');
                    if (colonIdx > 0) {
                        String name = partHeaderLine.substring(0, colonIdx).trim().toLowerCase();
                        String val = partHeaderLine.substring(colonIdx + 1).trim();
                        partHeaders.put(name, val);
                    }
                }
                continue;
            }

            if (inPart) {
                partBody.append(line).append("\n");
            }
        }

        if (inPart && partBody.length() > 0) {
            processPart(partHeaders, partBody.toString(), bodyText, attachments);
        }
    }

    private void processPart(Map<String, String> headers, String body,
                            StringBuilder aggregatedText, List<AttachmentInfo> attachments) {
        String contentDisp = headers.getOrDefault("content-disposition", "");
        String contentType = headers.getOrDefault("content-type", "text/plain");

        Matcher filenameMatcher = FILENAME_PATTERN.matcher(contentDisp + " " + contentType);
        if (filenameMatcher.find()) {
            String filename = filenameMatcher.group(1).trim();
            long sizeBytes = estimateSize(body, headers.getOrDefault("content-transfer-encoding", ""));
            Matcher typeMatcher = CONTENT_TYPE_PATTERN.matcher(contentType);
            String cleanType = typeMatcher.find() ? typeMatcher.group(1) : contentType.split(";")[0].trim();

            attachments.add(new AttachmentInfo(filename, sizeBytes, cleanType));
        } else if (contentType.toLowerCase().contains("text/plain") || contentType.toLowerCase().contains("text/html")) {
            aggregatedText.append("\n").append(body);
        }
    }

    private long estimateSize(String body, String encoding) {
        if ("base64".equalsIgnoreCase(encoding.trim())) {
            // Estimate decoded size from base64 characters
            String clean = body.replaceAll("\\s+", "");
            return (long) (clean.length() * 0.75);
        }
        return body.getBytes(StandardCharsets.UTF_8).length;
    }

    private String stripHtml(String html) {
        if (html == null) return "";
        return html.replaceAll("<style[^>]*>[\\s\\S]*?</style>", "")
                   .replaceAll("<script[^>]*>[\\s\\S]*?</script>", "")
                   .replaceAll("<[^>]+>", " ")
                   .replaceAll("&nbsp;", " ")
                   .replaceAll("&amp;", "&")
                   .replaceAll("&lt;", "<")
                   .replaceAll("&gt;", ">")
                   .replaceAll("\\s+", " ")
                   .trim();
    }
}
