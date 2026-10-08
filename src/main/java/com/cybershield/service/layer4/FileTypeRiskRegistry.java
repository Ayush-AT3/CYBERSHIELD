package com.cybershield.service.layer4;

import java.util.Map;
import java.util.Set;

public class FileTypeRiskRegistry {

    public static final Set<String> HIGH_RISK_EXECUTABLES = Set.of(
            "exe", "scr", "bat", "cmd", "pif", "vbs", "vbe", "js", "jse", "wsf",
            "wsh", "hta", "cpl", "ps1", "ps2", "reg", "jar", "gadget", "com"
    );

    public static final Set<String> CONTAINER_DISK_IMAGES = Set.of(
            "iso", "img", "vhd", "vhdx", "dmg"
    );

    public static final Set<String> MACRO_ENABLED_DOCUMENTS = Set.of(
            "docm", "xlsm", "pptm", "dotm", "xltm", "iqy", "xla"
    );

    public static final Set<String> ARCHIVE_EXTENSIONS = Set.of(
            "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "ace", "cab"
    );

    public static final Set<String> FINANCIAL_LURE_KEYWORDS = Set.of(
            "invoice", "payment", "receipt", "swift", "remittance", "statement",
            "overdue", "purchase", "order", "bank", "settlement", "salary", "bonus"
    );

    public static final Map<String, String> EXTENSION_TO_EXPECTED_MIME = Map.of(
            "pdf", "application/pdf",
            "png", "image/png",
            "jpg", "image/jpeg",
            "jpeg", "image/jpeg",
            "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "txt", "text/plain"
    );
}
