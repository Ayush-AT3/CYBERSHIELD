# CyberShield: Smart Web Security System for Phishing Detection
> **Engineering Final Year Project** &bull; **Department of Information Technology**

[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Server](https://img.shields.io/badge/Server-Embedded%20Tomcat%2010.1-red.svg)](https://tomcat.apache.org/)
[![Database](https://img.shields.io/badge/Database-H2%20Embedded%20SQL%20%2F%20JPA-blue.svg)](https://www.h2database.com/)
[![Algorithm](https://img.shields.io/badge/Algorithm-Aho--Corasick-blue.svg)](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
[![Threat Intel](https://img.shields.io/badge/Threat%20Intel-VirusTotal%20v3-blueviolet.svg)](https://virustotal.com)
[![Tests](https://img.shields.io/badge/Tests-24%2F24%20Passed-success.svg)]()

---

## 1. Project Abstract
Phishing attacks have emerged as a major cybersecurity threat, targeting individuals and organizations through deceptive emails, fraudulent websites, and malicious URLs designed to steal sensitive information such as passwords, banking credentials, and personal data. As attackers continuously develop more sophisticated techniques, relying on conventional security measures alone can make it difficult to identify phishing attempts accurately and efficiently.

This project presents **CyberShield: Smart Web Security System for Phishing Detection**, a Java-based web application designed to identify phishing emails and malicious URLs using a **four-layer detection approach**:
1. **Layer 1**: Uses the **Aho-Corasick algorithm** to detect phishing-related keywords retrieved from the database, along with **sender verification** to identify potential email spoofing and display-name anomalies.
2. **Layer 2**: Performs **regular-expression-based pattern analysis** to identify suspicious language patterns, including urgency, credential requests, financial fraud indicators, and other phishing-related behaviors.
3. **Layer 3**: Conducts **heuristic URL analysis**, examining factors such as IP-based URLs, Shannon character entropy, URL structure, brand impersonation, and risky top-level domains (TLDs). URLs exceeding a predefined risk threshold are further verified using the **VirusTotal API**, with controlled API usage to improve efficiency.
4. **Layer 4**: Analyzes **email attachments** to identify potentially dangerous file types and suspicious characteristics (executables, container images, macro-enabled documents, double extensions, and MIME discrepancies).

To improve system performance, **caching mechanisms** (Caffeine in-memory cache) are implemented for phishing keywords, sender information, and VirusTotal results, reducing unnecessary database and API requests. All scans and keywords are persistently managed in an embedded **H2 SQL Database** (`./data/cybershield`) with a visual console at `/h2-console` and optional **Supabase Cloud PostgreSQL** sync. 

A **cumulative risk-scoring mechanism** classifies inputs into three standardized categories (normalized on a 0 to 15 scale):
- **Safe**: Total Score $< 5.0$ (Score range: $1.0 - 5.0$)
- **Suspicious**: Total Score $5.0 - 9.9$ (Score range: $5.0 - 10.0$)
- **Dangerous**: Total Score $\ge 10.0$ (Score range: $10.0 - 15.0$, strictly capped at $15.0$ maximum)

---

## 2. System Architecture

```mermaid
flowchart TD
    subgraph Client ["Client & Presentation Layer (Frontend)"]
        HP["Landing Home Page (Security Suite Overview)"]
        T1["Tool 1: Analyse Email (Manual Input & .EML Upload)"]
        T2["Tool 2: Scan URL (Heuristic & Threat Intelligence)"]
        UI["Side-by-Side Results Dashboard (Gauge, Layers & Findings)"]
    end

    subgraph Controller ["API Gateway / Spring Boot Controllers (Port 8085)"]
        SC["ScanController (/api/scan/email, /api/scan/eml, /api/scan/url)"]
        KC["KeywordController (/api/keywords)"]
        AC["AnalyticsController (/api/analytics/summary)"]
    end

    subgraph Engine ["CyberShield 4-Layer Detection Engine"]
        L1["Layer 1: Aho-Corasick Automaton & Sender Verification"]
        L2["Layer 2: Regular Expression Linguistic & Behavioral Analysis"]
        L3["Layer 3: Heuristic URL Analysis & Shannon Entropy"]
        L4["Layer 4: Attachment & Payload Risk Analysis"]
        Score["Cumulative Risk Scoring Engine (Capped at 15.0 max)"]
    end

    subgraph Persistence ["Database & Caching Layer"]
        H2[("Embedded H2 SQL Database\n./data/cybershield (Web Console: /h2-console)")]
        C1["Compiled Aho-Corasick Trie Cache (Caffeine)"]
        C2["VirusTotal Threat Intelligence Cache (24h TTL)"]
        C3["Recent Scans Circular Buffer"]
        Supa[("Optional Supabase Cloud PostgreSQL Sync")]
    end

    subgraph External ["External Intelligence Feed"]
        VT["VirusTotal v3 API (Conditional Threat Intel)"]
    end

    HP --> T1
    HP --> T2
    T1 --> SC
    T2 --> SC

    SC --> Engine
    KC --> H2
    KC -. Optional .-> Supa

    L1 <--> C1
    L1 <--> H2
    L3 <--> C2
    L3 -. Threshold Met (Score >= 6.0) .-> VT
    Engine --> C3
    Engine --> H2

    L1 --> Score
    L2 --> Score
    L3 --> Score
    L4 --> Score

    Score -->|"Safe (1-5) | Suspicious (5-10) | Dangerous (10-15)"| UI
```

---

## 3. Four-Layer Detection Pipeline

### Layer 1: Aho-Corasick Automaton & Sender Verification
- **Aho-Corasick Multi-Pattern Trie**:
  - Time complexity: $\mathcal{O}(n + m + z)$, where $n$ is the input text length, $m$ is the total length of all keywords, and $z$ is the number of matches.
  - Unlike naive nested iteration ($\mathcal{O}(n \cdot k)$), the Aho-Corasick trie processes all keywords simultaneously in a single pass using Breadth-First Search (BFS) failure links and output dictionaries.
  - Phishing keywords are persisted in the **H2 Database** and compiled into memory.
- **Sender Verification**:
  - **Display Name Brand Impersonation**: Detects when display names claim trusted brands (e.g. `"PayPal Support"`, `"Bank Alert"`) while the sender uses an unverified or free webmail address (e.g. `<billing@gmail.com>`).
  - **Lookalike & Typosquatted Domains**: Employs Levenshtein string distance to detect homoglyph variants (e.g., `paypa1.com`, `micros0ft.com`).
  - **Disposable Email Filtering**: Flags burner and temporary mailbox providers.
  - **RFC 5322 Syntax Validation**: Identifies malformed addresses and forged headers.

### Layer 2: Regular Expression Linguistic & Behavioral Analysis
- **Urgency & Coercion Patterns**:
  - Detects strict psychological deadlines (`"within 24 hours"`, `"immediate action required"`, `"act immediately"`).
  - Flags punitive threats (`"account suspended"`, `"account will be locked"`, `"unauthorized login attempt"`).
- **Credential Harvesting Cues**:
  - Identifies direct calls to action (`"verify your password"`, `"confirm your account"`, `"reset your credentials"`).
  - Flags solicitations for sensitive identity tokens (`"enter your PIN"`, `"Social Security Number"`).
- **Financial Fraud Patterns**:
  - Detects requests for non-reversible transfers (`"wire transfer"`, `"cryptocurrency payout"`, `"bitcoin transaction"`).
  - Identifies fake lottery and prize lures (`"claim your prize"`, `"tax refund approved"`).
- **Defense Evasion Triggers**:
  - Flags instructions to bypass host security (`"disable your antivirus"`, `"enable macros to view"`).
  - Identifies secrecy requests (`"do not contact support"`, `"keep this confidential"`).

### Layer 3: Heuristic URL Analysis & VirusTotal Intelligence
- **IP-Based Host Detection**: Detects raw numerical IPv4/IPv6 hosts (e.g. `http://192.168.1.100/paypal/login.php`) commonly deployed by short-lived phishing kits.
- **Shannon Character Entropy**:
  $$H(S) = -\sum_{i=1}^{k} P(c_i) \log_2 P(c_i)$$
  Computes information entropy of the hostname. Hosts with $H(S) > 3.85$ bits indicate Algorithmic Domain Generation (DGA) or anti-filtering tokens.
- **Structural URL Heuristics**:
  - Excessive nested subdomains ($> 4$ segments).
  - UserInfo `@` sign obfuscation (`http://trusted-brand.com@attacker-server.com/login`).
  - URL length anomalies ($> 95$ characters).
  - Non-standard HTTP service ports (e.g., `:8080`, `:8443`, `:2082`).
  - Abusive / Risky Top-Level Domains (`.xyz`, `.top`, `.tk`, `.ml`, `.click`, `.zip`, `.mov`, `.buzz`, `.work`).
- **Brand Impersonation in URLs**: Identifies brands in subdomains (`paypal.com.scam-server.xyz`) and path masquerading (`/paypal/login.php`).
- **Conditional VirusTotal Verification**:
  - Triggered only when the heuristic risk score exceeds the predefined threshold ($\ge 6.0$).
  - Results cached for 24 hours to preserve API quotas (free tier: 4 requests/min).
  - Includes smart sandbox simulation mode when running offline without API keys.

### Layer 4: Email Attachment Threat Analysis
- **High-Risk Executables**: Flags direct executable and script payloads (`.exe`, `.scr`, `.bat`, `.cmd`, `.pif`, `.vbs`, `.js`, `.wsf`, `.hta`, `.cpl`, `.ps1`).
- **Container Disk Images**: Detects virtual disk formats (`.iso`, `.img`, `.vhd`) used to bypass Microsoft Mark-of-the-Web (MOTW) sandbox controls.
- **Macro-Enabled Documents**: Inspects Office formats with embedded VBA macros (`.docm`, `.xlsm`, `.pptm`).
- **Double Extension Deception**: Identifies right-to-left override and masquerade naming (e.g., `Invoice_Q4.pdf.exe`, `Security_Patch.docx.vbs`).
- **MIME Discrepancy Verification**: Detects binary executable MIME types (`application/x-dosexec`) disguised with non-executable extensions.

---

## 4. Cumulative Risk Scoring & Classification

The cumulative risk score is calculated by aggregating contributions across all four layers and is strictly clamped to a maximum of **15.0**:
$$\text{Raw Score} = \text{Score}_{L1} + \text{Score}_{L2} + \text{Score}_{L3} + \text{Score}_{L4}$$
$$\text{Overall Risk Score} = \min(15.0, \text{Raw Score})$$

| Score Range | Classification | Action / Advisory |
| :---: | :---: | :--- |
| **$1.0 - 5.0$** ($< 5.0$) | <span style="color:#10b981; font-weight:bold;">SAFE</span> | Clean communication. No critical threat indicators triggered. |
| **$5.0 - 10.0$** ($5.0 - 9.9$) | <span style="color:#f59e0b; font-weight:bold;">SUSPICIOUS</span> | Caution recommended. Exhibits social engineering patterns. Verify sender through out-of-band channels. |
| **$10.0 - 15.0$** ($\ge 10.0$) | <span style="color:#ef4444; font-weight:bold;">DANGEROUS</span> | High-confidence phishing attack. Block sender, quarantine message, do not open links or attachments. |

---

## 5. Technology Stack & Modules

### Frontend
- **Languages & Frameworks**: HTML5, Tailwind CSS (via CDN), Vanilla JavaScript ES6+.
- **Icons & Visuals**: FontAwesome 6, Chart.js (Interactive 0–15 Doughnut Risk Gauge).
- **Architecture**: Single Page Application (SPA) architecture with responsive full-width layout, landing Home Page, clean empty input fields, and side-by-side forensic reporting.

### Backend
- **Core Platform**: Java 17 (OpenJDK / Eclipse Adoptium Temurin).
- **Framework**: Spring Boot 3.2.5 (Spring MVC, REST Controllers, Spring Validation, Spring Data JPA).
- **Server Engine**: Embedded Apache Tomcat 10.1.20 (running on port `8085`).
- **String Algorithms**: Custom Aho-Corasick Multi-Pattern Trie, Apache Commons Text (Levenshtein Distance).
- **Caching**: Caffeine High-Performance Cache (Trie cache, VirusTotal 24h cache, recent scans buffer).
- **Database**: Embedded H2 SQL Database (`./data/cybershield`) with `/h2-console` web GUI (optional Supabase Cloud PostgreSQL client included).
- **RFC 822 Email Parser**: Built-in MIME multipart and header parser for `.eml` files.
- **Testing**: JUnit 5, Mockito (24 unit tests passing).

---

## 6. Project Modules Breakdown

The project is structured into **6 core modules**:

1. **Presentation Module (`src/main/resources/static/`)**:
   - `index.html`: Responsive full-screen user interface with Home Page, Email Analyzer, URL Scanner, and side-by-side results view.
   - `css/style.css`: High-contrast dark security theme with custom badges and animations.
   - `js/app.js`: Client-side logic for tool switching, `.eml` drag-and-drop, API communication, and Chart.js gauge rendering.

2. **Controller Module / API Gateway (`com.cybershield.controller`)**:
   - `ScanController.java`: Handles `/api/scan/email`, `/api/scan/eml` (multipart), `/api/scan/url`, and `/api/scan/db-history`.
   - `KeywordController.java`: Endpoints for listing, adding, and reloading Aho-Corasick keywords.
   - `AnalyticsController.java`: Aggregates real-time scan metrics, classification ratios, and cache stats.

3. **Detection Engine Module (`com.cybershield.service`)**:
   - `PhishingDetectionEngine.java`: Orchestrates the 4 layers, aggregates scores, clamps scores to 15.0 max, and generates defense advisories.
   - `EmlParserService.java`: Parses RFC 822 `.eml` files, extracting headers, body content, and multipart attachments.
   - **Layer 1 (`com.cybershield.service.layer1`)**: `AhoCorasickEngine.java`, `KeywordDetectionService.java`, `SenderVerificationService.java`.
   - **Layer 2 (`com.cybershield.service.layer2`)**: `RegexPatternAnalysisService.java`, `PatternRule.java`.
   - **Layer 3 (`com.cybershield.service.layer3`)**: `HeuristicUrlAnalysisService.java`, `ShannonEntropyCalculator.java`, `BrandImpersonationDetector.java`, `VirusTotalIntegrationService.java`.
   - **Layer 4 (`com.cybershield.service.layer4`)**: `AttachmentAnalysisService.java`, `FileTypeRiskRegistry.java`.

4. **Persistence & Database Module (`com.cybershield.entity`, `com.cybershield.repository`, `com.cybershield.service.database`)**:
   - `ScanRecordEntity.java` & `ThreatIndicatorEntity.java`: Maps scan audits and forensic evidence to H2 tables.
   - `KeywordEntity.java`: Maps phishing keywords, categories, and weights to the H2 database.
   - `ScanRecordRepository.java` & `KeywordRepository.java`: Spring Data JPA interfaces for SQL operations.
   - `DatabaseService.java`: Automatically seeds 41 keywords on first boot and persists every scan to `./data/cybershield`.

5. **Caching & Performance Module (`com.cybershield.service.cache`)**:
   - `CacheService.java`: Caffeine-backed cache for linear-time compiled Trie, VirusTotal API responses, and recent scans.

6. **External Integration Module (`com.cybershield.service.supabase`)**:
   - `SupabaseClientService.java`: PostgREST client for optional cloud PostgreSQL sync with built-in in-memory fallback.

---

## 7. How to Run the Project

### Prerequisites
- Java Development Kit (JDK) 17 or higher
- Windows, macOS, or Linux

### Running via VS Code (Recommended)
1. Open **VS Code** $\rightarrow$ **File** $\rightarrow$ **Open Folder...** $\rightarrow$ Select `CyberShield`.
2. Press <kbd>F5</kbd> (or click the green **Run (▶️)** button in the Run & Debug panel).
3. The server starts on port **8085** and automatically opens:
   👉 **`http://localhost:8085/`**

### Running via Terminal / Command Line
In PowerShell or Terminal inside the project directory:
```powershell
& "C:\Users\USER\.gemini\antigravity\scratch\maven\apache-maven-3.9.6\bin\mvn.cmd" spring-boot:run
```
*(Or simply double-click `run.bat`)*

### Accessing the Embedded H2 Database Console
Open Chrome and visit:
👉 **`http://localhost:8085/h2-console`**
- **Driver Class**: `org.h2.Driver`
- **JDBC URL**: `jdbc:h2:file:./data/cybershield`
- **User Name**: `sa`
- **Password**: `password`
- Click **Connect** to query `SELECT * FROM SCANS;` or `SELECT * FROM KEYWORDS;`.

---

## 8. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan/email` | Comprehensive 4-layer scan for manual email inputs |
| `POST` | `/api/scan/eml` | Upload and scan an RFC 822 `.eml` email file |
| `POST` | `/api/scan/url` | Standalone heuristic URL & VirusTotal threat intelligence scan |
| `GET` | `/api/scan/{id}` | Retrieve diagnostic report by scan UUID |
| `GET` | `/api/scan/history` | List recent scans from in-memory cache |
| `GET` | `/api/scan/db-history` | List permanent scan records from H2 Database |
| `GET` | `/api/keywords` | List active Aho-Corasick phishing keywords |
| `POST` | `/api/keywords` | Add a new phishing keyword to the database |
| `POST` | `/api/keywords/reload` | Recompile in-memory Aho-Corasick Trie |
| `GET` | `/api/analytics/summary` | Real-time threat stats, classification counts, and cache metrics |

---

## 9. Automated Testing (24/24 Passed)

Execute the full automated test suite:
```bash
mvn test
```
The test suite validates:
- `AhoCorasickEngineTest` (3 tests): Trie creation, BFS failure link traversal, overlapping keyword detection.
- `SenderVerificationTest` (4 tests): Display name brand deception, lookalike typosquatting, disposable email providers.
- `RegexPatternAnalysisTest` (4 tests): Urgency, credential harvesting, financial fraud, and defense evasion patterns.
- `HeuristicUrlAnalysisTest` (4 tests): Numerical IP URLs, Shannon character entropy, brand spoofing in subdomains, abusive TLDs.
- `AttachmentAnalysisTest` (4 tests): Double extensions, executable payloads, container disk images, and macro documents.
- `CumulativeRiskScoringTest` (3 tests): Threshold boundaries for Safe ($<5$), Suspicious ($5-10$), and Dangerous ($10-15$).
- `EmlParserServiceTest` (2 tests): RFC 822 header extraction, MIME multipart decoding, attachment isolation.

---

## 10. Viva Voce & Defense Presentation Guide

1. **Why Aho-Corasick instead of standard substring search (`String.contains`)?**
   - Naive search requires $\mathcal{O}(k \cdot n)$ iterations for $k$ keywords on a text of length $n$. As the keyword database grows, naive search slows down significantly.
   - The Aho-Corasick automaton processes the entire input text in a single $\mathcal{O}(n + m + z)$ pass using a deterministic finite-state automaton with failure transitions, making it computationally optimal.

2. **Why use an Embedded Apache Tomcat Server?**
   - CyberShield embeds Apache Tomcat 10.1 directly inside the Spring Boot JAR. This eliminates the need to install or configure external application servers on the host computer, ensuring the project is 100% portable across machines.

3. **Why use an Embedded H2 Database?**
   - H2 requires zero external software installation (no MySQL or PostgreSQL service needed to run in the background). It writes to a persistent local file (`./data/cybershield`) so data survives reboots, and includes a built-in web console (`/h2-console`) to demonstrate live SQL queries during viva.

4. **What is Shannon Entropy and why is it used?**
   - Shannon entropy measures information unpredictability: $H(S) = -\sum P(c) \log_2 P(c)$. Legitimate brand domains have natural linguistic character distributions (low entropy $\approx 2.5 - 3.2$), whereas algorithmically generated domains (DGA) and obfuscated redirect tokens exhibit high entropy ($> 3.85$).

5. **How does the cumulative scoring prevent False Positives?**
   - A single weak indicator (e.g. an urgency phrase like "please reply today") only contributes 3–4 points and remains classified as **Safe** ($< 5$).
   - A message is only flagged as **Dangerous** ($\ge 10$) when multiple layers corroborate threat signals (e.g. spoofed sender + urgency + credential harvesting link + suspicious attachment), with the total score capped at 15.0.
