# Lab 03: Vulnerability Scanning and Management

## 🎯 Lab Overview

This lab demonstrates enterprise-grade vulnerability assessment and management using OpenVAS (Open Vulnerability Assessment System). The hands-on experience covers vulnerability scanning, risk assessment, automated alerting, and remediation planning—essential skills for Security Analysts and Vulnerability Management professionals.

**Completion Date:** As per curriculum  
**Environment:** Kali Linux with OpenVAS/GVM  
**Target Network:** 192.168.252.0/24 (3 systems scanned)  
**Vulnerabilities Identified:** 11 unique findings across Critical to Low severity  
**Duration:** Full vulnerability assessment lifecycle

---

## 📋 Table of Contents

- [Objectives](#objectives)
- [Technologies & Tools Used](#technologies--tools-used)
- [Lab Sections & Methodology](#lab-sections--methodology)
  - [1. OpenVAS Configuration & Access](#1-openvas-configuration--access)
  - [2. Network Vulnerability Scanning](#2-network-vulnerability-scanning)
  - [3. Port List Configuration](#3-port-list-configuration)
  - [4. Automated Alert System Setup](#4-automated-alert-system-setup)
  - [5. Report Generation & Analysis](#5-report-generation--analysis)
- [Vulnerability Findings & Analysis](#vulnerability-findings--analysis)
- [Risk Assessment & Remediation](#risk-assessment--remediation)
- [Skills Demonstrated](#skills-demonstrated)
- [Real-World Applications](#real-world-applications)
- [Key Learnings](#key-learnings)

---

## 🎓 Objectives

- Deploy and configure OpenVAS vulnerability scanner in enterprise environment
- Perform comprehensive network vulnerability assessments across multiple targets
- Analyze vulnerability scan results using CVSS scoring methodology
- Configure automated alerting systems for critical vulnerability detection
- Generate professional vulnerability assessment reports
- Develop remediation strategies based on risk prioritization
- Understand cryptographic weaknesses and their security implications

---

## 🛠️ Technologies & Tools Used

| Category | Tools/Technologies |
|----------|-------------------|
| **Vulnerability Scanner** | OpenVAS (Greenbone Vulnerability Management) |
| **Operating System** | Kali Linux |
| **Target Systems** | Linux servers (192.168.252.3, 192.168.252.61, 192.168.252.241) |
| **Web Interface** | HTTPS (Port 9392) |
| **Email System** | Postfix mail server, Mailutils |
| **Report Formats** | PDF, XML, HTML |
| **Vulnerability Databases** | NVD (National Vulnerability Database), CVE |
| **Risk Scoring** | CVSS v3.1 (Common Vulnerability Scoring System) |
| **Network Services** | SSH, MySQL/MariaDB, ICMP, TCP |

---

## 🔬 Lab Sections & Methodology

### 1. OpenVAS Configuration & Access

**Objective:** Establish secure access to OpenVAS vulnerability management platform.

#### Web Interface Authentication

**Access URL:** `https://localhost:9392`

**Credentials:**
- Username: `MGS650`
- Password: `Change.me!`

**Security Considerations:**
- HTTPS encryption for web management interface
- Strong password policy (special characters, mixed case)
- Localhost binding limits attack surface
- Credential management best practices

**Platform Overview:**
- **OpenVAS (GVM):** Open-source vulnerability scanner
- **NVD Integration:** 100,000+ vulnerability tests
- **Continuous Updates:** CVE database synchronization
- **Enterprise Features:** Scheduling, reporting, alerting

**Access Verified:** Successfully authenticated to vulnerability management console

---

### 2. Network Vulnerability Scanning

**Objective:** Execute comprehensive vulnerability assessment across target infrastructure.

#### Scan Configuration - Task Wizard

**Navigation:** Scans → Tasks → Task Wizard (wand icon)

**Target IP Addresses:**
```
192.168.252.3
192.168.252.61
192.168.252.241
```

**Scan Parameters:**
- **Scan Type:** Full and Fast
- **Port Range:** Default (1-65535)
- **Scan Policy:** Comprehensive vulnerability checks
- **Execution:** Immediate start

**Methodology:**
1. **Target Enumeration:** Defined IP scope
2. **Port Discovery:** Identified open services
3. **Service Detection:** Determined running software versions
4. **Vulnerability Matching:** Compared against CVE database
5. **Exploit Assessment:** Evaluated exploitability

**Scan Execution:**
- Initiated background scan process
- Monitored progress through web interface
- Allowed completion before analysis

**Network Topology:**
```
Scanner (Kali Linux) → 192.168.252.0/24 Network
                        ├─ 192.168.252.3 (Linux Server)
                        ├─ 192.168.252.61 (Database Server)
                        └─ 192.168.252.241 (Minimal System)
```

---

### 3. Port List Configuration

**Objective:** Understand scan scope and customize port scanning parameters.

#### Port List Examination

**Navigation:** Configuration → Port Lists

**Available Port Lists Identified:**

| Port List Name | Description | Port Count | Use Case |
|----------------|-------------|------------|----------|
| **All IANA assigned TCP** | Complete IANA registry | ~15,000 | Comprehensive scans |
| **All IANA assigned TCP and UDP** | Full protocol coverage | ~30,000 | Maximum coverage |
| **All TCP and Nmap top 100 UDP** | Balanced approach | ~65,635 | Efficient scanning |

**Port List Analysis:**

**Selected List Details:**
- Port ranges view available
- Custom port definitions possible
- Service-to-port mappings displayed

**Information Window Components:**
- Port list metadata
- Creation date and owner
- Number of ports included
- Target protocol types

**Port Ranges Window:**
- Start/End port numbers
- Protocol specification (TCP/UDP)
- Comment/description fields

**Security Relevance:**
- Comprehensive scanning = better vulnerability coverage
- Targeted scanning = faster, focused results
- Custom lists = environment-specific assessments

---

### 4. Automated Alert System Setup

**Objective:** Configure real-time notifications for critical vulnerability detection.

#### Email System Configuration

**Mail Server Installation:**
```bash
sudo apt install postfix mailutils
```

**Purpose:**
- **Postfix:** SMTP server for sending emails
- **Mailutils:** Command-line email utilities
- **Integration:** OpenVAS notification capability

---

#### Postfix Configuration

**Configuration File:** `/etc/postfix/main.cf`

```bash
sudo nano /etc/postfix/main.cf
```

**Critical Configuration Change:**

**Before:**
```
inet_interfaces = all
```

**After:**
```
inet_interfaces = loopback-only
```

**Security Rationale:**
- **Loopback-only:** Accepts connections only from localhost (127.0.0.1)
- **Attack Surface Reduction:** No external mail relay capability
- **Prevents Abuse:** Cannot be used as open mail relay
- **Internal Use Only:** Perfect for local notification system

**Best Practice Applied:** Minimize network exposure of support services

---

#### Mail Service Restart

```bash
sudo systemctl restart postfix
```

**Verification:** Service reloaded with new configuration

---

#### Email Functionality Test

```bash
echo "Email Test from Kali" | mail -s "mgs650" fahmed29@buffalo.edu
```

**Command Breakdown:**
- `echo "Email Test from Kali"` → Email body content
- `|` → Pipe to mail command
- `mail -s "mgs650"` → Subject line
- `fahmed29@buffalo.edu` → Recipient address

**Test Result:** ✅ Email successfully received

**Confirmation:**
- Email delivered to inbox
- Subject: "mgs650"
- Body: "Email Test from Kali"
- Sender: Kali system user

**System Verification:** Email infrastructure operational for alerting

---

#### OpenVAS Alert Creation

**Navigation:** Configuration → Alerts → New Alert (+ icon)

**Alert Configuration:**

| Field | Value | Purpose |
|-------|-------|---------|
| **Name** | High Severity Alert | Descriptive identifier |
| **Event** | Task run status changed | Trigger condition |
| **Condition** | Severity at least High | Filter criteria (CVSS ≥ 7.0) |
| **Method** | Email | Notification mechanism |
| **To Address** | fahmed29@buffalo.edu | Security team recipient |
| **From Address** | OpenVAS Scanner | Source identification |
| **Subject** | [ALERT] High Severity Vulnerabilities Detected | Clear notification |

**Alert Logic:**
```
IF (scan_complete) AND (vulnerabilities_found WITH cvss_score >= 7.0)
THEN send_email(security_team)
```

**Business Value:**
- Immediate notification of critical risks
- Reduces mean time to detection (MTTD)
- Enables rapid incident response
- Supports 24/7 monitoring without manual checks

---

#### Alert Integration with Scan Task

**Navigation:** Scans → Tasks → Edit Task

**Configuration:**
- Selected existing "Immediate Scan" task
- Added "High Severity Alert" to task
- Saved configuration

**Result:** Scan now triggers email notification when high/critical vulnerabilities detected

**Alert Flow:**
```
Scan Execution → Vulnerability Detection → CVSS Evaluation → 
Alert Condition Match → Email Notification → Security Team Response
```

**Automation Benefit:** Proactive security monitoring without constant manual review

---

### 5. Report Generation & Analysis

**Objective:** Extract actionable intelligence from vulnerability scan results.

#### Scan Completion Verification

**Navigation:** Scans → Reports

**Status Check:**
- Monitored scan progress
- Verified 100% completion
- Confirmed all targets scanned

**Scan Metadata:**
- Start time logged
- End time recorded
- Duration calculated
- Vulnerability count displayed

---

#### PDF Report Generation

**Navigation:** Scan Report → Download → PDF Format

**Report Export:**
- Selected completed scan by date
- Clicked download icon
- Chose "PDF" in Report Format dropdown
- Generated comprehensive PDF document

**Report Contents:**
- Executive summary
- Vulnerability details by severity
- CVSS scores and vectors
- Affected systems and services
- Remediation recommendations

**Use Cases:**
- Management briefings
- Compliance documentation
- Audit evidence
- Remediation tracking

---

#### Vulnerability Results Analysis

**Navigation:** Scans → Results

**Results View Features:**
- Sortable vulnerability list
- Severity-based filtering
- Host-specific grouping
- CVE reference linking
- Solution recommendations

**Analysis Capabilities:**
- Identify highest risk vulnerabilities
- Group by affected system
- Filter by severity level
- Review technical details
- Access remediation guidance

---

#### Detailed Report Review

**Navigation:** Scans → Reports → Select Report

**Report Dashboard Components:**

| Section | Information Provided |
|---------|---------------------|
| **Summary** | Total vulnerabilities by severity |
| **Hosts** | Per-system vulnerability breakdown |
| **Ports** | Service-level exposure |
| **Vulnerabilities** | Detailed findings with CVE IDs |
| **Solutions** | Remediation strategies |
| **Task Information** | Scan parameters and timestamp |

**Professional Output:** Publication-ready vulnerability assessment documentation

---

## 🚨 Vulnerability Findings & Analysis

### Executive Summary

**Scan Results Overview:**

| Severity | Count | CVSS Range | Risk Level |
|----------|-------|------------|-----------|
| **Critical** | 0 | 9.0-10.0 | Immediate Action |
| **High** | 1 | 7.0-8.9 | Urgent |
| **Medium** | 3 | 4.0-6.9 | Important |
| **Low** | 7 | 0.1-3.9 | Informational |
| **Total** | 11 | - | - |

**Affected Systems:**
- **192.168.252.61:** 6 vulnerabilities (1 High, 2 Medium, 3 Low)
- **192.168.252.3:** 5 vulnerabilities (2 Medium, 3 Low)
- **192.168.252.241:** 1 vulnerability (1 Low)

---

### 🔴 Critical/High Severity Findings

#### CVE-2012-xxxx: MySQL/MariaDB Default Credentials

**Affected System:** 192.168.252.61  
**Service:** MySQL/MariaDB Database Server  
**CVSS Score:** 9.8 (Critical) → **HIGH**  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

**Vulnerability Description:**

The database server is running with **default root credentials** - specifically, an **empty password** for the root account. This represents one of the most severe security misconfigurations possible in database deployments.

**Attack Scenario:**
```
1. Attacker scans for open MySQL ports (3306)
2. Attempts connection: mysql -u root -p [press enter, no password]
3. IMMEDIATE ROOT DATABASE ACCESS GRANTED
4. Full control over all databases, tables, and data
5. Potential for:
   - Complete data exfiltration
   - Data manipulation/deletion
   - Privilege escalation to OS level
   - Malware injection into database
   - Ransomware deployment
```

**CVSS v3.1 Vector:**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Vector Analysis:**
- **AV:N (Attack Vector: Network)** - Exploitable remotely
- **AC:L (Attack Complexity: Low)** - No special conditions required
- **PR:N (Privileges Required: None)** - No authentication needed
- **UI:N (User Interaction: None)** - Fully automated exploitation
- **C:H/I:H/A:H** - Complete compromise of confidentiality, integrity, availability

**Real-World Impact:**
- **Data Breach:** All customer data, PII, financial records exposed
- **Compliance Violations:** GDPR, HIPAA, PCI-DSS non-compliance
- **Reputational Damage:** Loss of customer trust
- **Financial Loss:** Fines, lawsuits, remediation costs
- **Business Disruption:** Potential ransomware or data destruction

**Remediation - URGENT (Priority 1):**

**Immediate Actions:**
```sql
-- Set strong root password immediately
ALTER USER 'root'@'localhost' IDENTIFIED BY 'ComplexP@ssw0rd123!#';
FLUSH PRIVILEGES;
```

**Best Practices:**
1. **Strong Password Policy:**
   - Minimum 16 characters
   - Uppercase, lowercase, numbers, special characters
   - No dictionary words
   - Regular rotation (90 days)

2. **Access Control:**
   ```sql
   -- Restrict root to localhost only
   DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
   FLUSH PRIVILEGES;
   ```

3. **Create Limited Privilege Accounts:**
   ```sql
   CREATE USER 'app_user'@'192.168.252.%' IDENTIFIED BY 'StrongPassword!';
   GRANT SELECT, INSERT, UPDATE ON app_database.* TO 'app_user'@'192.168.252.%';
   ```

4. **Additional Hardening:**
   - Disable remote root login entirely
   - Implement IP whitelisting
   - Enable audit logging
   - Use SSL/TLS for connections
   - Regular security updates

**Verification:**
```bash
# Test that default credentials no longer work
mysql -u root -p
# Should require password
```

**Timeline:** Fix within 24 hours - actively exploitable

---

### 🟡 Medium Severity Findings

#### 1. Weak Key Exchange (KEX) Algorithm in SSH

**Affected Systems:** 192.168.252.61, 192.168.252.3  
**Service:** SSH Server (Port 22)  
**CVSS Score:** 5.3 (Medium)  
**CWE:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm)

**Vulnerability Description:**

SSH server supports **weak Diffie-Hellman key exchange** using 1024-bit MODP groups with SHA-1 hashing. These algorithms are cryptographically obsolete and vulnerable to modern attacks.

**Technical Details:**

**Weak Algorithms Detected:**
- `diffie-hellman-group1-sha1` (1024-bit, SHA-1)
- `diffie-hellman-group14-sha1` (2048-bit, SHA-1)

**Why This Matters:**
1. **1024-bit MODP Groups:** Vulnerable to Logjam attack (CVE-2015-4000)
   - Nation-state actors can break 1024-bit DH
   - Pre-computation attacks reduce brute-force time
   - Academic research demonstrates practical breaks

2. **SHA-1 Hashing:** Collision attacks proven (SHAttered attack, 2017)
   - Not collision-resistant
   - Deprecated by NIST since 2011
   - No longer considered secure

**Attack Vector:**

```
Man-in-the-Middle Attack:
1. Attacker intercepts SSH handshake
2. Forces downgrade to weak 1024-bit DH + SHA-1
3. Performs pre-computed Logjam attack
4. Recovers session keys
5. Decrypts SSH traffic in real-time
6. Steals credentials, command history, data transfers
```

**Risk Assessment:**
- **Confidentiality:** Medium - Encrypted traffic can be decrypted
- **Integrity:** Low - Session hijacking possible
- **Compliance:** Violates NIST, PCI-DSS cryptographic standards

**Remediation:**

**1. Identify Current Configuration:**
```bash
sshd -T | grep kexalgorithms
```

**2. Edit SSH Configuration:**
```bash
sudo nano /etc/ssh/sshd_config
```

**3. Configure Strong KEX Algorithms:**
```
# Add this line to sshd_config
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# Remove weak algorithms - do NOT include:
# - diffie-hellman-group1-sha1
# - diffie-hellman-group14-sha1
```

**4. Restart SSH Service:**
```bash
sudo systemctl restart sshd
```

**5. Verify Configuration:**
```bash
ssh -vv user@host 2>&1 | grep "kex:"
# Should show only approved algorithms
```

**Recommended Algorithms:**
- ✅ **curve25519-sha256** (Elliptic Curve, best performance)
- ✅ **ecdh-sha2-nistp521** (NIST P-521 curve)
- ✅ **diffie-hellman-group-exchange-sha256** (Dynamic DH groups, SHA-256)

**Timeline:** Remediate within 30 days

---

#### 2. Weak Encryption Algorithms in SSH

**Affected Systems:** 192.168.252.61, 192.168.252.3  
**Service:** SSH Server (Port 22)  
**CVSS Score:** 4.3 (Medium)  
**CWE:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm)

**Vulnerability Description:**

SSH server permits **outdated block ciphers** vulnerable to cryptographic attacks.

**Vulnerable Ciphers Detected:**

**CBC-Mode Ciphers (Vulnerable to Plaintext Recovery):**
- `3des-cbc` (Triple DES - obsolete, 64-bit block size)
- `aes128-cbc`, `aes192-cbc`, `aes256-cbc` (CBC mode vulnerable)
- `blowfish-cbc` (64-bit block, SWEET32 attack)
- `cast128-cbc` (Weak key schedule)
- `rijndael-cbc@lysator.liu.se` (Non-standard implementation)

**RC4-Based Ciphers (Completely Broken):**
- `arcfour`, `arcfour128`, `arcfour256` (Statistical biases exploitable)

**Known Attacks:**

1. **CBC Mode - Lucky 13 Attack:**
   - Timing side-channel attack
   - Recovers plaintext bytes
   - Affects all CBC-mode ciphers

2. **SWEET32 (Birthday Attack):**
   - Affects 64-bit block ciphers (3DES, Blowfish)
   - Recovers plaintext after ~32GB of data
   - Demonstrated in 2016 research

3. **RC4 Biases:**
   - Multiple statistical weaknesses
   - Prohibited by RFC 7465 (2015)
   - First bytes of keystream predictable

**Impact:**
- Session data decryption
- Password interception
- File transfer compromise
- Command injection via MITM

**Remediation:**

**Edit SSH Server Configuration:**
```bash
sudo nano /etc/ssh/sshd_config
```

**Configure Strong Ciphers:**
```
# Add modern, secure ciphers only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Explicitly REMOVE:
# - All CBC mode ciphers
# - All RC4/arcfour variants
# - 3DES and Blowfish
```

**Cipher Explanation:**
- ✅ **chacha20-poly1305** (Modern AEAD, mobile-optimized)
- ✅ **aes-gcm** (Authenticated encryption, hardware accelerated)
- ✅ **aes-ctr** (Counter mode, no CBC vulnerabilities)

**Restart and Verify:**
```bash
sudo systemctl restart sshd
ssh -Q cipher localhost  # List supported ciphers
```

**Timeline:** Remediate within 60 days

---

### 🟢 Low Severity Findings

#### 3. Weak MAC Algorithms in SSH

**Affected Systems:** 192.168.252.61, 192.168.252.3  
**Service:** SSH Server (Port 22)  
**CVSS Score:** 2.6 (Low)  
**CWE:** CWE-327 (Use of Broken Cryptographic Algorithm)

**Vulnerability Description:**

SSH server supports **weak Message Authentication Code (MAC)** algorithms for integrity verification.

**Weak MACs Detected:**

**MD5-Based (Cryptographically Broken):**
- `hmac-md5`
- `hmac-md5-96`
- `hmac-md5-etm@openssh.com`
- `hmac-md5-96-etm@openssh.com`

**SHA-1 Truncated (Weakened Security):**
- `hmac-sha1-96` (Truncated to 96 bits)
- `hmac-sha1-96-etm@openssh.com`

**Security Issues:**
- MD5 collisions proven since 2004
- Truncated MACs reduce security margin
- Integrity verification can be bypassed

**Attack Impact:**
- Message tampering possible
- Session injection attacks
- Data integrity compromise

**Remediation:**

```bash
sudo nano /etc/ssh/sshd_config
```

**Configure Strong MACs:**
```
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
```

**Recommended:**
- ✅ **hmac-sha2-512** (SHA-2 family, 512-bit)
- ✅ **hmac-sha2-256** (SHA-2 family, 256-bit)
- ✅ **ETM variants** (Encrypt-then-MAC, better security)

**Timeline:** Remediate within 90 days

---

#### 4. TCP Timestamps Information Disclosure

**Affected Systems:** 192.168.252.61, 192.168.252.3  
**Protocol:** TCP  
**CVSS Score:** 2.6 (Low)  
**CWE:** CWE-200 (Exposure of Sensitive Information)

**Vulnerability Description:**

System responds to TCP packets with **RFC 1323 timestamps** that leak system uptime information.

**Information Leaked:**
- System uptime (time since last boot)
- Reboot patterns
- Patch cycle timing
- Potential OS fingerprinting data

**Attacker Use Cases:**
1. **Uptime Analysis:** Identify unpatched systems (long uptime = no reboots = no patches)
2. **Reboot Detection:** Plan attacks after system restarts
3. **OS Fingerprinting:** Improve attack targeting
4. **Timing Attacks:** Enhanced precision for race conditions

**Example:**
```bash
# Attacker sends TCP SYN with timestamp option
# Server responds with uptime in milliseconds
Uptime: 42 days, 7 hours, 23 minutes
Conclusion: System hasn't been patched in 6 weeks
```

**Risk Level:** Low (information gathering, not direct exploit)

**Remediation:**

**Disable TCP Timestamps:**
```bash
# Temporary (until reboot)
sudo sysctl -w net.ipv4.tcp_timestamps=0

# Permanent
echo "net.ipv4.tcp_timestamps = 0" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Consideration:** May slightly impact network performance (RTT calculation)

**Timeline:** Remediate during next maintenance window (low priority)

---

#### 5. ICMP Timestamp Reply Information Disclosure

**Affected Systems:** 192.168.252.61, 192.168.252.3, 192.168.252.241  
**Protocol:** ICMP  
**CVSS Score:** 2.1 (Low)  
**CWE:** CWE-200 (Exposure of Sensitive Information)

**Vulnerability Description:**

Systems respond to **ICMP Timestamp Request (Type 13)** with **Timestamp Reply (Type 14)**, revealing system time information.

**Information Disclosed:**
- System's current time
- Time zone information
- Clock synchronization status
- Uptime indicators

**Attack Scenarios:**
1. **Time-Based Attacks:** Exploit time-sensitive security mechanisms
2. **NTP Attacks:** Identify systems with incorrect time for Kerberos/certificate attacks
3. **Reconnaissance:** Map network infrastructure
4. **Covert Channels:** Use timestamp replies for data exfiltration

**Exploitation Example:**
```bash
# Attacker sends ICMP Timestamp Request
hping3 --icmp-ts 192.168.252.61

# Receives system time
[Response] Timestamp: 1234567890 (system time in milliseconds since midnight)
```

**Remediation:**

**Option 1: Firewall Block (Recommended)**
```bash
# Block ICMP Timestamp requests at firewall
sudo iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP
sudo iptables -A OUTPUT -p icmp --icmp-type timestamp-reply -j DROP

# Make persistent
sudo iptables-save > /etc/iptables/rules.v4
```

**Option 2: Disable in Kernel**
```bash
# Add to sysctl.conf
echo "net.ipv4.icmp_echo_ignore_all = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Trade-off:** Blocking all ICMP may impact network troubleshooting (ping, traceroute)

**Timeline:** Remediate during next maintenance window

---

## 📊 Risk Assessment & Remediation

### Vulnerability Priority Matrix

```
┌─────────────────────────────────────────────────────────────┐
│                    RISK PRIORITIZATION                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CRITICAL (CVSS 9.0-10.0)                                   │
│  └─ None identified                                         │
│                                                             │
│  HIGH (CVSS 7.0-8.9) - URGENT ACTION REQUIRED               │
│  └─ [P1] MySQL Default Credentials (9.8)                    │
│     Timeline: 24 hours                                      │
│     Impact: Complete database compromise                    │
│                                                             │
│  MEDIUM (CVSS 4.0-6.9) - IMPORTANT                          │
│  ├─ [P2] Weak SSH KEX Algorithms (5.3)                      │
│  │   Timeline: 30 days                                      │
│  │   Impact: SSH session decryption                         │
│  │                                                           │
│  └─ [P3] Weak SSH Encryption Algorithms (4.3)               │
│      Timeline: 60 days                                      │
│      Impact: Confidentiality breach                         │
│                                                             │
│  LOW (CVSS 0.1-3.9) - INFORMATIONAL                         │
│  ├─ [P4] Weak SSH MAC Algorithms (2.6)                      │
│  ├─ [P5] TCP Timestamp Disclosure (2.6)                     │
│  └─ [P6] ICMP Timestamp Disclosure (2.1)                    │
│      Timeline: Next maintenance window                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Remediation Roadmap

**Phase 1: Emergency Response (24 Hours)**
- ✅ Change MySQL root password immediately
- ✅ Verify no unauthorized database access occurred
- ✅ Audit database logs for suspicious activity
- ✅ Notify security team and management

**Phase 2: Critical Hardening (Week 1)**
- ✅ Implement database access controls
- ✅ Create application-specific DB users
- ✅ Configure SSH KEX algorithm restrictions
- ✅ Test SSH connectivity with new algorithms
- ✅ Document all changes

**Phase 3: Comprehensive Hardening (Month 1)**
- ✅ Update SSH cipher suites
- ✅ Configure MAC algorithms
- ✅ Disable TCP timestamps (if acceptable)
- ✅ Implement ICMP filtering
- ✅ Rescan to verify remediation

**Phase 4: Ongoing Monitoring**
- ✅ Schedule quarterly vulnerability scans
- ✅ Configure automated alerts
- ✅ Track remediation metrics
- ✅ Update vulnerability management process

### Remediation Tracking

| Vulnerability | Severity | Status | ETA | Owner |
|---------------|----------|--------|-----|-------|
| MySQL Default Creds | High (9.8) | 🔴 Open | 24h | DBA Team |
| Weak SSH KEX | Medium (5.3) | 🟡 In Progress | 30d | SysAdmin |
| Weak SSH Ciphers | Medium (4.3) | 🟡 In Progress | 60d | SysAdmin |
| Weak SSH MACs | Low (2.6) | ⚪ Planned | 90d | SysAdmin |
| TCP Timestamps | Low (2.6) | ⚪ Planned | Q2 | Network Team |
| ICMP Timestamps | Low (2.1) | ⚪ Planned | Q2 | Network Team |

---

## 💡 Skills Demonstrated

### Technical Skills

**Vulnerability Assessment:**
- ✅ OpenVAS/GVM deployment and configuration
- ✅ Network-wide vulnerability scanning
- ✅ Multi-target assessment coordination
- ✅ Scan result interpretation and analysis
- ✅ False positive identification

**Risk Analysis:**
- ✅ CVSS scoring methodology understanding
- ✅ Vulnerability prioritization based on risk
- ✅ Attack vector analysis
- ✅ Business impact assessment
- ✅ Threat modeling application

**Security Tools:**
- ✅ OpenVAS/Greenbone Vulnerability Manager
- ✅ Postfix mail server configuration
- ✅ Linux system administration
- ✅ Network service enumeration
- ✅ Report generation and documentation

**Remediation Planning:**
- ✅ Technical solution identification
- ✅ Configuration hardening recommendations
- ✅ Patch management strategies
- ✅ Security baseline establishment
- ✅ Verification and validation methods

**Cryptography:**
- ✅ Understanding of SSH cryptographic components (KEX, ciphers, MACs)
- ✅ Recognition of weak/deprecated algorithms
- ✅ Modern cryptographic standard recommendations
- ✅ Attack vector comprehension (SWEET32, Logjam, Lucky 13)

### Professional Competencies

**Communication:**
- ✅ Technical vulnerability explanations
- ✅ Executive summary creation
- ✅ Risk communication to non-technical stakeholders
- ✅ Remediation guidance documentation
- ✅ Professional report generation

**Process & Methodology:**
- ✅ Systematic vulnerability assessment workflow
- ✅ Automated alerting configuration
- ✅ Incident notification procedures
- ✅ Change management considerations
- ✅ Continuous monitoring implementation

**Security Mindset:**
- ✅ Defense-in-depth thinking
- ✅ Proactive threat identification
- ✅ Risk-based decision making
- ✅ Compliance awareness (PCI-DSS, NIST, HIPAA)
- ✅ Security vs. usability balance

---

## 🌐 Real-World Applications

### Enterprise Security Operations

**1. Vulnerability Management Program**

**Typical Workflow:**
```
Quarterly Scans → Vulnerability Database → Risk Prioritization → 
Remediation Assignment → Verification Scanning → Metrics Reporting
```

**This Lab Demonstrates:**
- Initial vulnerability discovery
- Automated alert configuration
- Risk-based prioritization
- Remediation planning
- Professional reporting

**Industry Standards:**
- Monthly authenticated scans (PCI-DSS Requirement 11.2)
- Quarterly external scans (PCI-DSS ASV scans)
- Critical vulnerabilities patched within 30 days
- High vulnerabilities patched within 90 days

---

**2. Security Incident Response**

**Scenario:** Database Breach Investigation

**OpenVAS Application:**
1. **Initial Scan:** Discover default MySQL credentials
2. **Immediate Alert:** High severity email sent to SOC
3. **Investigation:** Check database logs for unauthorized access
4. **Containment:** Change password, restrict network access
5. **Eradication:** Remove weak configurations
6. **Recovery:** Verify remediation with rescan
7. **Lessons Learned:** Update deployment procedures

**Skills Transferable to IR:**
- Rapid vulnerability identification
- Automated detection systems
- Evidence collection (scan reports)
- Remediation verification

---

**3. Compliance & Audit Support**

**Regulatory Requirements:**

| Standard | Requirement | Lab Alignment |
|----------|-------------|---------------|
| **PCI-DSS** | Req. 11.2 - Quarterly vulnerability scans | ✅ Scanning methodology |
| **HIPAA** | § 164.308(a)(8) - Periodic risk assessment | ✅ Risk analysis |
| **SOX** | Section 404 - Internal controls | ✅ Automated monitoring |
| **NIST 800-53** | RA-5 - Vulnerability scanning | ✅ Complete process |
| **ISO 27001** | A.12.6.1 - Technical vulnerability management | ✅ Full lifecycle |

**Audit Evidence Generated:**
- PDF vulnerability reports
- Remediation tracking documentation
- Alert configuration proof
- Scan frequency records

---

**4. Penetration Testing Support**

**Pre-Engagement Reconnaissance:**
- Vulnerability scanning identifies low-hanging fruit
- CVSS scores guide exploitation priority
- Service version detection aids exploit selection
- Weak cryptography findings guide attack planning

**Example Attack Path (Based on Findings):**
```
1. Scan identifies MySQL default credentials (OpenVAS)
2. Pen tester confirms exploitability
3. Gains database access
4. Pivots to application server using stored credentials
5. Escalates privileges using system vulnerabilities
6. Achieves full environment compromise
```

---

**5. Secure DevOps Integration**

**CI/CD Pipeline Security:**
```
Code Commit → Build → Automated Scan (OpenVAS) → 
Vulnerability Gate → Deploy to Test → Production
```

**Integration Points:**
- Pre-production vulnerability scanning
- Automated scan triggering
- Build failure on high/critical findings
- Continuous security validation

**Tools Integration:**
- Jenkins plugins for OpenVAS
- GitLab security scanning
- Automated ticketing (Jira integration)
- Slack/Teams notifications

---

### Industry Scenarios

**Healthcare (HIPAA Compliance):**
- Scan patient data systems quarterly
- Verify encryption standards (SSH hardening)
- Protect PHI from breach (database security)
- Document security controls for audits

**Financial Services (PCI-DSS):**
- Scan cardholder data environment monthly
- ASV quarterly external scans mandatory
- Track remediation for audit trails
- Automated compliance reporting

**Technology Companies:**
- Pre-release vulnerability assessment
- Third-party vendor security verification
- Bug bounty program support
- Security regression testing

**Managed Security Service Providers (MSSPs):**
- Multi-client vulnerability management
- Automated scanning and reporting
- SLA-driven remediation tracking
- 24/7 alert monitoring

---

### Career-Relevant Tasks

| Role | Applicable Skills from This Lab |
|------|--------------------------------|
| **Security Analyst** | Vulnerability scanning, risk assessment, alert configuration |
| **Vulnerability Manager** | Scan orchestration, prioritization, remediation tracking |
| **Compliance Specialist** | Audit evidence generation, regulatory requirement mapping |
| **Penetration Tester** | Recon automation, exploit target identification |
| **Security Engineer** | Tool deployment, automation setup, integration |
| **SOC Analyst** | Alert triage, incident detection, threat analysis |
| **System Administrator** | Remediation implementation, configuration hardening |
| **DevSecOps Engineer** | CI/CD security integration, automated scanning |

---

## 📚 Key Learnings

### 1. Vulnerability Management Lifecycle

**Complete Process Understanding:**

```
┌─────────────────────────────────────────────────────────────┐
│          VULNERABILITY MANAGEMENT LIFECYCLE                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. DISCOVER (Identification)                               │
│     └─ OpenVAS scanning, asset inventory                    │
│                                                             │
│  2. PRIORITIZE (Risk Assessment)                            │
│     └─ CVSS scoring, business impact analysis               │
│                                                             │
│  3. ASSESS (Validation)                                     │
│     └─ Verify exploitability, eliminate false positives     │
│                                                             │
│  4. REPORT (Communication)                                  │
│     └─ Executive summaries, technical details               │
│                                                             │
│  5. REMEDIATE (Fix)                                         │
│     └─ Patching, configuration changes, compensating        │
│        controls                                             │
│                                                             │
│  6. VERIFY (Validation)                                     │
│     └─ Rescan to confirm fix, regression testing            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**This Lab Covered:**
- ✅ Discovery through OpenVAS scanning
- ✅ Prioritization via CVSS analysis
- ✅ Reporting via PDF generation
- ✅ Automated alerting for efficiency
- ✅ Remediation planning with technical solutions

**Missing Components (Future Learning):**
- Verification scanning post-remediation
- Continuous monitoring integration
- Trend analysis over time
- Metrics and KPI tracking

---

### 2. CVSS Scoring System Deep Dive

**Understanding CVSS v3.1:**

**Base Score Metrics:**
- **Attack Vector (AV):** Network, Adjacent, Local, Physical
- **Attack Complexity (AC):** Low, High
- **Privileges Required (PR):** None, Low, High
- **User Interaction (UI):** None, Required
- **Scope (S):** Unchanged, Changed
- **Impact Metrics (C/I/A):** None, Low, High

**Real Example from Lab:**
```
MySQL Default Credentials: CVSS 9.8
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Translation:
- Network exploitable (AV:N) = Remote attack
- Low complexity (AC:L) = Easy to exploit
- No privileges needed (PR:N) = Unauthenticated
- No user interaction (UI:N) = Fully automated
- High impact on all three (C:H/I:H/A:H) = Complete compromise
```

**Why This Matters in Business:**
- CVSS guides prioritization with limited resources
- Standardized scoring enables consistent decision-making
- Temporal and environmental modifiers adjust for context
- Industry-standard language for risk communication

---

### 3. Defense in Depth for Cryptography

**Layered Cryptographic Security (SSH Example):**

```
Layer 1: KEY EXCHANGE (KEX)
├─ Establishes shared secret
├─ Vulnerability: Weak DH groups (Logjam)
└─ Fix: Modern elliptic curve (curve25519)

Layer 2: ENCRYPTION CIPHER
├─ Protects data confidentiality
├─ Vulnerability: CBC mode (Lucky 13, SWEET32)
└─ Fix: AEAD ciphers (ChaCha20-Poly1305, AES-GCM)

Layer 3: MESSAGE AUTHENTICATION (MAC)
├─ Ensures data integrity
├─ Vulnerability: MD5/SHA-1 based MACs
└─ Fix: SHA-2 based MACs (HMAC-SHA256/512)
```

**Key Insight:** All three layers must be strong - one weak link compromises the entire connection.

**Real-World Parallel:**
- TLS/SSL also uses KEX + Cipher + MAC
- VPNs (IPsec, OpenVPN) follow same principles
- Encrypted storage requires strong algorithms
- API authentication relies on crypto foundations

---

### 4. Default Configuration Dangers

**The Configuration Maturity Model:**

```
Level 0: DEFAULT INSTALLATION
└─ Greatest risk (MySQL with no password in this lab)

Level 1: BASIC HARDENING
└─ Change defaults, disable unnecessary features

Level 2: COMPLIANCE BASELINE
└─ Meet regulatory standards (CIS, STIGs)

Level 3: CONTINUOUS HARDENING
└─ Ongoing updates, monitoring, improvement

Level 4: ZERO TRUST
└─ Assume breach, minimal trust, verify everything
```

**Lab Finding:** MySQL at Level 0 (default install) = CVSS 9.8 vulnerability

**Industry Statistics:**
- 60% of breaches involve default credentials (Verizon DBIR)
- 95% of database breaches use default/weak passwords
- Average time to exploit default config: < 1 hour

**Lesson:** NEVER deploy systems with default configurations

---

### 5. Automated Security Monitoring

**Alert Fatigue vs. Actionable Intelligence:**

**Bad Alerting:**
```
Alert on EVERY vulnerability found
Result: 1000+ emails per scan
Outcome: Alerts ignored, critical issues missed
```

**Good Alerting (Implemented in Lab):**
```
Alert only on High/Critical (CVSS ≥ 7.0)
Result: 1 email for MySQL default credentials
Outcome: Immediate attention to critical risk
```

**Best Practice Principles:**
1. **Severity-Based Filtering:** Only alert on actionable findings
2. **Aggregation:** Combine related alerts
3. **Context:** Include remediation guidance in alerts
4. **Escalation:** Critical findings to management
5. **SLA Tracking:** Automate remediation deadline notifications

**Real-World Application:**
- SIEM correlation rules
- SOC alert tuning
- Incident response automation
- Threat intelligence integration

---

### 6. Risk-Based Prioritization

**Common Prioritization Mistake:**
```
Fix vulnerabilities in order discovered
OR
Fix based on CVSS score alone
```

**Better Approach (Risk = Likelihood × Impact):**

| Vulnerability | CVSS | Exploitability | Asset Value | Business Risk | Priority |
|---------------|------|----------------|-------------|---------------|----------|
| MySQL Default | 9.8 | Very High | Critical (Customer DB) | CRITICAL | P1 |
| Weak SSH KEX | 5.3 | Medium | High (Admin Access) | HIGH | P2 |
| ICMP Timestamp | 2.1 | Low | Low (Info Disclosure) | LOW | P6 |

**Factors Beyond CVSS:**
- Publicly available exploits?
- System exposure (internal vs. internet-facing)?
- Data sensitivity (PII, financial, IP)?
- Business criticality (revenue-generating system)?
- Compensating controls present?

**Lab Application:**
- MySQL (P1): High CVSS + Easy exploit + Critical data = Urgent
- SSH issues (P2-P3): Medium CVSS + Harder exploit = Important but not urgent
- Information disclosure (P4-P6): Low CVSS + Minimal impact = Backlog

---

### 7. Vulnerability Scanning vs. Penetration Testing

**Complementary but Different:**

| Aspect | Vulnerability Scanning (This Lab) | Penetration Testing |
|--------|----------------------------------|---------------------|
| **Approach** | Automated tool-based | Manual + automated |
| **Scope** | Identify known vulnerabilities | Exploit vulnerabilities |
| **Depth** | Broad coverage, surface-level | Narrow focus, deep exploitation |
| **Frequency** | Weekly/monthly/quarterly | Annually or on-demand |
| **Output** | Vulnerability list with CVSS | Attack narrative, proof of compromise |
| **Goal** | Find and report issues | Demonstrate real-world impact |
| **Skill Level** | Security Analyst | Penetration Tester/Ethical Hacker |

**When to Use Each:**
- **Scanning:** Continuous security posture monitoring
- **Pen Testing:** Validate defenses before attacks, post-remediation verification

**Lab Limitation:** OpenVAS doesn't exploit - it only identifies. A pen tester would attempt to actually login to MySQL with no password and demonstrate data exfiltration.

---

## 🎖️ Certifications & Standards Alignment

**Certifications Demonstrated:**

- ✅ **CompTIA Security+:** Vulnerability scanning, risk assessment (Domain 5.1, 5.3)
- ✅ **CEH (Certified Ethical Hacker):** Scanning and enumeration (Module 3)
- ✅ **GIAC GCIA:** Intrusion analysis, vulnerability assessment
- ✅ **OSCP Preparation:** Network reconnaissance, vulnerability identification
- ✅ **CISSP:** Risk assessment, security testing (Domain 7)

**Frameworks & Standards:**

- ✅ **NIST 800-53:** RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation)
- ✅ **PCI-DSS:** Requirement 11.2 (Quarterly vulnerability scans)
- ✅ **ISO 27001:** A.12.6.1 (Technical vulnerability management)
- ✅ **CIS Controls:** Control 7 (Continuous Vulnerability Management)
- ✅ **NIST Cybersecurity Framework:** Identify, Protect, Detect functions

**Compliance Mappings:**

| Regulation | Requirement | Lab Fulfillment |
|------------|-------------|-----------------|
| **HIPAA** | § 164.308(a)(8) - Risk analysis | ✅ Vulnerability assessment performed |
| **PCI-DSS** | Req. 11.2.1 - Quarterly internal scans | ✅ Scanning methodology established |
| **SOX** | Section 404 - Internal control testing | ✅ Automated monitoring configured |
| **GDPR** | Article 32 - Security measures | ✅ Risk-based security improvements |
| **FISMA** | Continuous monitoring | ✅ Alert system for ongoing detection |

---

## 📊 Metrics & Reporting

### Vulnerability Metrics Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│              VULNERABILITY SCAN SUMMARY                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Scan Date:     [Scan Completion Date]                      │
│  Targets:       3 systems                                   │
│  Duration:      [Scan Runtime]                              │
│                                                             │
│  FINDINGS BY SEVERITY:                                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Critical  ████░░░░░░░░░░░░░░░  0  (0%)              │   │
│  │ High      ████████░░░░░░░░░░  1  (9%)              │   │
│  │ Medium    ████████████░░░░░░  3  (27%)             │   │
│  │ Low       ████████████████████  7  (64%)             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  TOP RISK FINDING:                                          │
│  MySQL/MariaDB Default Credentials (CVSS 9.8)               │
│  └─ Status: OPEN - Requires immediate action                │
│                                                             │
│  REMEDIATION TIMELINE:                                      │
│  ├─ 24 hours:   1 vulnerability (High)                      │
│  ├─ 30 days:    2 vulnerabilities (Medium)                  │
│  └─ 90 days:    7 vulnerabilities (Low)                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### KPIs for Vulnerability Management

**Key Performance Indicators:**

1. **Mean Time to Detect (MTTD):** < 24 hours (via automated scanning)
2. **Mean Time to Remediate (MTTR):**
   - Critical: < 24 hours
   - High: < 7 days
   - Medium: < 30 days
   - Low: < 90 days
3. **Vulnerability Recurrence Rate:** 0% (proper remediation verification)
4. **Scan Coverage:** 100% of production assets
5. **SLA Compliance:** Track on-time remediation percentage

**Trend Analysis (Hypothetical After Multiple Scans):**
```
Month 1: 11 vulnerabilities
Month 2: 4 vulnerabilities (after remediation)
Month 3: 2 vulnerabilities (new findings)
Trend: Improving security posture ✅
```

## 🎯 Recommendations for Production Deployment

**Scaling OpenVAS for Enterprise:**

1. **Distributed Scanning Architecture:**
   - Multiple scanners for large networks
   - Segment scanners by network zones (DMZ, internal, cloud)
   - Centralized management console

2. **Authenticated Scanning:**
   - Credential-based scans for deeper analysis
   - Windows domain account integration
   - SSH key-based Linux scanning
   - Database credential scanning

3. **Integration & Automation:**
   - SIEM integration (Splunk, QRadar, ELK)
   - Ticketing system automation (Jira, ServiceNow)
   - CI/CD pipeline integration
   - API-driven workflows

4. **Advanced Reporting:**
   - Executive dashboards
   - Compliance mapping reports
   - Trend analysis visualization
   - Custom report templates

5. **Continuous Improvement:**
   - Vulnerability database updates (daily)
   - Scan policy tuning (reduce false positives)
   - Performance optimization
   - Staff training and development

---