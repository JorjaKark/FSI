# FSI

# CVE-2014-6271 – Shellshock Vulnerability

This document summarizes the key points of the Shellshock vulnerability (CVE-2014-6271), discovered in GNU Bash in 2014.  
It is structured according to the characterization requirements: identification, cataloging, exploits, attacks, and countermeasures.

---

## 1. Identification
- **General Description**: Critical bug in GNU Bash allowing remote code execution via specially crafted environment variables.  
- **Affected Systems**: Linux, Mac OS X, BSD, and UNIX where Bash is installed or default shell.  
- **Exploitable Services**: Web servers using CGI, OpenSSH ForceCommand, DHCP clients, and other services that pass environment variables.  
- **Severity**: CVSS score 10 (Critical); required immediate patching and vendor advisories.  

---

## 2. Cataloging
- **Discovery**: Found by Stéphane Chazelas, privately reported to Bash maintainers (September 2014).  
- **Disclosure**: Publicly revealed on 24 September 2014, causing global emergency responses.  
- **Severity**: Assigned CVSS impact score of 10 (Critical), due to ease of exploitation and remote code execution.  
- **Bug Bounty**: No financial bounty; disclosure coordinated via open-source and vendor security teams.  

---

## 3. Exploits
- **Metasploit Module**: Exploits Apache CGI to run arbitrary commands on vulnerable servers.  
- **Public PoCs**: HTTP header payloads and scanning tools (like Pyshock) enabled mass detection/exploitation.  
- **Verification**: Attackers often checked `/etc/passwd` remotely to confirm execution.  
- **Detection Tools**: IDS/IPS signatures (Snort) and DHCP checks created to block payloads.  

---

## 4. Attacks
- **Scale**: SecureWorks observed >140,000 scanning/exploitation attempts within 5 days of disclosure.  
- **Malware**: Used to install Linux DDoS tools on compromised systems.  
- **Targets**: QNAP NAS devices exploited in October 2014.  
- **Impact**: Arbitrary commands executed on internet-exposed web servers through CGI.  

---

## 5. Countermeasures
- **Official Patch**: Developed by Stéphane Chazelas and Bash maintainer Chet Ramey, released after discovery.  
- **Vendor Updates**: Red Hat, Ubuntu, Debian, Apple and others released Bash security updates.  
- **Workarounds**: Disable Bash-based CGI scripts or filter/block suspicious traffic at firewalls.  
- **Post-Patch Test**:  
  ```bash
  env x='() { :;}; echo vulnerable' bash -c "echo test"
