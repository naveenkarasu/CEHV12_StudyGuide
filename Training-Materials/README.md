# CEH v12 Training Material

## Overview

This repository contains comprehensive training materials for the Certified Ethical Hacker (CEH) v12 exam. It combines theoretical knowledge and practical exercises to prepare you for the certification.

## Modules Overview

1.  [**Introduction to Ethical Hacking**](module_01)
2.  [**Footprinting and Reconnaissance**](module_02)
3.  [**Scanning Networks**](module_03)
4.  [**Enumeration**](module_04)
5.  [**Vulnerability Analysis**](module_05)
6.  [**System Hacking**](module_06)
7.  [**Malware Threats**](module_07)
8.  [**Sniffing**](module_08)
9.  [**Social Engineering**](module_09)
10. [**Denial-of-Service**](module_10)
11. [**Session Hijacking**](module_11)
12. [**Evading IDS, Firewalls, and Honeypots**](module_12)
13. [**Hacking Web Servers**](module_13)
14. [**Hacking Web Applications**](module_14)
15. [**SQL Injection**](module_15)
16. [**Hacking Wireless Networks**(module_16)]
17. [**Hacking Mobile Platforms**](module_17)
18. [**IoT and OT Hacking**](module_18)
19. [**Cloud Computing**](module_19)
20. [**Cryptography**](module_20)

## Detailed Instructions

### 1. Reconnaissance and Footprinting

**Objective:** Gather information about your target using various tools and techniques.

**Tools:**
- WHOIS
- Nslookup
- Fierce
- Maltego

**Steps:**
1. **WHOIS Lookup:**  
   Command: `whois example.com`  
   Document the findings.

2. **DNS Enumeration:**  
   Commands: `nslookup example.com` or `dig example.com`  
   List all subdomains and IP addresses.

3. **Network Mapping:**  
   Command: `fierce -dns example.com`  
   Create a network map.

4. **Using Maltego:**  
   Document the findings and prepare a report.

### 2. Scanning and Enumeration

**Objective:** Identify live systems, open ports, and services running on the target.

**Tools:**
- Nmap
- Netcat

**Steps:**
1. **Network Scanning with Nmap:**  
   Command: `nmap -sP 192.168.1.0/24`  
   Document live hosts.

2. **Port Scanning:**  
   Command: `nmap -sV -p 1-65535 192.168.1.1`  
   List open ports and services.

3. **Service Enumeration:**  
   Command: `nc -v 192.168.1.1 80`  
   Document service banners.

### 3. Vulnerability Analysis

**Objective:** Perform vulnerability assessments to identify potential weaknesses.

**Tools:**
- Nessus
- OpenVAS

**Steps:**
1. **Nessus Vulnerability Scan:**  
   Install and configure Nessus.  
   Run the scan and document vulnerabilities.

2. **OpenVAS Scan:**  
   Install and configure OpenVAS.  
   Perform a comprehensive scan and document vulnerabilities.

3. **Manual Verification:**  
   Use `Metasploit` to verify vulnerabilities.  
   Document the verification process.

### 4. System Hacking

**Objective:** Gain unauthorized access to systems.

**Tools:**
- John the Ripper
- Hashcat
- Metasploit

**Steps:**
1. **Password Cracking:**  
   Commands: `john --wordlist=/path/to/wordlist.txt hashfile` or `hashcat -a 0 -m 0 hashfile /path/to/wordlist.txt`  
   Document cracked passwords.

2. **Privilege Escalation:**  
   Commands: `use exploit/windows/local/bypassuac` and `set SESSION <session_id>`  
   Document the escalation process.

3. **Maintaining Access:**  
   Commands: `use exploit/multi/handler` and `set PAYLOAD windows/meterpreter/reverse_tcp`  
   Document the backdoor installation.

## Best Practices

- **Set Up a Lab Environment:** Use virtual machines for a safe and controlled environment.
- **Document Everything:** Keep detailed notes of your methods, tools, and results.
- **Stay Updated:** Keep yourself updated with the latest tools, techniques, and best practices.


Happy Hacking!

