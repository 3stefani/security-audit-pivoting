# 🌐 Language / Idioma

[![en](https://img.shields.io/badge/lang-English-blue.svg)](README.md)
[![es](https://img.shields.io/badge/lang-Español-red.svg)](README.es.md)

---

# Security Audit - Web Pentesting and Network Pivoting

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-blue)](https://owasp.org/Top10/)
[![Metasploit](https://img.shields.io/badge/Metasploit-Framework-red)](https://www.metasploit.com/)

## Project Description

Comprehensive security audit demonstration project featuring web application pentesting and advanced pivoting techniques for internal network access. The project simulates a real-world multi-phase attack scenario against a segmented infrastructure.

**⚠️ This project is for educational purposes only and must be executed exclusively in controlled environments with explicit authorization.**

## Objectives

- Demonstrate common vulnerabilities from **OWASP Top 10 2021**
- Illustrate **lateral movement** techniques through pivoting
- Document **professional pentesting** methodology
- Provide exploitation and remediation **evidence**

## Lab Architecture
```
┌─────────────────┐
│   Kali Linux    │ 192.168.0.30
│   (Attacker)    │
└────────┬────────┘
         │ Bridged Network
         │
┌────────▼────────────────┐
│ Ubuntu Mutillidae       │
│ DMZ:  192.168.0.21      │
│ INT:  192.168.8.131     │
│ (Web Server)            │
└────────┬────────────────┘
         │ Host-Only Network
         │
┌────────▼────────────────┐
│  Metasploitable         │
│  192.168.8.133          │
│  (Internal Server)      │
└─────────────────────────┘
```

### Technical Specifications

| Machine | Operating System | Interfaces | IP |
|---------|------------------|------------|-----|
| **Kali Linux** | Kali Linux 2024.x | eth0 | 192.168.0.30 |
| **Ubuntu Mutillidae** | Ubuntu Server 20.04 | ens33 (Bridge)<br>ens37 (Host-Only) | 192.168.0.21<br>192.168.8.131 |
| **Metasploitable** | Ubuntu 8.04 (Metasploitable 2) | eth0 (Host-Only) | 192.168.8.133 |

## Tools Used

### Reconnaissance and Analysis
- **Burp Suite Community** - Intercepting proxy and web analysis
- **Skipfish** - Web application security scanner
- **Nmap** - Network mapper and port scanner

### Exploitation
- **Metasploit Framework** - Exploitation platform
- **Meterpreter** - Advanced post-exploitation payload
- **SQLMap** - Automated SQL Injection tool (optional)

### Post-Exploitation
- **John the Ripper** - Password cracker
- **Python** - Scripting and HTTP server
- **Hashcat** - Advanced password recovery

## Identified Vulnerabilities

### 🔴 Critical (CVSS 9.0-10.0)

| Vulnerability | CVSS | Impact |
|---------------|------|--------|
| **SQL Injection** | 9.8 | Full database extraction, authentication bypass |
| **Remote Code Execution** | 10.0 | Complete web server control |
| **Samba Exploit (Pivoting)** | 9.6 | Root access to internal network |

### 🟠 High (CVSS 7.0-8.9)

| Vulnerability | CVSS | Impact |
|---------------|------|--------|
| **Path Traversal** | 7.5 | Sensitive file reading |
| **Broken Authentication** | 8.1 | Unrestricted brute force |

### 🟡 Medium (CVSS 4.0-6.9)

| Vulnerability | CVSS | Impact |
|---------------|------|--------|
| **Security Misconfiguration** | 5.3 | Information disclosure |
| **Cryptographic Failures** | 6.5 | Plaintext passwords |

## Complete Attack Chain
```
┌─────────────────────────────────────────────────────────┐
│              PHASE 1: RECONNAISSANCE                     │
├─────────────────────────────────────────────────────────┤
│ • Burp Suite → Web application mapping                  │
│ • Skipfish → Automated scanning                         │
│ • Attack vector identification                          │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│             PHASE 2: WEB EXPLOITATION                    │
├─────────────────────────────────────────────────────────┤
│ • SQL Injection → 26 users compromised                  │
│ • Webshell Upload → RCE as www-data                     │
│ • Path Traversal → /etc/passwd reading                  │
│ • Burp Intruder → Credential brute force                │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│           PHASE 3: POST-EXPLOITATION                     │
├─────────────────────────────────────────────────────────┤
│ • ip addr show → 192.168.8.0/24 network discovery       │
│ • ping sweep → Host 192.168.8.133 identified            │
│ • Persistence → SSH user created                        │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│                  PHASE 4: PIVOTING                       │
├─────────────────────────────────────────────────────────┤
│ • msfvenom → Meterpreter payload generated              │
│ • Meterpreter session established                       │
│ • autoroute → Internal network tunnel configured        │
│ • Port scan → Vulnerable services identified            │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│        PHASE 5: INTERNAL NETWORK EXPLOITATION            │
├─────────────────────────────────────────────────────────┤
│ • Samba usermap_script (CVE-2007-2447)                  │
│ • Root shell obtained                                   │
│ • /etc/shadow extracted                                 │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│        PHASE 6: ADVANCED POST-EXPLOITATION               │
├─────────────────────────────────────────────────────────┤
│ • John the Ripper → 3 passwords cracked                 │
│ • Complete system enumeration                           │
│ • Root access documentation                             │
└─────────────────────────────────────────────────────────┘
```

## Repository Structure
```text
pentesting-web-pivoting/
│
├── README.md                          # Spanish version
├── README.es.md                       # English version
│
├── documentation/
│   ├── executive-report.pdf            # Full report in English
│   ├── informe-ejecutivo.pdf           # Full report in Spanish
│   ├── methodology.es.md               # Detailed methodology in Spanish
│   └── methodology.md                  # Detailed methodology in English
│
└── img/                                # Images of the process
```

## Compromised Credentials

### Web Server (Mutillidae) - SQL Injection

**Total: 26 users with plaintext passwords**
```
admin:admin
john:monkey
jeremy:password
bryce:password
ed:pentest
samurai:samurai
jim:password
pablo:letmein
dave:password
adrian:somepassword
[... +16 usuarios adicionales]
```
### Internal Server (Metasploitable) - Password Cracking

**MD5 hashes cracked with John the Ripper:**
```
✅ klog:123456789
✅ sys:batman
✅ service:service

❌ root: No crackeado (no en rockyou.txt)
❌ msfadmin: No crackeado
❌ user: No crackeado
❌ postgres: No crackeado
```
## Key Results

| Metric | Result |
|--------|--------|
| **Critical Vulnerabilities** | 3 |
| **High Vulnerabilities** | 2 |
| **Medium Vulnerabilities** | 2 |
| **Compromised Users** | 26 |
| **Cracked Passwords** | 3 |
| **Compromised Systems** | 2/2 (100%) |
| **Root Access Obtained** | ✅ Yes |
| **Total Attack Time** | ~4 hours |

## Remediation Recommendations

### 🔴 CRITICAL Priority (0-7 days)

1. **Implement Prepared Statements**
```php
// ❌ VULNERABLE
$query = "SELECT * FROM users WHERE username='$username'";

// ✅ SECURE
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
```

2. **Patch Samba** (CVE-2007-2447)
```bash
sudo apt-get update && sudo apt-get upgrade samba
```

3. **Network segmentation with firewall**
```bash
# Block DMZ → Internal Network traffic by default
iptables -A FORWARD -i ens33 -o ens37 -j DROP
# Allow only specific authorized traffic
iptables -A FORWARD -i ens33 -o ens37 -p tcp --dport 443 -j ACCEPT
```

### 🟠 HIGH Priority (1-4 weeks)

4. **Implement WAF**
5. **Rate Limiting and CAPTCHA**
6. **Hash passwords with bcrypt**

### 🟡 MEDIUM Priority (1-3 months)

7. **Implement IDS/IPS**
8. **SIEM for event correlation**
9. **Secure Coding training**
10. **Regular pentesting**

## Lessons Learned

### One vulnerability = Total compromise

**SQL Injection** → **Webshell** → **Pivoting** → **Internal network compromised**

### Segmentation without firewall is useless

Separating networks (DMZ / Internal) **is not enough** without active firewall controls.

### Defense in Depth is essential

Multiple security layers are required for effective protection.

### Detection is as important as prevention

Without active monitoring, the entire attack went **completely undetected**.

## How to Reproduce this Lab

### Prerequisites

- VMware Workstation / VirtualBox
- 16GB RAM minimum
- 100GB disk space
- Basic knowledge of networking and Linux

### Installation

1. **Download images:**
   - [Kali Linux](https://www.kali.org/get-kali/)
   - [Metasploitable 2](https://sourceforge.net/projects/metasploitable/)
   - Ubuntu Server 20.04 + [Mutillidae](https://github.com/webpwnized/mutillidae)

2. **Configure networks:**
```
Kali:          eth0 → Bridge
Ubuntu:        ens33 → Bridge
               ens37 → Host-Only (VMnet1)
Metasploitable: eth0 → Host-Only (VMnet1)
```

3. **Follow detailed guide:** [lab-setup.md](resources/lab-setup.md) (SOON)

## References and Resources

### Official Documentation
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

### Exploited CVEs
- [CVE-2007-2447](https://nvd.nist.gov/vuln/detail/CVE-2007-2447) - Samba usermap script

### Tools
- [CVSS Calculator 4.0](https://www.first.org/cvss/calculator/4.0)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- 
## Author

**Estefanía Ramírez Martínez**

Junior Pentester | eJPT Certified | Cybersecurity Enthusiast

- Email: estefania.rammar@gmail.com
- LinkedIn: [linkedin.com/in/estefania-ramirez-martinez](https://linkedin.com/in/estefaniazerimar/)
- GitHub: [@estefaniaramirez](https://github.com/3stefani)
- Blog: [diariohacking.com](https://diariohacking.com)
- Certificaciones: eJPT (Junior Penetration Tester)

## License

Copyright (c) 2026 Estefanía Ramírez Martínez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
## ⚠️ Legal Disclaimer

**IMPORTANT: This project is for educational and security research purposes only.**

- ✅ **Allowed:** Use in controlled environments and personal labs
- ✅ **Allowed:** Pentesting with explicit written authorization
- ❌ **Prohibited:** Use against systems without authorization
- ❌ **Prohibited:** Illegal or malicious activities

The author is **NOT responsible** for misuse of the information or tools presented in this repository. Unauthorized access to computer systems is **illegal** in most jurisdictions.

**Always act ethically and legally. #EthicalHacking**

---

## Acknowledgments

- **OWASP** for providing invaluable web security resources
- **Metasploit Team** for the excellent pentesting platform
- **Mutillaide Project** for the educational vulnerability application
- **Offensive Security** for the pentesting methodology
- **InfoSec Community** for freely sharing knowledge

---

*Last updated: January 2026*
