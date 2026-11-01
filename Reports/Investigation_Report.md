# DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) EXECUTIVE REPORT
**Case Reference:** CASE-2026-DFIR-001  
**Incident Classification:** Unauthorized Access & Sensitive Database Exfiltration  
**Severity Level:** 🔴 CRITICAL  
**Investigation Date:** 2026-11-01 22:02:35  
**Lead Investigator:** DFIR Specialist / CSRL Security Unit  

---

## 1. Executive Summary

On **07 July 2026**, the Security Operations Center (SOC) detected an advanced security compromise involving corporate VPN access and unauthorized outbound HTTPS traffic from the Finance Server (**SRV-FIN-01**, IP `10.10.15.25`). 

A multi-source forensic investigation correlating firewall access logs, Linux operating system auth logs, and VPN gateway authentication records confirmed that:
1. An external threat actor operating from IP `203.45.18.101` conducted targeted brute-force / password spraying attacks against user account `j.smith`.
2. Following five failed attempts, unauthorized VPN access was successfully established at **14:20:22 IST**.
3. Within seconds (**14:20:35 IST**), the attacker moved laterally via SSH to the Finance Server using VPN assigned tunnel IP `10.10.1.5`.
4. The adversary executed automated reconnaissance script `finance_export.sh`, dumping relational tables (`billing_details` and `transactions_2026`) from the local PostgreSQL database.
5. The extracted database records were compressed into an encrypted archive (`archive.zip`, **45.2 MB**) and exfiltrated to an external Command & Control (C2) server at IP `198.51.100.20` over HTTPS (Port 443).
6. Prior to disconnecting, the adversary attempted outbound lateral pivoting to `45.33.18.7:22`, which was actively blocked by perimeter firewall security policies.

---

## 2. Evidence Acquisition & Chain of Custody Integrity

All digital artifacts were preserved under forensic standards. Cryptographic hashes (MD5 and SHA-256) and Shannon Entropy metrics were calculated to guarantee evidence non-repudiation and detect data tampering.

| Artifact Filename | Size | MD5 Checksum | SHA-256 Checksum | Entropy Score |
| :--- | :--- | :--- | :--- | :--- |
| `email_thread.txt` | 560 B | `41b75580094ed62ad42c715a29122c11` | `848645ae2cc7e016de8f7033950daf26a2d87efae800c8ad5f5b6f5eb2644a4e` | 4.6761 (Low) |
| `firewall.log` | 1540 B | `d4ca5d3b14923ef39422110af0b75b0e` | `2b31b846737a5aaa661ba11b52cab5a8432567a27d3bea35f78907ab539ae70a` | 4.7487 (Low) |
| `incident_report.txt` | 978 B | `ff86de1b1c1793ead536a587b5de9d6c` | `c8603da8191645c2f78d428d7b0b980a2888bac6c27eb89cce409350264aba6d` | 4.9366 (Low) |
| `invoice.txt` | 518 B | `522fdf523dda7e304753cbf7c28e0e12` | `eb8bb942c434c8bbe204062961d344b52dbc429552d4bddf322b9fb2e92730f7` | 4.2292 (Low) |
| `meeting_minutes.txt` | 735 B | `927df5c4473c0da6ce05566fd8ca9795` | `61309662c920ba98661b390843fa7ea331b74e02d0aacad01f54f8e189d62290` | 4.697 (Low) |
| `phishing_email.txt` | 703 B | `1c9a8de1edf0070128e312acf4418382` | `7f8820052250c84aee3486a00e89297c63d115dd7faa6d5e08df0e92cc8c8f0e` | 4.5621 (Low) |
| `ransomware_note.txt` | 615 B | `17b929ac174b92d67ed695d511ee0ee9` | `6959858bb313305cf293f24ec62ed79b040814ad2ab1010c402d7d369e5de06d` | 4.4827 (Low) |
| `system.log` | 1557 B | `d8b61854ed22e5a81186bfa6bd57cf58` | `fd35d229a32f5fa99c30ea2389e687e0f81c7e7ba4b477b84d22aca86b522335` | 5.2263 (Medium) |
| `vpn.log` | 1442 B | `ce89dbb27edab6a9782c45d9b8c863aa` | `b7353260b4459bc516db0f7be0e225a4a072cea1906999dda83717bf9c273301` | 5.0739 (Medium) |


---

## 3. Cyber Kill Chain & Attack Chronology

The reconstructed timeline establishes the following coordinated sequence of adversary operations:

| Timestamp (IST) | Severity | Kill Chain Stage | Source | Event Description |
| :--- | :--- | :--- | :--- | :--- |
| 2026-07-07 14:18:43 | **HIGH** | Credential Access / Brute Force | VPN Gateway | VPN LOGIN FAILED for user 'j.smith' from IP 203.45.18.101 |
| 2026-07-07 14:19:11 | **HIGH** | Credential Access / Brute Force | VPN Gateway | VPN LOGIN FAILED for user 'j.smith' from IP 203.45.18.101 |
| 2026-07-07 14:19:54 | **HIGH** | Credential Access / Brute Force | VPN Gateway | VPN LOGIN FAILED for user 'j.smith' from IP 203.45.18.101 |
| 2026-07-07 14:20:22 | **CRITICAL** | Initial Access | VPN Gateway | VPN LOGIN SUCCESS for user 'j.smith' from IP 203.45.18.101 |
| 2026-07-07 14:20:35 | **HIGH** | Initial Access | System | [SRV-FIN-01] sshd[1402]: SSH login accepted for user j.smith from 10.10.1.5 |
| 2026-07-07 14:20:40 | **HIGH** | Initial Access | Firewall | Firewall ALLOW TCP from 203.45.18.101:54320 to 10.10.15.25:22 - SSH Inbound via VPN |
| 2026-07-07 14:22:17 | **CRITICAL** | Collection & Staging | System | [SRV-FIN-01] bash[1421]: finance_export.sh executed by j.smith |
| 2026-07-07 14:22:18 | **HIGH** | Collection & Staging | System | [SRV-FIN-01] postgres[1425]: query: SELECT * FROM billing_details LIMIT 10000; |
| 2026-07-07 14:22:50 | **HIGH** | Collection & Staging | System | [SRV-FIN-01] postgres[1425]: query: SELECT * FROM transactions_2026; |
| 2026-07-07 14:23:51 | **CRITICAL** | Collection & Staging | System | [SRV-FIN-01] bash[1430]: zip -r archive.zip /tmp/finance_export/ |
| 2026-07-07 14:23:52 | **CRITICAL** | Collection & Staging | System | [SRV-FIN-01] kernel: archive.zip created, size: 45.2 MB |
| 2026-07-07 14:24:12 | **CRITICAL** | Exfiltration | System | [SRV-FIN-01] curl[1445]: HTTPS connection established to 198.51.100.20 |
| 2026-07-07 14:25:00 | **HIGH** | Incident Detection | SOC Advisory | Incident IR-2026-0710: Suspected compromise of user 'j.smith' credentials and outbound HTTPS exfiltration. |
| 2026-07-07 14:31:10 | **CRITICAL** | Exfiltration | System | [SRV-FIN-01] curl[1445]: archive.zip upload completed, HTTP 200 OK |
| 2026-07-07 14:32:10 | **CRITICAL** | Exfiltration | Firewall | Firewall ALLOW TCP from 10.10.15.25:49811 to 198.51.100.20:443 - HTTPS Outbound Exfil |
| 2026-07-07 14:33:15 | **CRITICAL** | Exfiltration | Firewall | Firewall ALLOW TCP from 10.10.15.25:49812 to 198.51.100.20:443 - HTTPS Outbound Exfil |
| 2026-07-07 14:34:21 | **CRITICAL** | Exfiltration | Firewall | Firewall ALLOW TCP from 10.10.15.25:49813 to 198.51.100.20:443 - HTTPS Outbound Exfil |
| 2026-07-07 14:36:02 | **CRITICAL** | Exfiltration | Firewall | Firewall ALLOW TCP from 10.10.15.25:49814 to 198.51.100.20:443 - HTTPS Outbound Exfil |
| 2026-07-07 14:40:15 | **HIGH** | Lateral Movement / C2 | Firewall | Firewall DENY TCP from 10.10.15.25:49815 to 45.33.18.7:22 - SSH Outbound Blocked |
| 2026-07-07 14:40:15 | **HIGH** | Lateral Movement / C2 | System | [SRV-FIN-01] ssh[1512]: Connect to 45.33.18.7 port 22 failed: Connection refused |
| 2026-07-07 14:43:11 | **CRITICAL** | Exfiltration | Firewall | Firewall ALLOW TCP from 10.10.15.25:49816 to 198.51.100.20:443 - HTTPS Outbound Exfil |
| 2026-07-07 15:30:00 | **HIGH** | Incident Detection | Email Communication | SOC Manager escalates urgent alert regarding user 'j.smith' and unauthorized Finance Server outbound HTTPS connections. |


### Key Incident Milestones:
- **14:02:55 - 14:03:25**: Preliminary reconnaissance and brute-force probing against generic accounts (`admin`, `administrator`, `root`) from IP `198.51.100.5`.
- **14:18:02 - 14:19:54**: Targeted credential brute-forcing targeting employee `j.smith` from external IP `203.45.18.101` (5 consecutive failures).
- **14:20:22**: Adversary achieves successful VPN session authentication.
- **14:20:35**: SSH session accepted on `SRV-FIN-01` from VPN assigned IP `10.10.1.5`.
- **14:22:17 - 14:23:52**: Execution of `finance_export.sh`, unauthorized SQL queries dumping billing tables, and creation of `archive.zip` (45.2 MB).
- **14:24:12 - 14:31:10**: Exfiltration upload to `198.51.100.20` completed via curl HTTPS.
- **14:35:44**: Adversary closes SSH connection; attempts outbound SSH to secondary pivot IP `45.33.18.7` at 14:40:15 (blocked by firewall policy).

---

## 4. Indicators of Compromise (IOC) Analysis

The investigation identified high-fidelity threat indicators classified as follows:

| Indicator / IP | Threat Level | Strategic Role | Forensic Context |
| :--- | :--- | :--- | :--- |
| `198.51.100.20` | MALICIOUS | External C2 & Exfiltration Destination | Receives stolen corporate database archive (archive.zip 45.2 MB) via HTTPS curl upload. |
| `203.45.18.101` | MALICIOUS | Attacker Source / VPN Brute Force | Origin of 5 consecutive failed logins followed by compromised VPN session for user 'j.smith'. |
| `198.51.100.5` | SUSPICIOUS | Password Spraying Probe | Reconnaissance login attempts for admin, administrator, root. |
| `45.33.18.7` | SUSPICIOUS | Secondary C2 / Lateral Movement Target | Target of denied outbound SSH connection attempt from SRV-FIN-01. |
| `10.10.15.25` | COMPROMISED_HOST | Finance Server (SRV-FIN-01) | Internal server compromised via SSH session; database dumped and exfiltrated. |
| `10.10.1.5` | COMPROMISED_TUNNEL | VPN Assigned Tunnel IP | Internal VPN tunnel address assigned to attacker masquerading as j.smith. |


---

## 5. MITRE ATT&CK Enterprise Matrix Alignment

| Tactic | Technique ID | Technique Name | Forensic Evidence | Observed Artifact |
| :--- | :--- | :--- | :--- | :--- |
| Initial Access | `T1078.002` | **Valid Accounts: Domain Accounts** | Attacker gained entry using authenticated credentials for user 'j.smith' across the corporate VPN. | vpn.log & incident_report.txt |
| Credential Access | `T1110.001` | **Brute Force: Password Spraying** | Five failed authentication attempts recorded from IP 203.45.18.101 within 2 minutes preceding successful login. | vpn.log |
| Lateral Movement | `T1021.004` | **Remote Services: SSH** | Attacker traversed from VPN gateway (10.10.1.5) to Finance Server SRV-FIN-01 (10.10.15.25) over SSH. | system.log & firewall.log |
| Execution | `T1059.004` | **Command and Scripting Interpreter: Unix Shell** | Execution of finance_export.sh via bash session to query PostgreSQL database. | system.log |
| Collection | `T1560.001` | **Archive Collected Data: Archive via Utility** | Compression of billing details and transactions into archive.zip (45.2 MB) using zip utility. | system.log |
| Exfiltration | `T1048.002` | **Exfiltration Over Alternative Protocol: Symmetric Encrypted Non-C2 Protocol** | Stolen database archive transmitted to external IP 198.51.100.20 via HTTPS curl upload. | system.log & firewall.log |
| Command and Control | `T1571` | **Non-Standard Port / Outbound C2** | Attempted outbound connection to 45.33.18.7:22 blocked by network firewall. | firewall.log & system.log |


---

## 6. Root Cause & Impact Assessment

- **Root Cause:** Absence of Multi-Factor Authentication (MFA) and aggressive IP lockouts on the external VPN portal allowed brute-force credential stuffing.
- **Compromised User:** `j.smith` (Corporate domain account).
- **Compromised Infrastructure:** Finance Database Server (`SRV-FIN-01` / `10.10.15.25`).
- **Data Exfiltrated:** Corporate financial transactions and billing customer records (~45.2 MB compressed SQL data).
- **Business Impact:** High risk of customer data exposure, regulatory non-compliance, and proprietary business intelligence theft.

---

## 7. Immediate Containment & Incident Response Action Plan

### Immediate Containment Steps (Hours 0 - 4):
1. **Revoke Compromised Credentials:** Immediately terminate active sessions and reset credentials for account `j.smith` across Active Directory and VPN.
2. **Network Isolation:** Temporarily isolate `SRV-FIN-01` from the internal network for offline disk image preservation.
3. **Perimeter Firewall Blacklisting:** Block all inbound and outbound traffic to adversary IPs:
   - `198.51.100.20` (C2 Exfiltration Target)
   - `203.45.18.101` (Attacker VPN Ingress)
   - `45.33.18.7` (Secondary Pivot)
   - `198.51.100.5` (Probing Host)

### Eradication & Hardening (Hours 4 - 24):
1. **Mandatory MFA:** Enforce hardware token or authenticator-based Multi-Factor Authentication (MFA) on all external VPN endpoints.
2. **Account Lockout Policies:** Implement account lockout policies after 3 failed consecutive login attempts within a 15-minute window.
3. **Database Access Restriction:** Restrict direct SQL execution and database export permissions; disable interactive shell utilities (`curl`, `nc`, `zip`) for standard database users.
4. **Enhanced SIEM Detection Rules:** Implement real-time alerts for:
   - Successful VPN logins originating from outside standard geographic regions.
   - Sudden high-volume outbound data transfers (> 10 MB) from database servers to unfamiliar external IPs.

---
*Report generated automatically by the AI Cyber Forensics & Incident Response Platform.*
