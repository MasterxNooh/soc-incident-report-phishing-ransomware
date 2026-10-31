# Incident Report: PHI-2026-10-31-01
**Incident Title:** Phishing Email Leading to Ransomware Infection
**Date of Report:** October 31, 2026
**Analyst:** Nooh Abdul Ghaffar
**Severity:** High (Localized)
**Status:** Resolved (Contained & Eradicated)

---

## 1. Executive Summary
On October 31, 2026, at 09:15 AM, the SOC detected a ransomware infection on a corporate workstation belonging to the Finance department. The infection was initiated via a phishing email containing a malicious Excel document. The malware encrypted local files and attempted to establish command-and-control (C2) communication. 

The Security Operations Center (SOC) responded immediately, isolating the affected host from the network and disabling the compromised user account. Because of rapid detection and containment, the encryption was limited to a single endpoint, and no data exfiltration was observed. The host was successfully reimaged, and the user was re-educated on phishing risks.

## 2. Incident Details
- **Incident ID:** PHI-2026-10-31-01
- **Detection Source:** Endpoint Detection and Response (EDR) Alert - "Ransomware Behavior Detected"
- **Affected Asset:** `FIN-WS-042` (Windows 11 Workstation)
- **Affected User:** `j.doe@company.local`
- **Threat Actor:** Suspected FIN7 or affiliated ransomware affiliate.
- **MITRE ATT&CK Techniques:** 
    - T1566.001 (Spearphishing Attachment)
    - T1204.002 (User Execution: Malicious File)
    - T1486 (Data Encrypted for Impact)

## 3. Investigation Timeline (UTC)
| Time | Event | Data Source |
| :--- | :--- | :--- |
| 09:12 | User `j.doe` receives email from `billing@invoices-secure[.]com` with attachment `Invoice_Q3.xlsm`. | Email Gateway |
| 09:14 | User opens the Excel file, enabling macros. | Windows Event Log (Sysmon) |
| 09:15 | EDR alerts on suspicious process `rundll32.exe` spawned by `excel.exe`. | EDR |
| 09:15 | EDR blocks execution and quarantines the file. SOC receives alert. | EDR |
| 09:18 | SOC Analyst isolates `FIN-WS-042` from the network. | EDR Console |
| 09:22 | SOC Analyst disables user account `j.doe`. | Active Directory |
| 09:30 | SOC Analyst begins investigation, checks for lateral movement. | SIEM |
| 10:15 | Malware analysis confirms ransomware behavior (file encryption attempts). | Sandbox |
| 11:00 | Host reimaged from clean baseline. User account re-enabled with MFA reset. | IT Support |

## 4. Technical Analysis & Findings

### 4.1 Initial Access (T1566.001)
The user received a phishing email masquerading as an invoice. The attachment was a macro-enabled Excel file (`.xlsm`).

### 4.2 Execution (T1204.002)
When opened, the document prompted the user to "Enable Content" to view the invoice. Doing so executed a malicious VBA macro.

### 4.3 Defense Evasion & Execution
The macro executed `rundll32.exe` to run a hidden payload. The EDR immediately flagged this behavior as malicious.

### 4.4 Indicators of Compromise (IOCs)
| Type | Value | Description |
| :--- | :--- | :--- |
| SHA256 | `3f7b...e8a2` | Malicious Excel Document (`Invoice_Q3.xlsm`) |
| IP | `192.0.2.45` | C2 Server (Attempted connection, blocked) |
| Domain | `invoices-secure[.]com` | Sender Domain (Spoofed) |
| File | `C:\Users\Public\svchost.exe` | Dropped Malware Payload |

*Full IOC list available in `evidence/iocs.csv`.*

## 5. Response Actions
- **Containment:** The host `FIN-WS-042` was isolated via EDR at 09:18 UTC. The user account was disabled at 09:22 UTC to prevent lateral movement.
- **Eradication:** The malicious files were quarantined by EDR. The host was wiped and reimaged from a clean baseline.
- **Recovery:** The user account was re-enabled after a password reset and MFA re-registration. The user was contacted and briefed.

## 6. Business Impact
- **Operational:** Minimal. One employee was offline for approximately 2 hours.
- **Data Loss:** No confirmed data loss or exfiltration. The malware attempted to encrypt files, but EDR blocked the full encryption process.
- **Financial/Legal:** No regulatory impact. No ransom was paid.

## 7. Recommendations
### Immediate (24 hours)
- Block the sender domain `invoices-secure[.]com` on the email gateway.
- Block the C2 IP `192.0.2.45` on the perimeter firewall.
- Add the file hash to the EDR blocklist.

### Short-Term (1-4 weeks)
- Review email filtering rules to catch similar invoice-themed phishing.
- Enforce macro-blocking policy for documents from the internet via Group Policy.

### Long-Term (1-6 months)
- Conduct organization-wide phishing awareness training focusing on macro-enabled documents.
- Implement application allowlisting (AppLocker) on all endpoints.

## 8. Lessons Learned
- **What went well:** EDR detection was rapid, and SOC response was fast. The isolation procedure worked perfectly.
- **What could be improved:** The user was not aware of the risks of enabling macros in downloaded documents. Additional training is required.

---
**Appendix:** 
- `evidence/iocs.csv` (List of IOCs)
- `evidence/sysmon_logs.txt` (Redacted process creation logs)
