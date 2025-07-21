# FindDomianShare
![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Language: Python](https://img.shields.io/badge/Language-Python-blue)
![Platform: Cross-Platform](https://img.shields.io/badge/Platform-Cross--Platform-green)
![Status: Active](https://img.shields.io/badge/Status-Active-brightgreen)
![Purpose: Red/Blue Team](https://img.shields.io/badge/Purpose-Red%20%2F%20Blue%20Team-orange)

A powerful, modular, and multi-threaded Python tool to **enumerate and assess SMB shares across an entire Active Directory domain**, built for **penetration testers**, **red teamers**, and **cybersecurity professionals**.

This script leverages **Impacket**, **LDAP**, and **SMB** to identify computers in the domain and list available network shares with optional read/write and admin access testing.

## Key Features
- 🔍 Domain-wide scanning: Query AD for all computers and scan each one
- ⚡ Parallel processing: Multi-threaded scanning for fast results
- 🛡️ Access validation: Check read/write permissions on discovered shares
- 👑 Admin detection: Identify computers where current user has local admin rights
- 📊 Multiple output formats: Console, JSON, and CSV output options
- 🚫 Smart filtering: Skip default shares and filter computers by name
- 🔁 Robust retry logic: Automatic retries with configurable delays
- 🔧 Flexible authentication: Support for NTLM, Kerberos, and AES keys

## 🛠️ Requirements

- Python 3.8+
- [Impacket](https://github.com/fortra/impacket)
- `tqdm`

## 🧪 Usage
`-k` flag and access to the DC host are MANDATORY conditions.
```
Python3 FindDomianShare.py [domain/]username[:password]@<target> [options]
```
### 🔐 Authentication Options
Option	Description
| Option                  | Description                                                |
| ----------------------- | ---------------------------------------------------------- |
| `-hashes LMHASH:NTHASH` | Authenticate using NTLM hashes                             |
| `-aesKey HEXKEY`        | Use AES key for Kerberos authentication                    |
| `-k`                    | Use Kerberos authentication (from ccache if available)     |
| `-no-pass`              | Don't prompt for password (useful with Kerberos or hashes) |

### 🧾 Common Options
Option	Description
| Option                 | Description                                  |
| ---------------------- | -------------------------------------------- |
| `-check-access`        | Check for read/write access to each share    |
| `-check-admin`         | Check for local admin rights on each host    |
| `-skip-default`        | Skip ADMIN\$, C\$, IPC\$, PRINT\$ shares     |
| `-computer-name REGEX` | Filter computers by name or FQDN using regex |
| `-threads N`           | Number of threads to use (default: 10)       |
| `-retries N`           | Retry count on failure (default: 1)          |
| `-retry-delay SECONDS` | Delay between retries (default: 2)           |
| `-output FORMAT`       | Output format: console, json, csv, or all    |
| `-output-file NAME`    | Base filename for output files               |
| `-base-dn DN`          | Custom base DN for LDAP search               |
| `-dc-ip IP`            | IP of domain controller                      |
| `-dc-host HOSTNAME`    | Hostname of domain controller                |
| `-debug`               | Enable debug logging                         |
| `-ts`                  | Add timestamp to log output                  |

### 🧷 Examples
Basic enumeration
```
Python3 FindDomianShare.py corp.local/user@dc.corp.local -k
```
With Kerberos from ticket cache
```
KRB5CCNAME=tgt.ccache Python3 FindDomianShare.py corp.local/user@dc.corp.local -k -no-pass
```
Export to JSON and CSV, skip default shares
```
Python3 FindDomianShare.py corp.local/user@dc.corp.local -k \
  -check-access -check-admin -skip-default -output all
```
📤 Output

Results can be viewed directly in the terminal or exported to:
```
    domain_shares_<timestamp>.json

    domain_shares_<timestamp>.csv
```
Sample console output:
```
Found 247 shares:
--------------------------------------------------------------------------------
Computer            Share        Type                Admin  Read  Write  OS              Remark
--------------------------------------------------------------------------------
SRV-FILE01          Documents    Disk (Hidden)       Yes    Yes   Yes    Windows Server  Department Documents
SRV-APP02           Data         Disk                No     Yes   No     Windows Server  Application Data
HR-WORKSTATION01    C$           Disk (Hidden)       No     No    No     Windows 10      Default share
```
Sample json output:
```json
[
  {
    "ComputerName": "SRV-FILE01",
    "Name": "Documents",
    "TypeName": "Disk (Hidden)",
    "Remark": "Department Documents",
    "OperatingSystem": "Windows Server",
    "IsAdmin": true,
    "ReadAccess": true,
    "WriteAccess": true
  }
]
```
Sample csv output:
```
ComputerName,Name,TypeName,Remark,OperatingSystem,IsAdmin,ReadAccess,WriteAccess
SRV-FILE01,Documents,Disk (Hidden),Department Documents,Windows Server,True,True,True
```


## ⚠️ Legal & Ethical Notice
![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)

This tool is released under the GNU General Public License v3.0 (GPLv3). The software is provided "as is", without warranty of any kind. By using this tool, you agree to the following:

1. Authorization Requirement:
- Use only on networks and systems you own or have explicit written permission to test
- Unauthorized scanning may violate computer crime laws (CFAA, GDPR, etc.)

2. Professional Use Only:
- Intended for security professionals conducting authorized audits/assessments
- Not for malicious use or unauthorized data access

3. Compliance Responsibility:
- Users are solely responsible for ensuring compliance with all applicable laws
- Consult legal counsel before use in corporate/regulated environments

4. No Liability:
- Developers accept no liability for misuse or damages caused by this tool
- May trigger security alerts - use with caution in monitored environments

Warning: This tool actively scans network resources and may impact system performance. Use proper scheduling for production environments.

For full license terms, see [LICENSE](https://github.com/TacticalGator/FindDomianShare/blob/main/LICENSE) file. Continued use constitutes acceptance of these terms.
