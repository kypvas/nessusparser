# Nessus HTML Parser

A Python tool to parse Nessus HTML vulnerability reports and export them to CSV format for easier analysis and reporting.

## Features

- Parses Nessus HTML export files
- Extracts all vulnerability data including:
  - Plugin ID and Name
  - CVE references
  - CVSS v2.0 and v3.0 scores
  - Risk level (Critical, High, Medium, Low, Info)
  - Host IP addresses
  - Protocol and Port information
  - Synopsis, Description, and Solution
  - Plugin Output
  - Exploitability info (Metasploit, Core Impact, CANVAS)
  - See Also references
- Exports to clean CSV format for use in Excel, reporting tools, or further analysis
- Handles large scan files with multiple hosts efficiently
- Lightweight and fast - no external dependencies

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Installation

```bash
git clone git@github.com:kypvas/nessusparser.git
cd nessusparser
```

## Usage

```bash
python3 nessusparser.py --input <nessus_report.html> --output <output.csv>
```

### Example

```bash
python3 nessusparser.py --input scan_results.html --output vulnerabilities.csv
```

### Output

```
Parsing scan_results.html...
Read 24759868 characters from file
Found 5466 plugin sections
Found 152 host sections
Processed 100 vulnerabilities...
...
Extracted data for 5466 vulnerabilities
Writing 5466 entries to vulnerabilities.csv...
CSV file created: vulnerabilities.csv
File size: 11.25 MB
```

## CSV Output Columns

| Column | Description |
|--------|-------------|
| Plugin ID | Nessus plugin identifier |
| CVE | CVE reference(s) if available |
| CVSS v2.0 Base Score | CVSS version 2 score |
| Risk | Risk level (Critical/High/Medium/Low/None) |
| Host | Target IP address |
| Protocol | tcp/udp |
| Port | Port number |
| Name | Vulnerability name |
| Synopsis | Brief description |
| Description | Full vulnerability description |
| Solution | Recommended remediation |
| See Also | Reference URLs |
| Plugin Output | Raw plugin output from scan |
| CVSS v3.0 Base Score | CVSS version 3 score |
| Metasploit | Exploit available in Metasploit (true/false) |
| Core Impact | Exploit available in Core Impact (true/false) |
| CANVAS | Exploit available in CANVAS (true/false) |

## How to Export HTML from Nessus

1. Open your scan in Nessus
2. Click **Export** in the top right
3. Select **HTML** format
4. Download the report
5. Run this parser on the downloaded file

## Use Cases

- **Vulnerability Management**: Import into tracking systems
- **Reporting**: Generate executive or technical reports
- **Analysis**: Filter and pivot data in Excel/Sheets
- **Compliance**: Document findings for audits
- **Remediation Tracking**: Assign and track fixes by host/severity

## License

MIT License
