# GDPR Compliance Checker with OWASP ZAP and Nmap Integration

### Check more about it on my website: https://www.devangshumazumder.com/projects/content/gdpr-nmap/gdpr

## Description

This **GDPR Compliance Checker** helps websites and companies ensure their compliance with GDPR regulations and enhances their security posture by identifying potential vulnerabilities. It scans for cookies, checks transmission security, analyzes third-party scripts, assesses accessibility, and integrates **OWASP ZAP** and **Nmap** for in-depth security scans.

### Key Features:
***
- **Cookie Classification**: Categorizes cookies as strictly necessary, performance-related, or tracking cookies and checks their compliance with GDPR.
- **Transmission Security**: Verifies whether a website uses HTTPS and checks for secure SSL/TLS transmission.
- **XSS Vulnerability Detection**: Detects potential Cross-Site Scripting (XSS) vulnerabilities in the website’s HTML code.
- **Third-Party Script Analysis**: Identifies third-party scripts, such as Google Analytics and Facebook tracking, and checks for compliance with GDPR.
- **Accessibility Compliance**: Assesses the website's accessibility by checking for alt text and form labels, ensuring compliance with WCAG.
- **OWASP ZAP Security Scanning**: Integrates with **OWASP ZAP** for identifying vulnerabilities like SQL injection, XSS, and more.
- **Nmap Network Scan**: Uses **Nmap** to scan for open ports and services, identifying network vulnerabilities.
***

## Prerequisites

***
- Python 3.x
- `geckodriver` for Firefox automation.
- Required Python libraries:
    - splinter
    - pdfkit
    - requests
    - re
    - argparse
    - zapv2 (for OWASP ZAP integration)
    - python-nmap (for Nmap integration)

### Install the required dependencies:
```bash
pip install splinter pdfkit requests argparse zapv2 python-nmap
```

### ZAP and NMAP in systems
- I used MACBOOK bro 2017

```bash
brew install nmap
```

## Usage

- To run the GDPR Compliance Checker on a target website, use the following command:

``` bash
python gdpr_analyzer.py <url> <report_name> [options]
```
### Arguments:

- 	<url>: The target website URL.
-	<report_name>: The name of the report owner.

### Options:

- r, --report: Generate a PDF report.
- j, --json: Generate a JSON report.
- s, --security_scan: Run an OWASP ZAP vulnerability scan.
- n, --nmap_scan: Run an Nmap network scan.

### Example:

```bash
python gdpr_analyzer.py https://example.com report_owner -r -s -n
```

## GDPR Compliance

*  1.	Data Protection: Ensures compliance with GDPR regulations by categorizing cookies, checking privacy policies, and analyzing third-party
        scripts.
*	2.	Security Scanning: Identifies potential security threats such as SQL injection, open ports, and XSS vulnerabilities, reducing the risk
        of cyberattacks.
*	3.	Accessibility: Assesses accessibility based on WCAG standards, ensuring your website meets regulatory requirements.
*	4.	Comprehensive Reporting: Provides detailed reports that help improve website security and data protection strategies.
