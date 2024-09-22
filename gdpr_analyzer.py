#!/usr/bin/env python3
# coding: utf-8

import sys
import os
import argparse
import json
import requests
from requests.exceptions import ConnectionError, HTTPError
import re
from splinter import Browser
from selenium.webdriver.firefox.service import Service as FirefoxService
import pdfkit

class Bcolors:
    HEADER = "\033[95m"
    CYAN = "\033[36m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"
    REVERSE = "\033[;7m"

def banner():
    print(f"{Bcolors.CYAN}\nGDPR Compliance Checker with ADVANCED SECURICITY SCANNING \n{Bcolors.RESET}")


def get_content(target):
    print(f"{Bcolors.CYAN}[-] Retrieving website content{Bcolors.RESET}")
    service = FirefoxService(executable_path="/usr/local/bin/geckodriver")
    browser = Browser("firefox", headless=True, service=service)

    with browser:
        browser.visit(target)
        content_html = browser.html
        content_cookies = browser.cookies.all()

    print(f"{Bcolors.GREEN}[-] Website content obtained{Bcolors.RESET}")
    return content_cookies, content_html

# 1. Cookie Categories
def evaluate_cookies(cookies):
    """
    Process and evaluate cookies for compliance issues.
    Classifies cookies into categories and checks for GDPR compliance.
    """
    print(f"{Bcolors.CYAN}[-] Checking cookies{Bcolors.RESET}")

    categories = {
        "strictly_necessary": 0,
        "performance": 0,
        "tracking": 0,
        "unknown": 0
    }

    for cookie in cookies:
        if isinstance(cookie, dict):  # Ensure each cookie is a dictionary
            cookie_name = cookie.get('name', '').lower()
            if "session" in cookie_name:
                categories['strictly_necessary'] += 1
            elif "analytics" in cookie_name:
                categories['performance'] += 1
            elif "track" in cookie_name:
                categories['tracking'] += 1
            else:
                categories['unknown'] += 1
        else:
            print(f"Invalid cookie format: {cookie}")

    result = {
        "cookie_count": len(cookies),
        "categories": categories,
        "compliance": "pass" if len(cookies) <= 10 else "fail"
    }
    return result
# 2. XSS Vulnerability Check
def check_xss_vulnerabilities(html):
    print(f"{Bcolors.CYAN}[-] Checking for XSS vulnerabilities{Bcolors.RESET}")
    potential_xss = re.findall(r'<input.*>', html)  # Search for input tags

    vulnerable_fields = []
    for field in potential_xss:
        if not ('oninput' in field or 'onchange' in field or 'onblur' in field):
            vulnerable_fields.append(field)

    if vulnerable_fields:
        return f"XSS vulnerabilities found in {len(vulnerable_fields)} input fields."
    else:
        return "No XSS vulnerabilities found."

def check_transmission_security(target):
    """
    Evaluate transmission security (SSL/TLS) using requests.
    Checks whether the target URL uses HTTPS.
    """
    print(f"{Bcolors.CYAN}[-] Checking transmission security{Bcolors.RESET}")
    try:
        response = requests.get(target, timeout=10, verify=True)
        if response.url.startswith("https://"):
            return {"ssl_status": "secure"}
        else:
            return {"ssl_status": "insecure"}
    except (ConnectionError, HTTPError) as e:
        return {"ssl_status": "failed", "error": str(e)}

# 3. Detailed Third-Party Script Analysis
def check_third_party_scripts(html):
    print(f"{Bcolors.CYAN}[-] Checking third-party scripts{Bcolors.RESET}")
    third_party_domains = {
        'google-analytics.com': 'Tracking & Analytics',
        'facebook.com': 'Social Media Tracking',
        'adservice.google.com': 'Ad Delivery'
    }

    third_party_scripts = {}

    for domain, purpose in third_party_domains.items():
        if domain in html:
            third_party_scripts[domain] = purpose

    if third_party_scripts:
        return f"Third-party scripts found: {third_party_scripts}"
    return "No third-party scripts found."

# 4. Accessibility Check (WCAG compliance)
def check_accessibility(html):
    print(f"{Bcolors.CYAN}[-] Checking website accessibility{Bcolors.RESET}")
    # Simple heuristic check for alt text and label tags
    img_tags = len(re.findall(r'<img\s[^>]*alt="[^"]+"', html))
    label_tags = len(re.findall(r'<label\s', html))

    if img_tags > 0 and label_tags > 0:
        return "Basic accessibility checks passed (alt text and labels found)."
    else:
        return "Accessibility issues found (missing alt text or labels)."

# Beacon Detection
def detect_web_beacons(html):
    print(f"{Bcolors.CYAN}[-] Checking for web beacons{Bcolors.RESET}")
    beacon_count = html.count("1x1")
    return {"beacon_count": beacon_count, "beacon_found": beacon_count > 0}

# Privacy Policy Detection
def check_privacy_policy(html):
    print(f"{Bcolors.CYAN}[-] Checking privacy policy{Bcolors.RESET}")
    policy_keywords = ['privacy', 'gdpr', 'data protection']
    if any(keyword in html.lower() for keyword in policy_keywords):
        return "Privacy Policy found on the site."
    return "No Privacy Policy found."

# CSP Headers
def check_csp_headers(website):
    print(f"{Bcolors.CYAN}[-] Checking Content Security Policy{Bcolors.RESET}")
    response = requests.get(website)
    if 'Content-Security-Policy' in response.headers:
        return f"CSP Header found: {response.headers['Content-Security-Policy']}"
    else:
        return "Warning: No Content Security Policy (CSP) header found."

# CORS Headers
def check_cors_headers(website):
    print(f"{Bcolors.CYAN}[-] Checking CORS policy{Bcolors.RESET}")
    response = requests.get(website)
    if 'Access-Control-Allow-Origin' in response.headers:
        return f"CORS Policy found: {response.headers['Access-Control-Allow-Origin']}"
    else:
        return "Warning: No CORS policy found."

from zapv2 import ZAPv2

def run_owasp_zap_scan(target_url):
    try:
        print(f"{Bcolors.CYAN}[-] Starting OWASP ZAP vulnerability scan{Bcolors.RESET}")
        zap = ZAPv2(apikey='your-api-key')  # Replace with actual ZAP API key

        # Check if ZAP is running
        if not zap.core.version:
            raise Exception("OWASP ZAP is not running or API key is incorrect")

        # Start the ZAP spider to crawl the target website
        zap.spider.scan(target_url)
        while int(zap.spider.status()) < 100:
            print(f"Spider scan progress: {zap.spider.status()}%")

        print(f"{Bcolors.GREEN}[-] Spider scan completed{Bcolors.RESET}")

        # Start Active Scan
        zap.ascan.scan(target_url)
        while int(zap.ascan.status()) < 100:
            print(f"Active scan progress: {zap.ascan.status()}%")

        print(f"{Bcolors.GREEN}[-] Active scan completed{Bcolors.RESET}")

        # Fetch scan results
        alerts = zap.core.alerts(baseurl=target_url)
        return alerts  # Alerts will contain all the vulnerabilities detected

    except Exception as e:
        print(f"Error during OWASP ZAP scan: {str(e)}")
        return []

import nmap

def run_nmap_scan(target_url):
    print(f"{Bcolors.CYAN}[-] Starting Nmap network scan{Bcolors.RESET}")
    nm = nmap.PortScanner()
    nm.scan(target_url)

    scan_results = {}
    for host in nm.all_hosts():
        scan_results[host] = nm[host]

    return scan_results

def generate_report(name, target, results):
    result_target = "reports"
    os.makedirs(result_target, exist_ok=True)

    target_safe = target.replace("https://", "").replace("http://", "").replace("/", "_")

    # JSON Report
    json_path = f"{result_target}/Toolanalyzed_{name}_{target_safe}.json"
    with open(json_path, "w") as json_file:
        json.dump(results, json_file, indent=4)
    print(f"{Bcolors.GREEN}[-] JSON report generated at {json_path}{Bcolors.RESET}")

    # PDF Report
    html_content = f"""
    <h1>GDPR Compliance Report for {target}</h1>
    <p><strong>Website: </strong>{target}</p>
    <p><strong>SSL Status: </strong>{results['ssl_status']}</p>
    <p><strong>Cookie Count: </strong>{results['cookie_count']}</p>
    <p><strong>Cookie Categories: </strong>{results['categories']}</p>
    <p><strong>XSS Vulnerabilities: </strong>{results['xss_vulnerabilities']}</p>
    <p><strong>Third-Party Scripts: </strong>{results['third_party_scripts']}</p>
    <p><strong>Accessibility: </strong>{results['accessibility']}</p>
    <p><strong>Privacy Policy: </strong>{results['privacy_policy']}</p>
    <p><strong>Content Security Policy: </strong>{results['content_security_policy']}</p>
    <p><strong>CORS Policy: </strong>{results['cors_policy']}</p>
    <p><strong>Beacon Count: </strong>{results['beacon_count']}</p>
    """
    pdf_path = f"{result_target}/gdpranalyzer_{name}_{target_safe}.pdf"
    pdfkit.from_string(html_content, pdf_path)
    print(f"{Bcolors.GREEN}[-] PDF report generated at {pdf_path}{Bcolors.RESET}")

def start():
    banner()
    parser = argparse.ArgumentParser(description="GDPR Compliance Checker with Security Scanning")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("name", help="Report owner")
    parser.add_argument("-r", "--report", help="Generate PDF report", action="store_true")
    parser.add_argument("-j", "--json", help="Generate JSON report", action="store_true")
    parser.add_argument("-s", "--security_scan", help="Run OWASP ZAP scan", action="store_true")
    parser.add_argument("-n", "--nmap_scan", help="Run Nmap network scan", action="store_true")
    args = parser.parse_args()

    target = args.url
    name = args.name

    cookies, html = get_content(target)

    cookie_results = evaluate_cookies(cookies)
    ssl_results = check_transmission_security(target)
    xss_results = check_xss_vulnerabilities(html)
    third_party_results = check_third_party_scripts(html)
    accessibility_results = check_accessibility(html)
    privacy_policy_result = check_privacy_policy(html)
    csp_results = check_csp_headers(target)
    cors_results = check_cors_headers(target)
    beacon_results = detect_web_beacons(html)

    # Run OWASP ZAP Security Scan if enabled
    zap_results = []
    if args.security_scan:
        zap_results = run_owasp_zap_scan(target)

    # Run Nmap Network Scan if enabled
    nmap_results = []
    if args.nmap_scan:
        nmap_results = run_nmap_scan(target)


    results = {
        **cookie_results,
        **ssl_results,
        "xss_vulnerabilities": xss_results,
        "third_party_scripts": third_party_results,
        "zap_vulnerabilities": zap_results,
        "nmap_vulnerabilities": nmap_results,
        "accessibility": accessibility_results,
        "privacy_policy": privacy_policy_result,
        "content_security_policy": csp_results,
        "cors_policy": cors_results,
        **beacon_results
    }

    if args.report or args.json:
        generate_report(name, target, results)

if __name__ == "__main__":
    start()
