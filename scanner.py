import nmap
import requests
import json
import argparse

# ---------- NMAP PORT SCANNER ----------
def scan_ports(target_ip):
    print(f"[+] Scanning ports on {target_ip}...")
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sV')
    open_ports = {}
    if target_ip in nm.all_hosts():
        for port in nm[target_ip]['tcp']:
            open_ports[port] = nm[target_ip]['tcp'][port]['name']
    return open_ports

# ---------- SECURITY HEADER CHECK ----------
def check_security_headers(url):
    print(f"[+] Checking security headers for {url}...")
    required_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options']
    try:
        res = requests.get(url, timeout=5)
        missing = [h for h in required_headers if h not in res.headers]
        return missing
    except Exception as e:
        print(f"[!] Error checking headers: {e}")
        return []

# ---------- SQL INJECTION CHECK ----------
def check_sql_injection(url):
    print(f"[+] Performing SQL injection test on {url}...")
    payload = "' OR '1'='1"
    try:
        response = requests.get(url + f"?id={payload}", timeout=5)
        if "mysql" in response.text.lower() or "syntax" in response.text.lower():
            return True
        return False
    except Exception as e:
        print(f"[!] Error in SQL injection test: {e}")
        return False

# ---------- XSS CHECK ----------
def check_xss(url):
    print(f"[+] Performing XSS test on {url}...")
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url + f"?q={payload}", timeout=5)
        if payload in response.text:
            return True
        return False
    except Exception as e:
        print(f"[!] Error in XSS test: {e}")
        return False

# ---------- REPORT GENERATION ----------
def generate_report(results, output_file='report.json'):
    print("[+] Generating report...")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"[+] Report saved as {output_file}")

# ---------- MAIN EXECUTION ----------
def main():
    parser = argparse.ArgumentParser(description='WebApp Vulnerability Scanner')
    parser.add_argument('target', help='Target IP or URL (e.g., http://example.com)')
    args = parser.parse_args()

    target = args.target
    results = {}

    if target.startswith('http'):
        results['missing_headers'] = check_security_headers(target)
        results['sql_injection'] = check_sql_injection(target)
        results['xss'] = check_xss(target)

    ip = target.replace('http://', '').replace('https://', '').split('/')[0]
    results['open_ports'] = scan_ports(ip)

    generate_report(results)

if __name__ == '__main__':
    main()
