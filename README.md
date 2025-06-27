# 🛡️ Vulnerability Scanner

A moderate-level **Python-based vulnerability scanner** for web applications. It checks for:
- Open ports using **Nmap**
- Missing **security headers**
- Basic **SQL Injection** and **XSS** vulnerabilities
- Outputs results to a structured **JSON report**

---

## 🚀 Features
- Scans open TCP ports on a given target domain/IP
- Verifies if essential security headers are implemented
- Detects SQL injection & XSS vulnerabilities using test payloads
- Generates scan report as `report.json`

---

## 📁 Project Structure
```
vuln-scanner/
├── scanner.py            # Main scanner script
├── requirements.txt      # Required libraries
└── README.md             # Project documentation
```

---

## 🧰 Requirements
- Python 3.x
- Nmap installed and added to system PATH

### 📦 Python Libraries:
```
python-nmap
requests
```
Install them using:
```bash
pip install -r requirements.txt
```

---

## ⚙️ How to Run
```bash
python scanner.py http://testphp.vulnweb.com
```

> ✅ Use only legal and safe targets. Recommended:
> - http://testphp.vulnweb.com
> - http://demo.testfire.net
> - https://juice-shop.herokuapp.com

---

## 📄 Sample Output
```json
{
  "missing_headers": [
    "Content-Security-Policy",
    "Strict-Transport-Security"
  ],
  "sql_injection": true,
  "xss": false,
  "open_ports": {
    "80": "http",
    "443": "https"
  }
}
```

---

## 📌 Author
- 💻 Developed by Manasi Lohar
- 🌐 For Cybersecurity learning and resume projects

---

## 📜 Disclaimer
> This tool is for **educational and legal testing** only. Do not scan unauthorized websites.
