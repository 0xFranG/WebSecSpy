# ⚙️WebSecSpy

**WebSecSpy** is a **web reconnaissance and security analysis tool** built for **cybersecurity professionals**, **penetration testers**, and **ethical hackers**.  
It provides a comprehensive suite of features for scanning URLs, detecting vulnerabilities, analyzing HTTP headers, and more.

---

## 👤Author

🛠️ Developed by **[0xFranG]**  
🔗 [LinkedIn](https://www.linkedin.com/in/francisco-g-48309821a/)  
📸 IG: [@CyberwithFran](https://instagram.com/CyberwithFran)

---
```bash
## 🔧 Installation
Make sure you have **Python 3.7+** installed.
git clone https://github.com/0xFranG/websecspy.git
cd websecspy
pip install -r requirements.txt
```

# ⚙️Usage
```bash
python WebSecS.py -U http(s)://www.example.com [options]
python WebSecS.py -f urls.txt [options]
```

# 🔍Features
| Option              | Description                                                               |
|---------------------|---------------------------------------------------------------------------|
| `-U, --url`         | Scan a single target URL                                                  |
| `-f, --file`        | Scan multiple URLs from a file                                            |
| `-p, --ports`       | Scan for open ports                                                       |
| `-s, --ssl`         | Check SSL/TLS version                                                     |
| `-H, --headers`     | Display HTTP response headers                                             |
| `-P, --proxy`       | Use a proxy (e.g., `http://127.0.0.1:8080`)                               |
| `-sL, --subdomains` | Enumerate subdomains using Sublist3r                                      |
| `-dW, --detect-waf` | Detect Web Application Firewall (WAF)                                     |
| `-l, --find-login`  | Detect common login/admin panels                                          |
| `-i, --injection`   | Scan for injection vulnerabilities (levels 1–5)                           |
| `-dC, --dos-check`  | Simulate a DoS attack (1: light, 2: medium, 3: aggressive)                |

```bash
# Scan a single URL with port scanning
python WebSecS.py -U https://example.com -p

# Scan multiple URLs from a file and show headers
python WebSecS.py -f urls.txt -H

# Enumerate subdomains and check for WAF
python WebSecS.py -U https://target.com -sL -dW

# Run through a proxy and search for login pages
python WebSecS.py -U http://example.com -P http://127.0.0.1:8080 -l

# Check for injection vulnerabilities (level 3)
python WebSecS.py -U https://vulnsite.com -i 3

# Simulate a medium-level DoS attack
python WebSecS.py -U https://target.com -dC 2
```


