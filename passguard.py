import re
import secrets
import string
import hashlib
import requests
import pyfiglet
import os
import base64
from colorama import Fore, Style, init
from dotenv import load_dotenv

# Initialize tools
init(autoreset=True)
load_dotenv() # This loads your secret key from the .env file

def print_banner():
    """Displays the stylized ASCII banner."""
    try:
        ascii_banner = pyfiglet.figlet_format("PASSGUARD")
        print(Fore.CYAN + ascii_banner)
        print(Fore.WHITE + "Cybersecurity Toolkit by Lee-roy Breat Chimuka\n")
    except Exception:
        print("PassGuard v3.0")

def check_url_safety(url_to_scan):
    """
    Scans a URL using the VirusTotal API.
    """
    api_key = os.getenv('VT_API_KEY')
    
    if not api_key:
        print(f"{Fore.RED}[Error] API Key not found! Make sure you have a .env file.{Style.RESET_ALL}")
        return

    # VirusTotal requires the URL to be Base64 encoded
    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    print(f"{Fore.YELLOW}Scanning URL with VirusTotal... (This may take a second){Style.RESET_ALL}")
    
    # 1. Ask VirusTotal for the report
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = requests.get(api_url, headers=headers)

    # 2. Handle the response
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        harmless = stats['harmless']

        if malicious > 0 or suspicious > 0:
            print(f"\n{Fore.RED}[DANGER] This URL is flagged as unsafe!{Style.RESET_ALL}")
            print(f"Malicious Reports: {malicious}")
            print(f"Suspicious Reports: {suspicious}")
        else:
            print(f"\n{Fore.GREEN}[SAFE] No security vendors flagged this URL.{Style.RESET_ALL}")
            print(f"Clean Reports: {harmless}")
            
    elif response.status_code == 404:
        print(f"{Fore.YELLOW}[Info] VirusTotal hasn't seen this URL before. Please submit it for scanning first.{Style.RESET_ALL}")
    elif response.status_code == 401:
        print(f"{Fore.RED}[Error] Invalid API Key. Check your .env file.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[Error] Something went wrong: {response.status_code}{Style.RESET_ALL}")

def check_pwned_api(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char = sha1password[:5]
    tail = sha1password[5:]
    url = 'https://api.pwnedpasswords.com/range/' + first5_char
    try:
        res = requests.get(url)
        if res.status_code != 200: 
            return 0
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == tail:
                return int(count)
        return 0
    except Exception:
        return 0

def check_password_strength(password):
    score = 0
    feedback = []
    if len(password) >= 12: score += 1
    else: feedback.append("Password should be at least 12 characters long.")
    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("Missing lowercase letters.")
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("Missing uppercase letters.")
    if re.search(r"\d", password): score += 1
    else: feedback.append("Missing numbers.")
    if re.search(r"[@$!%*#?&]", password): score += 1
    else: feedback.append("Missing special characters (@$!%*#?&).")
    
    if score == 5: return f"{Fore.GREEN}Very Strong{Style.RESET_ALL}", feedback
    elif score >= 3: return f"{Fore.YELLOW}Medium{Style.RESET_ALL}", feedback
    else: return f"{Fore.RED}Weak{Style.RESET_ALL}", feedback

def generate_password(length=16):
    if length < 12: print(f"{Fore.RED}[!] Warning: Short passwords are vulnerable.{Style.RESET_ALL}")
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main_menu():
    print_banner()
    while True:
        print(f"{Fore.CYAN}--- MAIN MENU ---{Style.RESET_ALL}")
        print("1. Check Password Strength")
        print("2. Check for Breaches (HIBP)")
        print("3. Generate Secure Password")
        print("4. Scan Phishing URL (VirusTotal)")
        print("5. Exit")
        
        choice = input(f"{Fore.GREEN}Select an option (1-5): {Style.RESET_ALL}")

        if choice == '1':
            pwd = input("\nEnter password to check: ")
            strength, feedback = check_password_strength(pwd)
            print(f"\nStrength: {strength}")
            for item in feedback: print(f"- {item}")
            print("\n")

        elif choice == '2':
            pwd = input("\nEnter password to check for breaches: ")
            print(f"{Fore.YELLOW}Checking database...{Style.RESET_ALL}")
            count = check_pwned_api(pwd)
            if count > 0:
                print(f"{Fore.RED}[DANGER] Seen {count} times in breaches!{Style.RESET_ALL}\n")
            else:
                print(f"{Fore.GREEN}[SAFE] Not found in known breaches.{Style.RESET_ALL}\n")

        elif choice == '3':
            try:
                l = input("\nEnter length (default 16): ")
                length = int(l) if l else 16
            except: length = 16
            print(f"\nGenerated: {Fore.GREEN}{generate_password(length)}{Style.RESET_ALL}\n")

        elif choice == '4':
            url = input("\nEnter URL to scan (e.g., http://google.com): ")
            check_url_safety(url)
            print("\n")

        elif choice == '5':
            print("Stay Secure. Goodbye!")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main_menu()