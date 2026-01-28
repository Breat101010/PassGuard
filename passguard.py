import re
import secrets
import string
import hashlib
import requests
import pyfiglet
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Displays the stylized ASCII banner."""
    try:
        ascii_banner = pyfiglet.figlet_format("PASSGUARD")
        print(Fore.CYAN + ascii_banner)
        print(Fore.WHITE + "v2.1 - Cybersecurity Toolkit by Lee-roy Breat Chimuka\n")
    except Exception:
        print("PassGuard v2.1")

def check_pwned_api(password):
    """
    Checks if a password exists in the Have I Been Pwned database using k-Anonymity.
    Returns the number of times it has been seen in breaches (0 if safe).
    """
    # 1. Hash the password (SHA-1)
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # 2. Split the hash: first 5 chars (prefix) vs the rest (suffix)
    first5_char = sha1password[:5]
    tail = sha1password[5:]
    
    # 3. Send ONLY the first 5 chars to the API
    url = 'https://api.pwnedpasswords.com/range/' + first5_char
    try:
        res = requests.get(url)
        if res.status_code != 200:
            raise RuntimeError(f"Error fetching: {res.status_code}, check API connection")
        
        # 4. Check the response for our tail
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == tail:
                return int(count)
        return 0
    except Exception as e:
        print(f"{Fore.RED}[Error] Could not connect to HIBP API: {e}{Style.RESET_ALL}")
        return 0

def check_password_strength(password):
    score = 0
    feedback = []
    
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Password should be at least 12 characters long.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Missing lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Missing uppercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Missing numbers.")

    if re.search(r"[@$!%*#?&]", password):
        score += 1
    else:
        feedback.append("Missing special characters (@$!%*#?&).")

    if score == 5:
        return f"{Fore.GREEN}Very Strong{Style.RESET_ALL}", feedback
    elif score >= 3:
        return f"{Fore.YELLOW}Medium{Style.RESET_ALL}", feedback
    else:
        return f"{Fore.RED}Weak{Style.RESET_ALL}", feedback

def generate_password(length=16):
    if length < 12:
        print(f"{Fore.RED}[!] Warning: Short passwords are vulnerable.{Style.RESET_ALL}")
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def main_menu():
    print_banner()
    while True:
        print(f"{Fore.CYAN}--- MAIN MENU ---{Style.RESET_ALL}")
        print("1. Check Password Strength")
        print("2. Check for Breaches (HIBP)")
        print("3. Generate Secure Password")
        print("4. Exit")
        
        choice = input(f"{Fore.GREEN}Select an option (1-4): {Style.RESET_ALL}")

        if choice == '1':
            pwd = input("\nEnter password to check: ")
            strength, feedback = check_password_strength(pwd)
            print(f"\nStrength: {strength}")
            if feedback:
                print(f"{Fore.RED}Suggestions:{Style.RESET_ALL}")
                for item in feedback:
                    print(f"- {item}")
            print("\n")

        elif choice == '2':
            pwd = input("\nEnter password to check for breaches: ")
            print(f"{Fore.YELLOW}Checking database...{Style.RESET_ALL}")
            count = check_pwned_api(pwd)
            if count > 0:
                print(f"{Fore.RED}[DANGER] This password has been seen {count} times in data breaches!{Style.RESET_ALL}")
                print(f"{Fore.RED}Do NOT use this password.{Style.RESET_ALL}\n")
            else:
                print(f"{Fore.GREEN}[SAFE] Good news! This password was not found in known breaches.{Style.RESET_ALL}\n")

        elif choice == '3':
            try:
                length_input = input("\nEnter password length (default 16): ")
                length = int(length_input) if length_input else 16
            except ValueError:
                length = 16
            
            new_pass = generate_password(length)
            print(f"\nGenerated Password: {Fore.GREEN}{new_pass}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}(Copy this immediately!){Style.RESET_ALL}\n")

        elif choice == '4':
            print("Stay Secure. Goodbye!")
            break
        else:
            print(f"{Fore.RED}Invalid option.{Style.RESET_ALL}")

if __name__ == "__main__":
    main_menu()