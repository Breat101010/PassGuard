import re
import secrets
import string
import pyfiglet
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Displays the stylized ASCII banner for the tool."""
    try:
        ascii_banner = pyfiglet.figlet_format("PASSGUARD")
        print(Fore.CYAN + ascii_banner)
        print(Fore.WHITE + "Cyber Toolkit by Lee-roy Breat Chimuka\n")
    except Exception as e:
        print("PassGuard")

def check_password_strength(password):
    """
    Checks the strength of a password based on several criteria.
    Returns the strength label and a list of feedback.
    """
    score = 0
    feedback = []
    
    # Criteria Checks
    if len(password) >= 12: # Increased standard to 12 for professional security
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

    # Final Evaluation logic
    if score == 5:
        return f"{Fore.GREEN}Very Strong{Style.RESET_ALL}", feedback
    elif score >= 3:
        return f"{Fore.YELLOW}Medium{Style.RESET_ALL}", feedback
    else:
        return f"{Fore.RED}Weak{Style.RESET_ALL}", feedback

def generate_password(length=16):
    """
    Generates a cryptographically strong random password.
    """
    if length < 12:
        print(f"{Fore.RED}[!] Warning: Short passwords are vulnerable.{Style.RESET_ALL}")

    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def main_menu():
    """
    The main interactive loop of the application.
    """
    print_banner()
    
    while True:
        print(f"{Fore.CYAN}--- MAIN MENU ---{Style.RESET_ALL}")
        print("1. Check Password Strength")
        print("2. Generate Secure Password")
        print("3. Exit")
        
        choice = input(f"{Fore.GREEN}Select an option (1-3): {Style.RESET_ALL}")

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
            try:
                length_input = input("\nEnter password length (default 16): ")
                if not length_input:
                    length = 16
                else:
                    length = int(length_input)
            except ValueError:
                print(f"{Fore.RED}Invalid input. Using default length 16.{Style.RESET_ALL}")
                length = 16 
            
            new_pass = generate_password(length)
            print(f"\nGenerated Password: {Fore.GREEN}{new_pass}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}(Copy this immediately!){Style.RESET_ALL}\n")

        elif choice == '3':
            print("Stay Secure. Goodbye!")
            break
        else:
            print(f"{Fore.RED}Invalid option, please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main_menu()