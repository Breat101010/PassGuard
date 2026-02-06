# PassGuard

**PassGuard** is a comprehensive cybersecurity toolkit designed to help users secure their digital identity. Built with Python, it combines robust password analysis, secure credential generation, and data breach detection into a single, professional command-line interface.

### 🚀 Features

* **✅ Password Strength Checker:** Evaluates passwords against industry standards (length, complexity, and entropy).
* **✅ Secure Password Generator:** Creates cryptographically strong, random passwords using the `secrets` module to ensure high entropy.
* **✅ Compromised Password Detection:** Safely checks if your password has appeared in known data breaches using the **Have I Been Pwned** API.
    * *Security Note:* Uses **k-Anonymity** (hashing) to ensure your actual password is never sent over the internet.
* * ✅ **Phishing URL Scanner:** Detects malicious links using the **VirusTotal API** (Requires free API key).
* **🚧 GUI:** (Coming Soon) A graphical user interface for easier usage.

### 🛠️ Installation

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Breat101010/PassGuard.git](https://github.com/Breat101010/PassGuard.git)
    cd PassGuard
    ```

2.  **Install Requirements:**
    This tool requires a few external libraries for the interface and API connections.
    ```bash
    pip install requests colorama pyfiglet
    ```

### 💻 How to Use

Run the main script to launch the interactive menu:

```bash
python passguard.py
```

-   Lee-roy Breat Chimuka - Connect with me on www.linkedin.com/in/lee-roy-chimuka

### Acknowledgment

*This project is a part of my journey to build a professional cybersecurity portfolio. I am eager to continue learning and adding new features. We are growing bit by bit!!*
