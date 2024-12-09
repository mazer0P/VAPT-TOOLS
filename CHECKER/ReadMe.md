In addition to the Python libraries, the script also relies on external tools that need to be installed separately. These are not Python packages, but rather system utilities or scripts that need to be available on your system.

1. **nmap**: Used for network scanning.
2. **nikto**: Used for web application vulnerability scanning.
3. **ffuf**: Used for directory brute-forcing.
4. **sublist3r**: Used for subdomain enumeration.
5. **whois**: For querying domain registration information.
6. **curl**: For HTTP requests and headers.
7. **nslookup**: For DNS resolution.

These tools can be installed on a Linux-based system (e.g., Kali Linux, Ubuntu) with package managers like `apt`, `brew`, or by following specific installation guides. Below are the installation instructions for these tools.

### System Tools Installation Instructions

#### On **Kali Linux** or **Debian-based** systems (Ubuntu, etc.):

You can install all the required tools using the `apt` package manager. Run the following commands:

```bash
sudo apt update
sudo apt install -y nmap nikto ffuf sublist3r whois curl dnsutils
```

- **nmap**: `sudo apt install nmap`
- **nikto**: `sudo apt install nikto`
- **ffuf**: `sudo apt install ffuf`
- **sublist3r**: `git clone https://github.com/sublist3r/Sublist3r.git && cd Sublist3r && python3 setup.py install`
- **whois**: `sudo apt install whois`
- **curl**: `sudo apt install curl`
- **dnsutils**: This package includes `nslookup` and other DNS utilities.

#### On **macOS** (Using Homebrew):

```bash
brew install nmap nikto ffuf sublist3r whois curl dnsutils
```

#### On **Windows**:

For **Windows**, you can install these tools using the Windows Subsystem for Linux (WSL) or manually install the binaries. Here's a general approach using WSL:

1. Install **WSL** (if not already installed) via PowerShell as Administrator:

   ```bash
   wsl --install
   ```

2. Then, follow the **Kali Linux** or **Ubuntu-based** installation steps.

### Full `requirements.txt` with Installation Instructions

To summarize, here’s the full `requirements.txt` file and additional system tool installation instructions:

#### `requirements.txt`

```
pyfiglet==0.8.post1
termcolor==2.3.0
```

#### Installation for External Tools (System Tools)

- **On Kali Linux / Debian-based systems (Ubuntu)**:
  ```bash
  sudo apt update
  sudo apt install -y nmap nikto ffuf sublist3r whois curl dnsutils
  ```

- **On macOS** (using Homebrew):
  ```bash
  brew install nmap nikto ffuf sublist3r whois curl dnsutils
  ```

- **On Windows**:
  1. Install **WSL** (Windows Subsystem for Linux) by running the following in PowerShell (run as Administrator):
     ```bash
     wsl --install
     ```
  2. After installation, open the WSL terminal and follow the **Kali Linux / Ubuntu** installation steps for the tools listed above.

### Additional Notes:

- Ensure that **Python 3** is installed on your system.
- The script expects a wordlist file at the path `"/home/kali/tools/SecLists/Discovery/Web-Content/big.txt"`. You may need to change this path to a valid location for your environment or download the SecLists repository from GitHub:
  ```bash
  git clone https://github.com/danielmiessler/SecLists.git
  ```

This should cover all necessary Python libraries and system dependencies to get the script running successfully on most environments!