
---

# **Checker: Automated OWASP Web Application Security**

**Checker** is a Python-based tool designed to run an automated OWASP Web Application Security checklist on a website. It identifies common security vulnerabilities and checks for specific security issues such as HTTP headers, cookie security, outdated components, and more.

This tool also integrates popular security scanners like `nmap` and `nikto` to perform additional checks such as subdomain enumeration and vulnerability scanning.

## **Features**

- **Automated OWASP Checklist**: Run a series of OWASP security tests on a target website.
- **Security Headers**: Check for essential HTTP security headers such as `Strict-Transport-Security`, `X-XSS-Protection`, etc.
- **Cookie Security**: Ensure cookies are properly secured with attributes like `HttpOnly`, `Secure`, and `SameSite`.
- **Outdated Components**: Identify the versions of web components used (e.g., React, jQuery) and check if they are outdated.
- **Subdomain Enumeration**: Discover subdomains associated with the target website.
- **Vulnerability Scanning**: Perform scans using tools like `nmap` and `nikto` to identify vulnerabilities.

---

## **Installation**

To install the **Checker** package, follow these steps:

1. Clone the repository or download the package files.
   ```bash
   git clone https://github.com/mazer0P/VAPT-TOOLS.git
   ```

2. Navigate to the directory containing the `setup.py` file:

   ```bash
   cd /path/to/checker
   ```

3. Install the package using pip:

   ```bash
   pip install .
   ```

   This command will install the **Checker** package and its dependencies.

---

## **Usage**

### **Running the Checker**

Once installed, you can run the **Checker** tool to perform the VAPT with OWASP security checklist on a website. You can specify the URL of the target website and the desired level of checks.

### **Syntax:**

```bash
checker <URL> <LEVEL>
```

- `<URL>`: The target URL of the website to test (e.g., `http://example.com`).
- `<LEVEL>`: The depth of the checks to run. For example, a level of `1` could run basic tests, while level `3` could run more comprehensive tests.

### **Example:**

To run the OWASP checklist on `http://example.com` with level `3` checks:

```bash
checker http://example.com 3
```

This command will execute the checklist with an advanced level of testing, which may include subdomain enumeration, outdated component detection, and vulnerability scanning.

---


## **Distribute or Upload to PyPI**

If you want to share the package or upload it to PyPI (Python Package Index), follow these steps:

1. Ensure the package is correctly structured (as shown in the directory structure above).
2. Create a distribution package:

   ```bash
   python setup.py sdist bdist_wheel
   ```

3. Upload the distribution to PyPI using `twine`:

   ```bash
   twine upload dist/*
   ```

For more information on packaging and distributing Python packages, refer to the official [Python Packaging Guide](https://packaging.python.org/en/latest/tutorials/packaging-projects/).

---

## **System Requirements and Dependencies**

The **Checker** package requires the following:

- Python 3.6 or higher
- `requests` library (for HTTP requests)
- `termcolor` library (for colored output in terminal)
- System tools like `nmap` and `nikto` (for vulnerability scanning)

To install the required dependencies, simply run:

```bash
pip install -r requirements.txt
```

---

## **Troubleshooting and Notes**

- If you encounter any errors related to system dependencies like `nmap` or `nikto`, make sure those tools are installed and properly configured in your system's PATH.
- Some tests may require administrator/root privileges, especially for scanning subdomains and performing vulnerability scans.
  
---

## **Contributing**

Contributions are welcome! If you encounter a bug or have a feature request, please open an issue in the repository.

To contribute, fork the repository, make your changes, and create a pull request with a clear description of your modifications.

---

## **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## **Contact Information**

For questions or further assistance, feel free to contact the project maintainers or raise an issue on [GitHub](https://github.com/mazer0P/VAPT-TOOLS.git).

---

