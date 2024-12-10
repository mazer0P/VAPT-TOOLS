import requests
import re
from urllib.parse import urljoin
from termcolor import colored  # Import termcolor for colored output


# Test 1: Checking the Presence of Security Headers
def check_http_security_headers(url):
    print("\n[TEST] Checking HTTP Security Headers...\n")
    headers = requests.get(url).headers
    headers_list = {
        "Strict-Transport-Security": "Enforces the use of HTTPS",
        "Content-Security-Policy": "Helps prevent content injection attacks like XSS",
        "X-Content-Type-Options": "Prevents browsers from interpreting files as a different MIME type",
        "X-Frame-Options": "Prevents the page from being embedded in a frame (clickjacking protection)",
        "X-XSS-Protection": "Enables the browser's built-in XSS protection",
        "Referrer-Policy": "Controls the amount of information sent with requests regarding the referrer",
        "Feature-Policy": "Controls access to browser features, deprecated in favor of Permissions-Policy",
        "Permissions-Policy": "Restricts certain features in the browser to enhance security",
        "Cache-Control": "Prevents sensitive information from being cached",
        "Access-Control-Allow-Origin": "Defines which domains can access resources on the server (CORS)"
    }

    for header, description in headers_list.items():
        if header in headers:
            print(colored(f"[INFO] {header}: Present ({description})", 'green'))
        else:
            print(colored(f"[WARNING] {header}: Missing ({description})", 'red'))


# Test 2: Check for Website Components Version
def check_website_components_version(url):
    print("\n[TEST] Checking Website Components and Version...\n")

    try:
        # Make a request to the website
        response = requests.get(url)

        # Checking X-Powered-By header for framework info
        x_powered_by = response.headers.get('X-Powered-By', '')
        if x_powered_by:
            print(colored(f"[INFO] X-Powered-By: {x_powered_by}", 'green'))
        else:
            print(colored(f"[WARNING] X-Powered-By: Missing", 'red'))

        # Check for common JavaScript libraries and versions
        # check_js_libraries(response.text)

        # Check for versioning in other parts of the response body (meta tags, comments, etc.)
        check_meta_and_comments(response.text)

    except requests.exceptions.RequestException as e:
        print(colored(f"[ERROR] Failed to fetch the website: {e}", 'red'))


# Check for versioning in JavaScript libraries (e.g., React, jQuery, etc.)
# def check_js_libraries(html):
#     libraries = {
#         'react': r'react\.min\.js.*?(\d+\.\d+\.\d+)',  # Regex for React version
#         'jquery': r'jquery\.min\.js.*?(\d+\.\d+\.\d+)',  # Regex for jQuery version
#         'vue': r'vue\.min\.js.*?(\d+\.\d+\.\d+)',  # Regex for Vue.js version
#         'angular': r'angular\.min\.js.*?(\d+\.\d+\.\d+)'  # Regex for AngularJS version
#     }
#     for lib, pattern in libraries.items():
#         matches = re.findall(pattern, html)
#         if matches:
#             print(colored(f"[INFO] Found {lib.capitalize()} version: {matches[0]}", 'green'))
#         else:
#             print(colored(f"[WARNING] {lib.capitalize()} version: Missing", 'red'))
#

# Check for versioning information in meta tags or comments in HTML
def check_meta_and_comments(html):
    # Meta tags
    meta_version_pattern = r'<meta\s+name="generator"\s+content=".*?(\d+\.\d+\.\d+).*?"'
    meta_matches = re.findall(meta_version_pattern, html)
    if meta_matches:
        print(colored(f"[INFO] Meta tag version found: {meta_matches[0]}", 'green'))
    else:
        print(colored("[WARNING] Meta tag version: Missing", 'red'))

    # Comments inside the HTML (some devs leave versioning in comments)
    comment_version_pattern = r'<!--\s*version:\s*(\d+\.\d+\.\d+)\s*-->'
    comment_matches = re.findall(comment_version_pattern, html)
    if comment_matches:
        print(colored(f"[INFO] Comment version found: {comment_matches[0]}", 'green'))
    else:
        print(colored("[WARNING] Comment version: Missing", 'red'))


# Test 3: Cookie Security Test
def check_cookie_security(url):
    print("\n[TEST] Checking Cookie Security...\n")
    try:
        response = requests.get(url)
        cookies = response.cookies

        if cookies:
            for cookie in cookies:
                print(f"[INFO] Cookie: {cookie.name} - {cookie.value}")
                # Check if Secure flag is set
                if 'secure' in cookie.__dict__:
                    print(colored(f"[INFO] Secure: {cookie.secure} (Should be True for HTTPS)", 'green'))
                else:
                    print(colored("[WARNING] Secure flag not set.", 'red'))

                # Check if HttpOnly flag is set
                if 'httponly' in cookie.__dict__:
                    print(colored(f"[INFO] HttpOnly: {cookie.httponly} (Should be True for better security)", 'green'))
                else:
                    print(colored("[WARNING] HttpOnly flag not set.", 'red'))

                # Check if SameSite attribute is set
                if 'samesite' in cookie.__dict__:
                    print(colored(f"[INFO] SameSite: {cookie.samesite} (Should be 'Strict' or 'Lax')", 'green'))
                else:
                    print(colored("[WARNING] SameSite attribute not set.", 'red'))

                # Check for Expiry/Max-Age (not recommended for session cookies with very long lifespan)
                if 'expires' in cookie.__dict__:
                    print(colored(f"[INFO] Expiry: {cookie.expires} (Ensure it is not set too far in the future)",
                                  'green'))
                else:
                    print(colored("[INFO] No expiry date set for cookie.", 'red'))

        else:
            print(colored("[INFO] No cookies found for this domain.", 'red'))
    except requests.exceptions.RequestException:
        print(colored("[ERROR] Failed to fetch the website.", 'red'))


# Main Function to Run All Tests
def run_owasp_tests(url):
    print(f"\nRunning OWASP Web Application Security Tests for: {url}\n")
    check_http_security_headers(url)
    check_website_components_version(url)
    check_cookie_security(url)


if __name__ == "__main__":
    # Get the target URL from the user
    target_url = input("Please enter the URL of the web application to test (e.g., http://example.com): ")

    # Ensure the URL starts with http or https
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        print(colored("[ERROR] The URL must start with 'http://' or 'https://'.", 'red'))
    else:
        run_owasp_tests(target_url)
