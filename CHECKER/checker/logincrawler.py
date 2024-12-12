import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Common login page filenames to check for
COMMON_LOGIN_PAGES = [
    "login.php", "signin.php", "admin.php", "user-login.php",
    "login-form.php", "auth.php", "logincheck.php",
    "login.aspx", "signin.aspx", "auth.aspx", "admin.aspx", "user-login.aspx",
    "login.html", "signin.html", "login.htm", "signin.htm",
    "login-form.html", "login-page.html", "login-check.html",
    "login/", "signin/", "auth/", "user-login/", "admin-login/",
    "account/login/", "account/signin/", "admin/", "user/",
    "login-form/", "login-page/", "user-authentication/",
    "logincheck", "admin-login", "user-login", "secure-login",
    "login_area", "authentication", "user-authentication", "member-login",
    "sign-in", "member-signin", "access-login",
    "oauth/login/", "sso/login/", "login_secure/", "user-auth/",
    "login_admin", "login_user", "admin-login-form", "signin-form",
    "admin-signin", "user-signin", "auth-form", "loginwindow",
    "login-screen", "user-signup", "admin-signup", "login-portal",
    "sign-in-form", "signin-screen", "admin-signin-form", "user-login-form",
    "login-panel", "admin-auth", "user-auth", "user-login-form",
    "admin-authentication", "secure-login-page", "user-login-page",
    "admin-area", "user-area", "member-login-form", "admin-login-page",
    "signin-form.php", "auth-form.php", "login-panel.php", "auth-panel.php"

]


# Helper function to make an HTTP request and return the response
def make_request(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
    return None


# Function to find login functionality
def find_login_page(base_url, max_depth=3):
    visited_urls = set()  # To track visited URLs to prevent loops
    login_urls = []  # List to store URLs where login functionality is found
    urls_to_visit = [base_url]  # Start the crawl from the base URL

    # Check for common login pages directly
    login_urls += check_for_common_login_pages(base_url)

    # Crawl the site up to a certain depth
    for depth in range(max_depth):
        next_urls = []
        for url in urls_to_visit:
            if url in visited_urls:
                continue
            visited_urls.add(url)

            print(f"Crawling {url}...")
            response = make_request(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Check if the page contains a form with typical login fields
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action', '').lower()
                    method = form.get('method', '').lower()
                    inputs = form.find_all('input')
                    input_names = [input.get('name', '').lower() for input in inputs]

                    # Check if the form contains username/password fields
                    if any(name in input_names for name in ['username', 'email', 'login', 'user']) and \
                            any(name in input_names for name in ['password', 'pass']):
                        # Check if the form action points to a login URL
                        if action:
                            login_url = urljoin(url, action)
                            print(f"Found login form at {login_url}")
                            login_urls.append(login_url)

                # Find all links in the page
                links = soup.find_all('a', href=True)
                for link in links:
                    link_url = urljoin(url, link['href'])
                    # Only add URLs that have not been visited and are within the same domain
                    if link_url not in visited_urls and urlparse(link_url).netloc == urlparse(base_url).netloc:
                        next_urls.append(link_url)

        # Move on to the next set of URLs to visit
        urls_to_visit = next_urls
        if not urls_to_visit:
            break

    return login_urls


# Function to check for common login page URLs
def check_for_common_login_pages(base_url):
    login_urls = []
    for page in COMMON_LOGIN_PAGES:
        # Construct the full URL for each common login page
        url = urljoin(base_url, page)
        response = make_request(url)
        if response:
            print(f"Found possible login page at {url}")
            login_urls.append(url)
    return login_urls


# Main execution to find login pages
def run_crawler(url):
    base_url = url  # Replace with the base URL of the target site
    login_pages = find_login_page(base_url)

    if login_pages:
        print("\nLogin pages found:")
        for login_page in login_pages:
            print(login_page)
    else:
        print("No login pages found.")

