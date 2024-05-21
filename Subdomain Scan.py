import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

def check_sql_injection(url):
    sql_payload = "' OR '1'='1"
    response = requests.get(url, params={"id": sql_payload})
    if "error" in response.text or "syntax" in response.text:
        print(f"SQL Injection vulnerability found at {url}")
    else:
        print(f"No SQL Injection vulnerability detected at {url}")

def check_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    response = requests.get(url, params={"q": xss_payload})
    if xss_payload in response.text:
        print(f"XSS vulnerability found at {url}")
    else:
        print(f"No XSS vulnerability detected at {url}")

def crawl_and_scan(url, visited_urls):
    urls_to_visit = [url]

    while urls_to_visit:
        current_url = urls_to_visit.pop(0)

        try:
            response = requests.get(current_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            check_sql_injection(current_url)
            check_xss(current_url)

            for link in soup.find_all('a', href=True):
                absolute_link = urljoin(current_url, link['href'])
                parsed_url = urlparse(absolute_link)
                if parsed_url.netloc == urlparse(url).netloc and absolute_link not in visited_urls:
                    visited_urls.add(absolute_link)
                    urls_to_visit.append(absolute_link)

        except Exception as e:
            print(f"Error accessing {current_url}: {str(e)}")

def find_subdomains(base_url):
    subdomains = set()
    domain = urlparse(base_url).netloc
    response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json")
    if response.ok:
        for result in response.json():
            name_value = result['name_value']
            match = re.search(r"(\w+\.)?{}$".format(re.escape(domain)), name_value)
            if match:
                subdomain = match.group(0)
                if subdomain != domain:
                    subdomains.add(subdomain)
    return subdomains

if __name__ == "__main__":
    website_url = input("Enter the URL of the website to scan: ")
    visited_urls = set()

    crawl_and_scan(website_url, visited_urls)
    subdomains = find_subdomains(website_url)

    for subdomain in subdomains:
        subdomain_url = f"https://{subdomain}"
        print(f"Scanning subdomain: {subdomain_url}")
        crawl_and_scan(subdomain_url, visited_urls)
