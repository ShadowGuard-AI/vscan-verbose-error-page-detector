import argparse
import requests
import logging
import re
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VerboseErrorPageDetector:
    """
    Detects verbose error pages that may expose sensitive information.
    """

    def __init__(self, url, timeout=10, user_agent=None):
        """
        Initializes the VerboseErrorPageDetector.

        Args:
            url (str): The URL to scan.
            timeout (int): Timeout for HTTP requests in seconds. Defaults to 10.
            user_agent (str): Custom User-Agent header. Defaults to None.
        """
        self.url = url
        self.timeout = timeout
        self.user_agent = user_agent if user_agent else "vscan-verbose-error-page-detector/1.0"
        self.headers = {'User-Agent': self.user_agent}
        self.last_status = None
        self.sensitive_patterns = [
            re.compile(r"Stack Trace", re.IGNORECASE),
            re.compile(r"Exception Details", re.IGNORECASE),
            re.compile(r"Error Message", re.IGNORECASE),
            re.compile(r"SQL syntax error", re.IGNORECASE),
            re.compile(r"PDOException", re.IGNORECASE),
            re.compile(r"Warning:", re.IGNORECASE),
            re.compile(r"Notice:", re.IGNORECASE),
            re.compile(r"Fatal error:", re.IGNORECASE),
            re.compile(r"Internal Server Error", re.IGNORECASE),
            re.compile(r"The server encountered an internal error or misconfiguration", re.IGNORECASE),
            # Error shaped markers only. Bare words such as debug,
            # database, path, or version appear on ordinary pages and
            # are not findings on their own.
            re.compile(r"Traceback \(most recent call last\)"),
            re.compile(r"File \"[^\"]+\", line \d+"),
            re.compile(r"\bat [\w.$]+\([\w.]+:\d+\)"),
            re.compile(r"\b[A-Z][A-Za-z]*Exception\b"),
            re.compile(r"SQLSTATE\[", re.IGNORECASE),
            re.compile(r"ORA-\d{5}"),
            re.compile(r"Uncaught (Error|Exception)", re.IGNORECASE),
            re.compile(r"phpinfo\(\)"),
            re.compile(r"DOCUMENT_ROOT|SERVER_ADMIN|SCRIPT_FILENAME"),
        ]

    def is_valid_url(self):
        """
        Validates the URL format.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        try:
            result = urlparse(self.url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def fetch_page(self):
        """
        Fetches the content of the URL.

        Returns:
            str: The content of the page, or None if an error occurred.
        """
        try:
            response = requests.get(self.url, headers=self.headers, timeout=self.timeout)
            # No raise_for_status: verbose error pages are served with
            # 4xx and 5xx status codes, and the body of an error
            # response is exactly what this check exists to read.
            self.last_status = response.status_code
            return response.text
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching {self.url}: {e}")
            return None

    def analyze_content(self, content):
        """
        Analyzes the content for sensitive information disclosures.

        Args:
            content (str): The content to analyze.

        Returns:
            bool: True if sensitive information is found, False otherwise.
        """
        if not content:
            return False

        for pattern in self.sensitive_patterns:
            if pattern.search(content):
                return True
        return False

    def run(self):
        """
        Executes the verbose error page detection.

        Returns:
            bool or None: True if a verbose error page is detected,
            False if a page was fetched and held no markers, and None
            when nothing was fetched, so a failed scan is never folded
            into a clean verdict.
        """

        if not self.is_valid_url():
            logging.error(f"Invalid URL: {self.url}")
            return None

        content = self.fetch_page()

        if content is not None:
            if self.analyze_content(content):
                logging.warning(f"Potential verbose error page detected at: {self.url}")
                return True
            else:
                logging.info(f"No sensitive information found at: {self.url}")
                return False
        else:
            return None


def setup_argparse():
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Detects verbose error pages that may expose sensitive information.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout for HTTP requests in seconds (default: 10).")
    parser.add_argument("-u", "--user-agent", type=str, help="Custom User-Agent header.")
    return parser


def main():
    """
    Main function to execute the verbose error page detector.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    detector = VerboseErrorPageDetector(args.url, args.timeout, args.user_agent)
    result = detector.run()
    if result is None:
        print(f"Scan failed: {args.url} could not be fetched, so no verdict was reached.")
        sys.exit(1)
    if result:
        print(f"Potential verbose error page detected at: {args.url}")
    else:
        print(f"No verbose error page detected at: {args.url}")


if __name__ == "__main__":
    main()

# Usage Examples:
#
# 1. Basic usage:
#    python vscan-verbose-error-page-detector.py http://example.com
#
# 2. Specifying a timeout:
#    python vscan-verbose-error-page-detector.py http://example.com -t 5
#
# 3. Specifying a custom User-Agent:
#    python vscan-verbose-error-page-detector.py http://example.com -u "MyCustomScanner/1.0"
#
# Offensive Tool Integration example:
# This tool can be integrated as a module into other web vulnerability scanners. For example, it can be added as a check to identify verbose error pages after performing basic crawling and vulnerability scanning.