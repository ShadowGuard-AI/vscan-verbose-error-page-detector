# vscan-verbose-error-page-detector
Identifies verbose error pages that may expose sensitive information such as internal paths, database details, or framework versions. Scans HTTP responses for common error page patterns and analyzes the content for potentially sensitive disclosures, alerting users to potential information leakage. Error responses are read, not discarded: a 4xx or 5xx body is analyzed like any other page. Matching uses error shaped markers such as stack trace frames, exception class names, and SQL error strings; ordinary words on their own do not flag a page. A target that cannot be fetched ends as a failed scan at a non-zero exit, distinct from a fetched page with no markers. Only http and https URLs are accepted, the timeout must be positive, and a detection warning names the HTTP status and the pattern that matched. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuard-AI/vscan-verbose-error-page-detector`

## Usage
`python3 main.py http://example.com [-t 10] [-u USER_AGENT]`

## Parameters
- `-h`: Show help message and exit
- `-t`: Timeout for HTTP requests in seconds (default: 10)
- `-u`: Custom User-Agent header.

## License
MIT License (see LICENSE)
