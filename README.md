# vscan-verbose-error-page-detector
Identifies verbose error pages that may expose sensitive information such as internal paths, database details, or framework versions. Scans HTTP responses for common error page patterns and analyzes the content for potentially sensitive disclosures, alerting users to potential information leakage. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-verbose-error-page-detector`

## Usage
`./vscan-verbose-error-page-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: No description provided
- `-u`: Custom User-Agent header.

## License
Copyright (c) ShadowGuardAI
