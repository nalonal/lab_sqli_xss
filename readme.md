# Scanner XSS and SQL Injection
You are hired as a cybersecurity mentor for a small tech startup. The organization is concerned about the security of its web applications and wants a tool to automate the process of checking for common web application security vulnerabilities. The team is particularly interested in identifying issues like Cross-Site Scripting (XSS) and SQL Injection.

## Pre-Installation
- Python Version 3
- Pip

## Install Requirement
This program required beautifulsoup4 library
```
pip install beautifulsoup4
```

## Running Program
Running this program with command (insert URL target)
```
python main.py
```

You can use this List of target to Test (Its Lab For Testing Web Vulnerability):
```
http://testphp.vulnweb.com/search.php
http://testphp.vulnweb.com/
https://sudo.co.il/xss/level0.php ## Test for XSS
http://testphp.vulnweb.com/artists.php?artist=1" ## Test for SQL Injection
```