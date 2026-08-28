# Python SIEM Log Parser

## Overview
Python SIEM Log Parser is a lightweight security analysis tool that parses Linux SSH authentication logs to identify repeated failed login attempts, potential brute-force activity, and suspicious successful authentication following multiple failures.  

The project is designed to simulate a basic SIEM detection workflow by converting raw authentication events into actionable security alerts.

### Security Problem
SOC analysts frequently review authentication logs to identify abnormal login behavior, brute-force attempts, unauthorized access, and other suspicious activity.  

Manually reviewing large volumes of authentication events is inefficient and can make it difficult to quickly identify patterns across multiple login attempts.

### Solution
This project automates part of that analysis by parsing Linux SSH authentication logs, extracting relevant authentication events, tracking failed login attempts by source IP address, and generating alerts when predefined detection conditions are met.

## Features
- Parses Linux SSH authentication logs
- Extracts source IP addresses from authentication events
- Tracks failed authentication attempts by source IP
- Detects repeated failed login attempts
- Identifies possible SSH brute-force activity
- Identifies successful authentication following repeated failures
- Generates security alerts based on detection thresholds
- Writes detected alerts to an output file

## Detection Logic

### Repeated SSH Authentication Failures

**Description:**  
Detects multiple failed SSH authentication attempts originating from the same source IP address.  

**Data Source:**  
Linux SSH authentication logs  

**Detection Condition:**  
Failed authentication attempts >= 3  

**Grouping:**  
Source IP address  

**Example:**  
192.168.1.50 -> Failed login  
192.168.1.50 -> Failed login  
192.168.1.50 -> Failed login  

Result: Possible brute-force activity detected  

### Successful Authentication Following Multiple Failures

**Description:**  
Identifies situations where a source IP generates repeated authentication failures followed by a successful login.  

This behavior may warrant additional investigation because it can indicate that repeated credential attempts eventually resulted in successful authentication.  

**Detection Concept:**  
IF:  
    &emsp;&emsp;multiple authentication failures occur from a source IP  
AND:  
    &emsp;&emsp;that source IP later successfully authenticates  
THEN:  
    &emsp;&emsp;generate a suspicious authentication alert  

These detections are intentionally simple and are designed as a foundation for more advanced detection engineering techniques such as time-based correlation, configuration thresholds, severity classification, and false-possitive handling.  

## Example Input

May 11 20:14:01 server sshd[101]: Failed password for invalid user admin from 192.168.1.50 port 4455 ssh2  
May 11 20:14:05 server sshd[102]: Failed password for root from 192.168.1.50 port 4456 ssh2  
May 11 20:14:10 server sshd[103]: Failed password for user test from 192.168.1.50 port 4457 ssh2  

## Example Detection

Source IP: 192.168.1.50  
Failed Attempts: 3  
Threshold: 3  
Detection: Possible SSH brute-force activity  

## Tools and Technologies
- Python
- VSCode / PyCharm
- Regular Expression (Regex)
- Linux authentication logs
- Git and GitHub

## Skills Demonstrated
- Security Monitoring
- SIEM concepts
- Security automation with Python
- Authentication log analysis
- Detection logic development
- Incident detection
- Regular expression parsing
- Source IP correlation
- Security alert generation

## Project Structure

Python-SIEM-Log-Parser/  
│  
├── src/  
│   └── siem_parser.py  
│  
├── logs/  
│   └── sample_auth.log  
│  
├── tests/  
│   └── test_parser.py  
│  
├── output/  
│   └── .gitkeep  
│  
├── README.md  
├── .gitignore  
└── requirements.txt  

## Roadmap

### Reliability and Testing
[ ] Add unit tests for detection logic  
[ ] Improve malformed-log handling  
[ ] Add additional sample authentication events  
[ ] Add command-line arguments for selecting input files  

### Detection Improvements
[ ] Add confurable detection thresholds  
[ ] Add timestamp extration  
[ ] Add time-based detection windows  
[ ] Add failed login counts by username  
[ ] Add alert severity classifications  
[ ] Add structured JSON or CSV alert output  

### Additional Security Capabilities
[ ] Add IPv6 support  
[ ] Add Windows Event Log authentication support  
[ ] Map detections to MITRE ATT&CK techniques   
[ ] Add IP reputation enrichment  
[ ] Build a dashboard for visualizing detected activity  

## Purpose
This project is intended to strengthen my understanding of how raw security events are parsed, correlated, and transformed into detections within a security monitoring workflow.  

Future development will focus on expanding the parser into a more complete detection-engineering and SOC analysis project.  
