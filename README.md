# Security Log Analyzer

**Real-time security event detection and analysis system for identifying threats in system logs**

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🎯 Overview

A lightweight security monitoring tool that analyzes system logs in real-time to detect suspicious patterns, failed authentication attempts, privilege escalations, and potential security threats. Built to explore concepts from endpoint detection and response (EDR) platforms like CrowdStrike Falcon.

**Key Features:**
- Real-time log ingestion and parsing from multiple sources
- Pattern-based threat detection using regex and heuristics
- Anomaly detection for unusual login patterns and access attempts
- Configurable alerting system for security events
- Dashboard for visualizing detected threats

## 🚀 Why This Project?

Modern cybersecurity relies on rapid threat detection through log analysis. This project implements core concepts from Security Information and Event Management (SIEM) systems:
- **Event correlation**: Identifying related security events across different log sources
- **Behavioral analysis**: Detecting anomalies in authentication patterns
- **Threat intelligence**: Flagging known malicious IP addresses and attack signatures
- **Incident response**: Generating actionable alerts for security teams

## 🏗️ Architecture

```
┌─────────────────┐
│   Log Sources   │  (auth.log, syslog, application logs)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Log Ingestion  │  (File watchers, streaming)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Parser Engine  │  (Regex patterns, field extraction)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Threat Detector │  (Pattern matching, anomaly detection)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Alert Manager   │  (Severity scoring, notifications)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Dashboard     │  (Real-time visualization)
└─────────────────┘
```

## 🔍 Detected Threat Categories

### 1. **Authentication Attacks**
- Brute force login attempts (failed auth threshold)
- Credential stuffing patterns
- Unusual login times or geographic locations
- Multiple failed sudo attempts

### 2. **Privilege Escalation**
- Unexpected privilege changes
- Unauthorized sudo usage
- User account modifications

### 3. **Network Anomalies**
- Connections to known malicious IPs
- Unusual outbound traffic patterns
- Port scanning activity

### 4. **File System Events**
- Modifications to sensitive system files
- Unexpected file access patterns
- Suspicious file downloads or uploads

## 🛠️ Technical Stack

- **Language**: Python 3.9+
- **Log Parsing**: Regular expressions, custom parsers
- **Data Storage**: SQLite (for event history and patterns)
- **Visualization**: Matplotlib / Plotly
- **Configuration**: YAML-based rules engine

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Xiaofeng226/security-log-analyzer.git
cd security-log-analyzer

# Install dependencies
pip install -r requirements.txt

# Configure log sources
cp config.example.yaml config.yaml
# Edit config.yaml with your log file paths

# Run the analyzer
python analyzer.py --config config.yaml
```

## 🎮 Usage

### Basic Usage
```bash
# Analyze a single log file
python analyzer.py --file /var/log/auth.log

# Real-time monitoring mode
python analyzer.py --watch /var/log/auth.log --realtime

# Generate threat report
python analyzer.py --file /var/log/auth.log --report output.html
```

### Custom Rules
```yaml
# config.yaml
rules:
  - name: "Brute Force Detection"
    pattern: "Failed password for .* from (\\S+)"
    threshold: 5
    window: 300  # seconds
    severity: high
    
  - name: "Privilege Escalation"
    pattern: "sudo.*COMMAND=.*"
    severity: medium
```

## 📊 Example Output

```
[2025-01-29 14:32:15] 🚨 HIGH SEVERITY ALERT
Threat: Brute Force Attack Detected
Source IP: 192.168.1.100
Failed Attempts: 12 attempts in 5 minutes
User Targeted: root
Recommendation: Block source IP, review account security

[2025-01-29 14:35:22] ⚠️  MEDIUM SEVERITY ALERT
Threat: Privilege Escalation Attempt
User: john_doe
Action: Attempted sudo access to /etc/shadow
Status: Denied
Recommendation: Review user permissions
```

## 🧪 Testing

```bash
# Run unit tests
python -m pytest tests/

# Test with sample logs
python analyzer.py --file tests/sample_logs/auth.log --debug

# Generate synthetic attack patterns for testing
python tests/generate_test_logs.py
```

## 🔬 How It Works

### 1. Log Ingestion
```python
# Watches log files for new entries
# Supports multiple log formats (syslog, JSON, custom)
# Handles log rotation and file changes
```

### 2. Pattern Matching
```python
# Uses regex patterns to identify security events
# Extracts key fields: timestamp, source IP, user, action
# Maintains state for correlation across events
```

### 3. Threat Detection
```python
# Compares events against detection rules
# Implements sliding window for rate-based detection
# Maintains reputation database for known threats
# Scores events by severity
```

### 4. Alert Generation
```python
# Generates alerts when thresholds exceeded
# Deduplicates similar events
# Provides context and remediation suggestions
# Supports multiple notification channels
```

## 🎓 Learning Objectives

This project helped me understand:
- **Log parsing techniques**: Regular expressions, structured vs unstructured logs
- **Real-time data processing**: Streaming data, buffering, performance optimization
- **Security patterns**: Common attack signatures, MITRE ATT&CK framework
- **Anomaly detection**: Statistical methods, baseline establishment
- **System design**: Building scalable monitoring pipelines

## 🚀 Future Enhancements

- [ ] Machine learning-based anomaly detection
- [ ] Integration with threat intelligence feeds
- [ ] Distributed log collection from multiple hosts
- [ ] Real-time dashboard with WebSocket updates
- [ ] Export to SIEM platforms (Splunk, ELK)
- [ ] Docker containerization for easy deployment
- [ ] Kubernetes operator for cloud deployment

## 📚 Resources & References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Linux Log Files Overview](https://www.loggly.com/ultimate-guide/linux-logging-basics/)
- [CrowdStrike Falcon Platform](https://www.crowdstrike.com/platform/) (Inspiration)

## 🤝 Contributing

This is a learning project, but suggestions and improvements are welcome!

## 📄 License

MIT License - See LICENSE file for details

## 👤 Author

**Xiaofeng Li**
- Harvey Mudd College - CS/Math '27
- LinkedIn: [linkedin.com/in/xiaofeng-li](https://linkedin.com/in/xiaofeng-li-xl)
- Email: xiali@g.hmc.edu

---

**Note**: This is an educational project built to explore cybersecurity concepts. For production security monitoring, use established SIEM solutions.
