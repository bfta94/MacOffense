# MacOffense

**Advanced macOS Reconnaissance Toolkit**

---

## Description

MacOffense is an advanced reconnaissance toolkit designed specifically for macOS systems. An comprehensive CLI tool for gathering critical system information.

---

## Features

- Over 40 advanced reconnaissance functions including users, services, kernel modules, network info, installed apps, SUID files, TCC profiles, FileVault status, Homebrew packages, cron jobs, firewall status, and more.
- Real-time CLI output showing scan progress and findings.
- Export reports in JSON, TXT, or CSV formats.
- Native macOS compatibility with no external dependencies.

## Installation

```bash
git clone https://github.com/username/MacOffense.git
cd MacOffense
chmod +x macoffense.py
```

## Usage

Export the report in JSON format:
```bash
python3 macoffense.py --export json --output report.json
```
Export the report in TXT format:
```bash
python3 macoffense.py --export txt --output report.txt
```

Export the report in CSV format:
```bash
python3 macoffense.py --export csv --output report.csv
```
