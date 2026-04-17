# 🧠 AI Web Security Scanner

> Automated web reconnaissance tool with asynchronous scanning, vulnerability detection, and AI-assisted analysis.

---

## Overview

The **AI Web Security Scanner** is a Python-based tool designed for web security research and educational purposes.

It combines:

- ⚡ Asynchronous directory scanning
- 🔍 HTTP response analysis
- 🧠 AI-assisted vulnerability interpretation
- 📊 Structured reporting system
- 💻 Interactive CLI mode

---

## Demo

.................
.................
.................

---

## Features

- Asynchronous endpoint discovery (high performance)
- Wordlist-based enumeration
- Detection of common vulnerabilities:
  - SQL error exposure
  - XSS reflection
  - Sensitive file exposure
  - Information disclosure
- Risk scoring system
- Optional AI analysis layer
- Clean CLI interface (interactive + manual mode)
- JSON report export

---

## Installation

```bash
git clone https://github.com/your-username/ai-sec-scanner.git
cd ai-sec-scanner
pip install -r requirements.txt 
```
--- 

## Output Example
```bash
[HIGH] /admin
  - SQL error exposure detected
  - Sensitive path accessible

[MEDIUM] /backup
  - Information disclosure detected

[LOW] /robots.txt
  - Interesting endpoint discovered
```
---

## Project Architecture
```bash
Scanner → Async Engine → Analyzer → AI Layer → Report Generator
```
---

## Project Structure
```bash
ai-sec-scanner/
│
├── main.py
├── scanner/
│   ├── async_scanner.py
│   └── wordlist_loader.py
│
├── analyzer/
│   └── analyzer.py
│
├── ai/
│   └── llm_client.py
│
├── wordlists/
├── reports/
└── assets/
```
---

## Disclaimer

This tool is intended for:

Educational purposes
Authorized security testing
Personal research

Do not use against systems without explicit permission.

---

## Tech Stack
Python 3
aiohttp
asyncio
regex engine
optional LLM integration

---

##  Motivation

This project was built to explore:

Real-world asynchronous programming
Web security fundamentals
Automation of reconnaissance tasks
Integration of AI into security tooling
