# 🛡️ PASSGUARD AI

> **Intelligent Password Strength Checker & Cryptographic Defense Analyzer**  
> A cybersecurity mini-project featuring real-time password vulnerability auditing, Shannon entropy calculations, heuristic pattern detection, and a cryptographically secure password generator wrapped in a dark navy-purple cybersecurity dashboard.

---

## 📋 Table of Contents
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Security & Mathematical Architecture](#-security--mathematical-architecture)
- [Privacy & Threat Model](#-privacy--threat-model)
- [Installation & Quickstart](#-installation--quickstart)
- [Usage Guide](#-usage-guide)
- [Testing & Validation](#-testing--validation)

---

## 🌟 Overview

**PASSGUARD AI** bridges the gap between academic information theory and real-world credential security. Traditional password strength meters rely solely on simplistic character counts or arbitrary regex checks. PASSGUARD AI implements:
1. **NIST SP 800-63B Guidelines**: Emphasizing password length and credential blacklist auditing over forced predictable substitutions.
2. **Shannon Entropy Modeling**: Quantifying combinatorial strength in bits: \( H = L \times \log_2(R) \).
3. **Advanced Pattern & Walk Heuristics**: Detecting spatial keyboard walks, consecutive repeating characters, alphabetical/numerical sequences, and leetspeak variations.
4. **CSPRNG Password Generation**: Generating cryptographically secure random passwords and multi-word passphrases using Python's hardware-entropy-backed `secrets` module.
5. **Zero-Trust Privacy**: 100% client-side memory execution with zero telemetry, disk writes, or external API reliance.

---

## 🚀 Key Features

### 1. Password Analyzer
- **Show/Hide Input Toggle**: Protect against shoulder surfing with a live visibility toggle.
- **Length Analysis**: Granular tiering from critical short length to enterprise-grade length.
- **Character Diversity**: Live checks for lowercase, uppercase, digits, and special characters.
- **Heuristic Pattern Detection**:
  - Sequential letters (e.g. `abc`, `xyz`) and numbers (e.g. `123`, `789`).
  - Consecutive repeating sequences (e.g. `aaa`, `1111`).
  - Spatial keyboard walks (e.g. `qwerty`, `asdfgh`, `zxcvbn`).
  - Leetspeak normalization (e.g. `p@ssw0rd` mapped to `password`).
  - Birth year / calendar date patterns (e.g. `1990`-`2030`).
- **Local Dictionary Matching**: Audits passwords against an offline curated list of common breached credentials (`common_passwords.txt`).

### 2. Transparent Strength Meter
- **5-Tier Evaluation**: `Weak`, `Fair`, `Good`, `Strong`, `Very Strong`.
- **Dynamic Visual Progress Bar**: Animated color-coded bar with real-time numeric score (0–100).
- **Inspectable Scoring System**: Clear point breakdown across length, variety, entropy bonuses, and pattern penalties.

### 3. Deep Security Report
- **Categorized Vulnerabilities**: Severity badges (`Critical`, `High`, `Medium`, `Low`) explaining the exact mathematical risk.
- **Why It's Weak**: Explains attacker tactics (rainbow tables, mask attacks, wordlists, GPU brute-force).
- **Actionable Hardening Suggestions**: Concrete steps to elevate the password to maximum resistance.
- **Pass/Fail Security Checklist**: Visual indicators for compliance across 10+ criteria.

### 4. Cryptographically Secure Generator
- **Python `secrets` Module**: Uses OS-level cryptographically secure pseudo-random number generator (CSPRNG).
- **Customizable Length**: 8 to 64 characters.
- **Selective Character Sets**: Toggle uppercase, lowercase, numbers, and symbols with guaranteed inclusion.
- **Ambiguous Character Filter**: Exclude confusing glyphs (`O`, `0`, `l`, `1`, `I`, `|`).
- **Passphrase Mode**: Memorable multi-word diceware-style passphrases with custom separators and numbers.
- **One-Click Copy & Analyze**: Copy instantly or send directly to the Analyzer.

### 5. Illustrative Crack Time Estimation
- **Offline Hash Cracking**: Estimated for a high-performance GPU cluster (~10 billion guesses/sec).
- **Online Attack Rate**: Estimated for rate-limited authentication services (~1,000 requests/sec).
- *Strictly labeled as an illustrative heuristic calculation based on mathematical combinations, not a guaranteed crack time.*

---

## 🛠️ Tech Stack

| Technology | Purpose |
| :--- | :--- |
| **Python 3.10+** | Core programming language |
| **Streamlit** | Web application framework & reactive dashboard |
| **Python `secrets`** | Cryptographically secure pseudo-random number generation (CSPRNG) |
| **Python `re`** | Regular expressions for pattern & sequence detection |
| **Python `math`** | Shannon entropy calculations |
| **HTML5 / CSS3** | Custom dark navy-purple cybersecurity theme |

*Zero external AI API keys or third-party cloud services required.*

---

## 📂 Project Structure

```text
PASSGUARD AI/
├── app.py                  # Main Streamlit web application & cyber UI
├── analyzer.py             # Password analysis engine, entropy & heuristics
├── generator.py            # CSPRNG secure password & passphrase generator
├── common_passwords.txt    # Curated offline dictionary of common breached passwords
├── requirements.txt        # Minimal Python dependencies
├── README.md               # Project documentation & security guide
└── .gitignore              # Standard git exclusions
```

---

## 🧮 Security & Mathematical Architecture

### Information Entropy Formula
Shannon entropy represents the theoretical information density of a password in bits:

$$H = L \times \log_2(R)$$

- **$L$**: Length of the password in characters.
- **$R$**: Active pool size:
  - Lowercase (`a-z`): 26
  - Uppercase (`A-Z`): 26
  - Numbers (`0-9`): 10
  - Special Symbols (`!@#$%...`): 33
  - Full pool: $26 + 26 + 10 + 33 = 95$

### Scoring Model (0 – 100)
1. **Length Points (Up to 45 pts)**: Scales progressively with exponential resistance.
2. **Character Variety (Up to 35 pts)**: Points for each character class plus bonuses for 3+ or all 4 classes.
3. **Entropy & Uniqueness (Up to 15 pts)**: Bonuses for entropy $\ge 45, 65, 80$ bits and unique character ratios.
4. **Pattern Penalties**:
   - Common breached wordlist match: Score capped at 15 (Critical failure).
   - Keyboard walk detected: -15 pts.
   - 3+ repeating characters: -12 pts.
   - Sequential run detected: -10 pts.
   - Monolithic character set: -20 pts.

---

## 🔒 Privacy & Threat Model

PASSGUARD AI is engineered with an uncompromising privacy architecture:
- **Zero Telemetry / No Analytics**: No tracking scripts, Google Analytics, or telemetry hooks.
- **No Network Transmission**: Evaluated passwords never leave local process memory.
- **No Disk or Database Storage**: Passwords are never saved, cached on disk, or written to logs.
- **Air-Gapped Ready**: The application operates without an active internet connection.

---

## 💻 Installation & Quickstart

### Prerequisites
- Python 3.10, 3.11, or 3.12 installed on your system.

### 1. Clone / Navigate to Folder
```bash
cd "c:\Users\Deepika J\Downloads\PASSGUARD AI"
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Application
```bash
streamlit run app.py
```

The application will launch in your default web browser at `http://localhost:8501`.

---

## 📖 Usage Guide

1. **Evaluate a Password**:
   - Type or paste any password into the input field in the **Password Analyzer** tab.
   - Toggle **👁️ Show Password** to view or mask characters.
   - Review your **Overall Defense Score**, **Shannon Entropy**, **Criteria Checklist**, and **Identified Vulnerabilities**.
2. **Generate a Strong Credential**:
   - Switch to the **Secure Password Generator** tab.
   - Choose between **Random Character String** (maximum entropy) or **Memorable Passphrase**.
   - Customize length and character pools.
   - Click **Generate New Password** and click **Send to Analyzer** to instantly audit its security.
3. **Explore Cybersecurity Standards**:
   - Visit the **Security Methodology & Guide** tab to understand NIST SP 800-63B guidelines and attacker techniques.

---

## 🧪 Testing & Validation

PASSGUARD AI includes thorough validation covering weak passwords, strong passwords, sequential heuristics, and dictionary matches:

```bash
python -c "
from analyzer import analyze_password
from generator import generate_password

# Test 1: Weak dictionary password
res1 = analyze_password('password123')
assert res1.strength_level == 'Weak', 'Should be Weak'
assert res1.is_common, 'Should detect common password'

# Test 2: Strong password
res2 = analyze_password('K9#xV!7mP$2qL8*w')
assert res2.score >= 85, 'Should be Strong'

# Test 3: Generator
gen = generate_password(length=16)
assert len(gen) == 16, 'Generator length match'

print('All validation tests passed!')
"
```

---

## 📜 License
Developed as an educational cybersecurity demonstration project. Free to use and adapt for security awareness training.
