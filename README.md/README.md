# Phishing Email Detector — Chrome Extension

A real-time phishing detection system for Gmail that identifies malicious and suspicious links using **Machine Learning**, **NLP-based keyword analysis**, and **hybrid threat scoring**. The extension scans URLs inside email content, classifies their risk level, and warns users before they interact with potentially harmful links.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Tech Stack](#tech-stack)
- [Machine Learning Performance](#machine-learning-performance)
- [Model Comparison](#model-comparison)
- [How It Works](#how-it-works)
- [Threat Levels](#threat-levels)
- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Benchmark Summary](#benchmark-summary)
- [Use Cases](#use-cases)
- [Resume Description](#resume-description)
- [Future Improvements](#future-improvements)

---

## Project Overview

Phishing remains one of the most common and damaging cyber threats, often delivered through deceptive email links that trick users into revealing sensitive information. This project addresses that problem by combining a trained **Machine Learning classifier** with **rule-based NLP analysis** to detect suspicious URLs and phishing signals directly inside Gmail.

The system is composed of:

- A **Chrome Extension** that scans email content in Gmail
- A **Flask REST API** for URL and email analysis
- A **Random Forest model** trained on **549,000 URLs**
- A **hybrid scoring pipeline** combining ML predictions with phishing keyword signals
- **Threat visualization** and **click blocking** for dangerous links
- **SQLite logging** for monitoring and audit purposes
- **PhishTank integration** for external reputation checking

---

## Key Features

- Real-time phishing link scanning inside Gmail
- Machine Learning model trained on **549,000 URLs**
- **ROC-AUC: 0.9491**
- **4-tier threat classification**
  - **DANGEROUS**
  - **SUSPICIOUS**
  - **LOW RISK**
  - **SAFE**
- NLP keyword detection from email body content
- Hybrid scoring using **Machine Learning + NLP**
- Click blocking for dangerous links
- Trusted domain whitelist support
- Live popup dashboard with scanning statistics
- SQLite-based request and prediction logging
- PhishTank reputation integration
- Automated API test suite with **23/23 tests passing**

---

## System Architecture

```text
Chrome Extension (Gmail)
        │
        │ POST {url, email_text}
        ▼
Flask REST API (Port 5000)
        │
   ┌────┴────┐
   │         │
Feature   NLP Score
Extractor (keywords)
   │         │
   └────┬────┘
        │
   Hybrid Scoring
        ▼
Random Forest Model
(549k URLs, ROC-AUC 0.9491)
        │
        ▼
Threat Level + Probability
        │
        ▼
Visual Warning Badge in Gmail
Tech Stack
Layer	Technology
Machine Learning	Python, scikit-learn, Random Forest
Backend API	Python, Flask, SQLite
Feature Extraction	tldextract, python-whois
Browser Extension	JavaScript, Chrome Extension Manifest V3
Reputation Intelligence	PhishTank
Machine Learning Performance
Metric	Score
Test Accuracy	89.98%
ROC-AUC	0.9491
Phishing Recall (t = 0.35)	83.4%
Average Prediction Latency	128 ms
Automated Test Suite	23/23 passing
Model Comparison
Model	Accuracy	ROC-AUC
Random Forest	90.15%	0.9513
Gradient Boosting	85.72%	0.9005
Logistic Regression	81.46%	0.7935

The Random Forest model was selected because it delivered the best balance of accuracy, recall, and ROC-AUC, making it the most effective choice for phishing detection in this system.

How It Works
The Chrome extension monitors Gmail email content and extracts links.
Each URL, along with relevant email text, is sent to the Flask backend.
The backend performs:
URL feature extraction
NLP-based phishing keyword analysis
Reputation lookup using PhishTank
These signals are combined using a hybrid scoring approach.
The final result is mapped to one of four threat levels.
The extension displays a visual warning badge near suspicious or dangerous links.
Dangerous links can be blocked before the user clicks them.
Threat Levels
Threat Level	Description
DANGEROUS	Highly likely phishing or malicious link
SUSPICIOUS	Strong indicators of phishing behavior
LOW RISK	Minor suspicious characteristics detected
SAFE	No significant phishing indicators found
Project Structure
phishing-detector/
├── backend/
│   ├── app.py                # Flask API
│   ├── features.py           # URL feature extraction
│   ├── train_model.py        # Model training pipeline
│   ├── evaluate.py           # Model evaluation script
│   ├── reputation.py         # PhishTank integration
│   ├── benchmark.py          # Latency benchmarking
│   ├── test_api.py           # Automated API tests
│   ├── model_card.md         # Model documentation
│   └── model/
│       ├── phishing_model.pkl
│       └── feature_names.pkl
│
└── extension/
    ├── manifest.json
    ├── content.js
    ├── popup.html
    ├── popup.js
    ├── background.js
    └── styles.css
Setup Instructions
1. Clone the Repository
git clone <your-repo-url>
cd phishing-detector
2. Backend Setup
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python train_model.py
python app.py

The Flask server should start at:

http://127.0.0.1:5000
3. Load the Chrome Extension
Open Google Chrome
Go to chrome://extensions
Enable Developer mode
Click Load unpacked
Select the extension/ folder
Open Gmail — the extension will begin scanning automatically
API Endpoints
Endpoint	Method	Description
/health	GET	Check backend server status
/predict	POST	Predict phishing probability for a single URL
/analyze	POST	Analyze URL + email content using hybrid scoring
/reputation	POST	Query PhishTank reputation
/logs	GET	Retrieve recent scan and prediction logs
Testing

Run the backend API test suite using:

python test_api.py

Expected result:

23/23 tests passing

Benchmark Summary

Average backend prediction latency: 128 ms
Supports real-time Gmail scanning
Efficient hybrid pipeline for browser-integrated threat detection
Automated API testing confirms backend stability and endpoint correctness

Use Cases

Detect phishing links inside Gmail in real time
Warn users before clicking suspicious or malicious links
Demonstrate applied Machine Learning in cybersecurity
Showcase end-to-end full-stack ML deployment
Provide a practical browser-based email security solution

Future Improvements

VirusTotal API integration
Domain age and WHOIS-based trust scoring
Fine-tuned NLP model trained on phishing email datasets
User feedback loop for active retraining
Dockerized deployment
Multi-platform support for Outlook and Yahoo Mail
Centralized analytics dashboard for enterprise monitoring

Conclusion

This project demonstrates how Machine Learning can be deployed in a practical cybersecurity application to protect users from phishing attacks in real time. By combining browser extension development, backend API engineering, ML classification, NLP analysis, and threat intelligence integration, the system delivers an end-to-end security solution that is both technically strong and highly relevant for real-world use.