# PhishGuard AI — Real-Time Phishing Email Detector

A Chrome extension that protects Gmail users from phishing attacks using
Machine Learning, NLP analysis, and hybrid threat scoring.

---

## Overview

Phishing remains one of the most prevalent cybersecurity threats, with
attackers increasingly using sophisticated techniques to bypass traditional
defenses. PhishGuard AI addresses this challenge by combining a trained
Machine Learning classifier with NLP-based analysis to detect malicious
URLs directly within Gmail — before users click them.

The system operates in real-time, analyzing email content as users view
their inbox, providing immediate visual warnings and click-blocking
protection for dangerous links.

### Core Capabilities

- Real-time URL scanning inside Gmail emails
- Random Forest classifier trained on 549,000 URLs (94.91% ROC-AUC)
- Hybrid scoring combining ML predictions with NLP keyword analysis
- Click blocking for confirmed dangerous links
- Live dashboard showing scanning statistics and threat summaries
- 23/23 automated API tests ensuring reliability

---

## Key Features

### Security Features

| Feature | Description |
|---|---|
| 4-Tier Threat Classification | DANGEROUS, SUSPICIOUS, LOW RISK, SAFE |
| NLP Keyword Detection | Analyzes email body for phishing indicators |
| PhishTank Integration | External reputation validation |
| Whitelist Support | Trusted domain bypass |
| Click Interception | Blocks navigation to dangerous URLs |

### Technical Capabilities

- 549,000 URLs used for model training
- 94.91% ROC-AUC score
- 128ms average latency for predictions
- SQLite logging for audit trails
- Complete API test coverage (23/23 passing)

---

## System Architecture
```
Chrome Extension (Gmail)
        |
        | URL + email text
        v
Flask REST API (port 5000)
        |
   -----+-----
   |         |
Feature    NLP Keyword
Extractor  Analyzer
   |         |
   -----+-----
        |
        v
Random Forest Model
(549,000 URLs, AUC 0.9491)
        |
        v
Threat Level + Probability
        |
        v
Visual Badge in Gmail
```

### Data Flow

1. Extension monitors Gmail DOM for email content
2. URL extraction occurs when emails are opened
3. Backend API receives URLs and email text
4. Feature extraction analyzes URL structure and metadata
5. NLP analysis scans email for phishing keywords
6. Model prediction generates threat probability
7. Hybrid scoring combines signals into final classification
8. Visual feedback displayed to user with click protection

---

## Tech Stack

| Layer | Technologies |
|---|---|
| Machine Learning | Python, scikit-learn, Random Forest, Pandas, NumPy |
| Backend | Flask, SQLite, tldextract, python-whois |
| Browser Extension | JavaScript, Chrome Extension Manifest V3 |
| Threat Intelligence | PhishTank API |
| Version Control | Git, GitHub |

---

## Model Performance

### Evaluation Metrics

| Metric | Score |
|---|---|
| Test Accuracy | 89.98% |
| ROC-AUC | 0.9491 |
| Phishing Recall (threshold=0.35) | 83.4% |
| Average Latency | 128ms |

### Model Comparison

| Model | Accuracy | ROC-AUC |
|---|---|---|
| Random Forest | 90.15% | 0.9513 |
| Gradient Boosting | 85.72% | 0.9005 |
| Logistic Regression | 81.46% | 0.7935 |

Random Forest achieved the best balance of accuracy, recall, and ROC-AUC
while maintaining acceptable inference latency for real-time protection.

---

## Threat Classification

| Level | Description | Action |
|---|---|---|
| DANGEROUS | Highly likely phishing | Click blocked + warning popup |
| SUSPICIOUS | Strong phishing indicators | Warning displayed |
| LOW RISK | Minor suspicious characteristics | Caution flag shown |
| SAFE | No phishing indicators | Normal behavior |

---

## Project Structure
```
phishing-detector/
|
|-- backend/
|   |-- app.py                  # Main Flask application
|   |-- features.py             # URL feature extraction (17 features)
|   |-- train_model.py          # Model training pipeline
|   |-- evaluate.py             # Performance evaluation
|   |-- reputation.py           # PhishTank API integration
|   |-- benchmark.py            # Latency benchmarking
|   |-- test_api.py             # API test suite (23 tests)
|   |-- model_card.md           # Model documentation
|   |-- requirements.txt        # Python dependencies
|   |
|   `-- model/
|       |-- phishing_model.pkl  # Serialized Random Forest
|       `-- feature_names.pkl   # Feature names for inference
|
`-- extension/
    |-- manifest.json           # Chrome MV3 configuration
    |-- content.js              # Gmail DOM scanner
    |-- background.js           # Service worker
    |-- popup.html              # Dashboard UI
    |-- popup.js                # Dashboard logic
    `-- styles.css              # Badge and tooltip styling
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Google Chrome browser
- Git

### Step 1 — Clone Repository
```bash
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
```

### Step 2 — Backend Setup
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
python train_model.py
python app.py
```

Expected output:
```
Model loaded.
* Running on http://127.0.0.1:5000
```

### Step 3 — Load Chrome Extension

1. Open Chrome and navigate to `chrome://extensions`
2. Enable Developer mode (toggle in top-right corner)
3. Click Load unpacked
4. Select the `extension/` folder
5. Navigate to Gmail — extension activates automatically

---

## Usage

### End Users

1. Open Gmail in Chrome with Flask server running
2. Read emails normally — extension scans automatically
3. Observe color-coded badges next to links
4. Dangerous links are blocked with a warning popup

### Developers
```bash
# Run test suite
cd backend
python test_api.py
# Expected: 23/23 tests passing

# Run latency benchmark
python benchmark.py
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| /health | GET | Server status check |
| /predict | POST | Single URL ML prediction |
| /analyze | POST | Full email hybrid analysis |
| /reputation | POST | PhishTank reputation lookup |
| /logs | GET | Recent scan history |

### Example Request
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-login-secure.xyz"}'
```

### Example Response
```json
{
  "url": "http://paypal-login-secure.xyz",
  "prediction": 1,
  "probability": 0.9497,
  "is_phishing": true,
  "threat_level": "DANGEROUS",
  "response_time_ms": 143.2
}
```

---

## Performance Benchmarks

| Metric | Value |
|---|---|
| Average prediction latency | 128ms |
| Min latency | 58ms |
| Max latency | 178ms |
| Model inference time | 15-20ms |
| API overhead | 100-110ms |

---

## Core Detection Logic

### Feature Engineering (17 URL Features)

- Length-based: URL length, slash count, dot count, digit count
- Character signals: hyphens, special characters, @ symbol, double slash
- Security indicators: HTTPS usage, raw IP address, port number, punycode
- Domain analysis: subdomain count, suspicious TLD, brand in subdomain
- Advanced: Shannon entropy, suspicious keyword presence

### NLP Keyword Analysis

Weighted keyword scoring across 5 categories:
- Urgency triggers (weight: 3)
- Account threats (weight: 4)
- Financial terms (weight: 3)
- Action demands (weight: 2)
- Direct threats (weight: 5)

### Hybrid Scoring
```
ML probability + NLP boost (if score >= 10: +0.15, if >= 5: +0.08)

>= 0.75  -->  DANGEROUS
>= 0.50  -->  SUSPICIOUS
>= 0.35  -->  LOW RISK
 < 0.35  -->  SAFE
```

---

## Challenges and Solutions

**Real-Time Performance**
Challenge: Maintaining under 200ms latency while running ML inference.
Solution: Optimized feature extraction, model serialization with joblib,
and whitelist bypass for trusted domains.

**Gmail DOM Stability**
Challenge: Gmail's dynamic content loading made link detection unreliable.
Solution: Implemented MutationObserver to detect DOM changes and trigger
re-scanning on new content.

**False Positive Management**
Challenge: Legitimate marketing links flagged as suspicious.
Solution: Domain whitelist for trusted providers and threshold tuning
at 0.35 to optimize recall-precision tradeoff.

---

## Future Improvements

| Priority | Feature |
|---|---|
| High | VirusTotal API integration |
| High | Domain age WHOIS scoring |
| Medium | User feedback loop for model retraining |
| Medium | Docker containerized deployment |
| Low | Outlook and Yahoo Mail support |
| Low | Centralized threat analytics dashboard |

---

## License

Distributed under the MIT License.

