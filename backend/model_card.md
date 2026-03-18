# Model Card — Phishing URL Detector

## Model Details
- Type: Random Forest Classifier
- Library: scikit-learn 1.8.0
- Version: v1.0
- Date: March 2026

## Dataset
- Source: Kaggle — phishing_site_urls.csv
- Size: 549,346 URLs
- Distribution: 392,924 safe / 156,422 phishing
- Split: 70% train / 15% validation / 15% test

## Features (17)
| Feature | Description |
|---|---|
| length | Total URL character count |
| dot_count | Number of dots |
| hyphen_count | Number of hyphens |
| slash_count | Number of slashes |
| digit_count | Number of digits |
| special_char_count | Non-alphanumeric characters |
| has_https | HTTPS usage (binary) |
| has_ip | Raw IP address present (binary) |
| has_at | @ symbol present (binary) |
| has_double_slash | Double slash after domain (binary) |
| has_port | Port number present (binary) |
| entropy | Shannon entropy of URL |
| has_punycode | Punycode/homograph attack (binary) |
| suspicious_tld | Suspicious TLD (.xyz .top etc) |
| subdomain_count | Number of subdomains |
| brand_in_subdomain | Brand name in wrong position |
| suspicious_words | Phishing keywords in URL |

## Performance
| Metric | Score |
|---|---|
| Test Accuracy | 89.98% |
| ROC-AUC | 0.9491 |
| Phishing Recall (t=0.35) | 0.834 |
| False Alarm Rate (t=0.35) | 0.085 |
| CV Mean | 89.91% ± 0.02% |

## Threshold
- Production threshold: 0.35
- Reason: Prioritizes recall over precision for security use case

## Top Features by Importance
1. entropy
2. suspicious_tld
3. length
4. brand_in_subdomain
5. has_ip

## Limitations
- Phishing recall 76% at default threshold
- Does not analyze email body text (NLP model coming Day 17)
- Does not check domain age yet (coming Day 11)
- Sophisticated homograph attacks may bypass detection

## Future Improvements
- Add domain age via WHOIS
- Add PhishTank reputation check
- Add NLP email body analysis
- Retrain with user feedback loop