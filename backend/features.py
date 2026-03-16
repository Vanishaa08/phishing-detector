import re
import math
import tldextract
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {'.xyz','.top','.club','.online','.site','.tk',
                   '.ml','.ga','.cf','.gq','.pw','.cc','.su'}

BRAND_NAMES = ['paypal','amazon','google','apple','microsoft','netflix',
               'facebook','instagram','bank','secure','account','verify']

def calculate_entropy(url):
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    length = len(url)
    entropy = 0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features(url):
    features = {}
    url = str(url).strip()

    # Basic URL features
    features['length'] = len(url)
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['slash_count'] = url.count('/')
    features['digit_count'] = sum(c.isdigit() for c in url)
    features['special_char_count'] = len(re.findall(r'[^a-zA-Z0-9]', url))

    # Security signals
    features['has_https'] = 1 if url.startswith('https') else 0
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_at'] = 1 if '@' in url else 0
    features['has_double_slash'] = 1 if '//' in url[7:] else 0
    features['has_port'] = 1 if re.search(r':\d{2,5}', url) else 0

    # Advanced signals
    features['entropy'] = calculate_entropy(url)
    features['has_punycode'] = 1 if 'xn--' in url.lower() else 0

    # TLD and domain analysis
    try:
        ext = tldextract.extract(url)
        tld = '.' + ext.suffix if ext.suffix else ''
        features['suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
        features['subdomain_count'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
        domain_full = ext.domain + tld
        features['brand_in_subdomain'] = 1 if any(
            b in ext.subdomain.lower() for b in BRAND_NAMES) else 0
    except:
        features['suspicious_tld'] = 0
        features['subdomain_count'] = 0
        features['brand_in_subdomain'] = 0

    # Suspicious keywords in URL
    features['suspicious_words'] = 1 if any(
        w in url.lower() for w in
        ['login','secure','verify','update','banking',
         'confirm','account','password','signin','ebayisapi']) else 0

    return features