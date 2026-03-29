from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib, os, sys, time, sqlite3
from datetime import datetime
from reputation import get_reputation
from logger import logger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cache import get_cached, set_cached, get_cache_stats

sys.path.append(os.path.dirname(__file__))
from features import extract_features

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'error': str(e)}), 500

# Load model
model = joblib.load('model/phishing_model.pkl')
feature_names = joblib.load('model/feature_names.pkl')
THRESHOLD = 0.35
print("Model loaded.")

# Database
os.makedirs('logs', exist_ok=True)

def init_db():
    conn = sqlite3.connect('logs/requests.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        url TEXT,
        prediction INTEGER,
        probability REAL,
        response_time_ms REAL
    )''')
    conn.commit()
    conn.close()

init_db()

def log_request(url, prediction, probability, response_time):
    conn = sqlite3.connect('logs/requests.db')
    conn.execute('INSERT INTO logs VALUES (NULL,?,?,?,?,?)',
        (datetime.now().isoformat(), url, prediction, probability, response_time))
    conn.commit()
    conn.close()

def predict_url(url):
    try:
        url = str(url).strip()
        if len(url) > 2000:
            url = url[:2000]
        if not url.startswith(('http','ftp','www')):
            url = 'http://' + url
        features = extract_features(url)
        values = [list(features.values())]
        prob = model.predict_proba(values)[0][1]
        pred = 1 if prob >= THRESHOLD else 0
        return pred, round(float(prob), 4)
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return 0, 0.0

def get_threat_level(probability):
    if probability >= 0.75:   return 'DANGEROUS'
    elif probability >= 0.50: return 'SUSPICIOUS'
    elif probability >= 0.35: return 'LOW_RISK'
    return 'SAFE'

# Routes
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'running', 'threshold': THRESHOLD})

@app.route('/predict', methods=['POST'])
@limiter.limit("30 per minute")
def predict():
    start = time.time()
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    cached = get_cached(url)
    if cached:
        cached['cached'] = True
        cached['response_time_ms'] = round((time.time()-start)*1000, 2)
        return jsonify(cached)

    pred, prob = predict_url(url)
    ms = round((time.time()-start)*1000, 2)
    log_request(url, pred, prob, ms)
    logger.info(f"PREDICT | {url[:60]} | {get_threat_level(prob)} | {prob} | {ms}ms")

    result = {
        'url': url,
        'prediction': pred,
        'probability': prob,
        'is_phishing': bool(pred == 1),
        'threat_level': get_threat_level(prob),
        'response_time_ms': ms,
        'cached': False
    }
    set_cached(url, result)
    return jsonify(result)

@app.route('/analyze', methods=['POST'])
def analyze():
    start = time.time()
    data = request.get_json() or {}
    email_text = data.get('email_text', '')
    urls = data.get('urls', [])
    sender = data.get('sender', '')
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400

    results = []
    threat_count = 0
    for url in urls:
        pred, prob = predict_url(url)
        level = get_threat_level(prob)
        if pred == 1: threat_count += 1
        log_request(url, pred, prob, 0)
        logger.info(f"ANALYZE | {url[:60]} | {level} | {prob}")
        results.append({
            'url': url,
            'prediction': pred,
            'probability': prob,
            'threat_level': level,
            'is_phishing': bool(pred == 1)
        })

    ms = round((time.time()-start)*1000, 2)
    return jsonify({
        'sender': sender,
        'total_urls': len(urls),
        'threat_count': threat_count,
        'results': results,
        'response_time_ms': ms
    })

@app.route('/logs', methods=['GET'])
def get_logs():
    conn = sqlite3.connect('logs/requests.db')
    rows = conn.execute(
        'SELECT * FROM logs ORDER BY id DESC LIMIT 20').fetchall()
    conn.close()
    return jsonify([{
        'id': r[0], 'timestamp': r[1], 'url': r[2],
        'prediction': r[3], 'probability': r[4],
        'response_time_ms': r[5]
    } for r in rows])

@app.route('/reputation', methods=['POST'])
def reputation():
    data = request.get_json() or {}
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    result = get_reputation(url)
    return jsonify(result)

@app.route('/cache', methods=['GET'])
def cache_stats():
    return jsonify(get_cache_stats())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)

