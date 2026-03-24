from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib, os, sys, time, sqlite3
from datetime import datetime
from reputation import get_reputation
from logger import logger

sys.path.append(os.path.dirname(__file__))
from features import extract_features

app = Flask(__name__)
CORS(app)

# -------------------- ERROR HANDLERS --------------------

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
    logger.error(f"Unhandled Exception: {str(e)}")
    return jsonify({'error': str(e)}), 500

# -------------------- LOAD MODEL --------------------

model = joblib.load('model/phishing_model.pkl')
feature_names = joblib.load('model/feature_names.pkl')
THRESHOLD = 0.35

print("Model loaded.")

# -------------------- DATABASE INIT --------------------

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

# -------------------- LOG REQUEST --------------------

def log_request(url, prediction, probability, response_time):
    conn = sqlite3.connect('logs/requests.db')
    conn.execute(
        'INSERT INTO logs VALUES (NULL,?,?,?,?,?)',
        (datetime.now().isoformat(), url, prediction, probability, response_time)
    )
    conn.commit()
    conn.close()

# -------------------- PREDICTION LOGIC --------------------

def predict_url(url):
    try:
        url = str(url).strip()

        # Limit URL length
        if len(url) > 2000:
            url = url[:2000]

        # Add scheme if missing
        if not url.startswith(('http', 'ftp', 'www')):
            url = 'http://' + url

        features = extract_features(url)
        values = [list(features.values())]

        prob = model.predict_proba(values)[0][1]
        pred = 1 if prob >= THRESHOLD else 0

        return pred, round(float(prob), 4)

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return 0, 0.0

# -------------------- THREAT LEVEL --------------------

def get_threat_level(probability):
    if probability >= 0.75:
        return 'DANGEROUS'
    elif probability >= 0.50:
        return 'SUSPICIOUS'
    elif probability >= 0.35:
        return 'LOW_RISK'
    return 'SAFE'

# -------------------- ROUTES --------------------

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'running', 'threshold': THRESHOLD})

# ✅ PREDICT ROUTE
@app.route('/predict', methods=['POST'])
def predict():
    start = time.time()

    data = request.get_json() or {}   # 🔥 FIXED (no crash)
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    pred, prob = predict_url(url)
    ms = round((time.time() - start) * 1000, 2)

    log_request(url, pred, prob, ms)

    # ✅ Structured logging
    logger.info(
        f"PREDICT | URL={url[:60]} | LEVEL={get_threat_level(prob)} | PROB={prob} | TIME={ms}ms"
    )

    return jsonify({
        'url': url,
        'prediction': pred,
        'probability': prob,
        'is_phishing': bool(pred == 1),
        'threat_level': get_threat_level(prob),
        'response_time_ms': ms
    })

# ✅ ANALYZE ROUTE
@app.route('/analyze', methods=['POST'])
def analyze():
    start = time.time()

    data = request.get_json() or {}   # 🔥 FIXED
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

        if pred == 1:
            threat_count += 1

        log_request(url, pred, prob, 0)

        # ✅ Logging for analyze
        logger.info(
            f"ANALYZE | URL={url[:60]} | LEVEL={level} | PROB={prob}"
        )

        results.append({
            'url': url,
            'prediction': pred,
            'probability': prob,
            'threat_level': level,
            'is_phishing': bool(pred == 1)
        })

    ms = round((time.time() - start) * 1000, 2)

    return jsonify({
        'sender': sender,
        'total_urls': len(urls),
        'threat_count': threat_count,
        'results': results,
        'response_time_ms': ms
    })

# ✅ LOGS ROUTE
@app.route('/logs', methods=['GET'])
def get_logs():
    conn = sqlite3.connect('logs/requests.db')
    rows = conn.execute(
        'SELECT * FROM logs ORDER BY id DESC LIMIT 20'
    ).fetchall()
    conn.close()

    return jsonify([{
        'id': r[0],
        'timestamp': r[1],
        'url': r[2],
        'prediction': r[3],
        'probability': r[4],
        'response_time_ms': r[5]
    } for r in rows])

# ✅ REPUTATION ROUTE
@app.route('/reputation', methods=['POST'])
def reputation():
    data = request.get_json() or {}   # 🔥 FIXED
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    result = get_reputation(url)
    return jsonify(result)

# -------------------- RUN APP --------------------

if __name__ == '__main__':
    app.run(debug=True, port=5000)