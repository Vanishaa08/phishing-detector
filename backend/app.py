from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import sys
import os

sys.path.append(os.path.dirname(__file__))
from features import extract_features

app = Flask(__name__)
CORS(app)

# Load trained model
model = joblib.load('model/phishing_model.pkl')
print("Model loaded successfully!")

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = extract_features(url)
    feature_values = [list(features.values())]

    prediction = model.predict(feature_values)[0]
    probability = model.predict_proba(feature_values)[0][1]

    return jsonify({
        'url': url,
        'prediction': int(prediction),
        'probability': round(float(probability), 2),
        'is_phishing': bool(prediction == 1)
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'running'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
