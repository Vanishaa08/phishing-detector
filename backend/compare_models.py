import pandas as pd
import time, sys, os
sys.path.append(os.path.dirname(__file__))
from features import extract_features
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score
import joblib

print("Loading dataset...")
df = pd.read_csv('data.csv/phishing_site_urls.csv')
df['label'] = df['Label'].apply(
    lambda x: 1 if str(x).strip().lower() == 'bad' else 0)

print("Extracting features...")
feature_list = []
for url in df['URL']:
    try:
        feature_list.append(extract_features(str(url)))
    except:
        feature_list.append(extract_features('http://error.com'))

X = pd.DataFrame(feature_list)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

models = {
    'Logistic Regression': LogisticRegression(max_iter=1000, n_jobs=-1),
    'Random Forest':       RandomForestClassifier(n_estimators=200,
                            max_depth=30, max_features='log2',
                            min_samples_split=5, random_state=42, n_jobs=-1),
    'Gradient Boosting':   GradientBoostingClassifier(n_estimators=100,
                            random_state=42)
}

print("\n" + "="*60)
print(f"{'Model':<25} {'Accuracy':>10} {'ROC-AUC':>10} {'Time(s)':>10}")
print("="*60)

results = []
for name, model in models.items():
    start = time.time()
    model.fit(X_train, y_train)
    elapsed = round(time.time() - start, 1)
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    print(f"{name:<25} {acc*100:>9.2f}% {auc:>10.4f} {elapsed:>9}s")
    results.append({'Model': name, 'Accuracy': f"{acc*100:.2f}%",
                    'ROC-AUC': f"{auc:.4f}", 'Train Time': f"{elapsed}s"})

print("="*60)
pd.DataFrame(results).to_csv('model/model_comparison.csv', index=False)
print("\nResults saved → model/model_comparison.csv")
