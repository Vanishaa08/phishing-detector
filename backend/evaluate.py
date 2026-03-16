import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
from sklearn.metrics import (confusion_matrix, roc_curve, auc,
    classification_report, ConfusionMatrixDisplay)
from sklearn.model_selection import train_test_split
import joblib, sys, os

sys.path.append(os.path.dirname(__file__))
from features import extract_features

print("="*50)
print("PHISHING DETECTOR — MODEL EVALUATION")
print("="*50)

# Load model and feature names
print("\n[1/5] Loading model...")
model = joblib.load('model/phishing_model.pkl')
feature_names = joblib.load('model/feature_names.pkl')
print(f"Model loaded. Features: {len(feature_names)}")

# Load dataset
print("\n[2/5] Loading dataset...")
df = pd.read_csv('data.csv/phishing_site_urls.csv')
df['label'] = df['Label'].apply(
    lambda x: 1 if str(x).strip().lower() == 'bad' else 0)

# Extract features
print("[3/5] Extracting features (takes 3-5 min)...")
feature_list = []
for url in df['URL']:
    try:
        feature_list.append(extract_features(str(url)))
    except:
        feature_list.append(extract_features('http://error.com'))

X = pd.DataFrame(feature_list)
y = df['label']

# Same split as training
_, X_test, _, y_test = train_test_split(
    X, y, test_size=0.15, random_state=42, stratify=y)

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

os.makedirs('evaluation', exist_ok=True)

# 1 — Classification report
print("\n[4/5] Generating reports...")
print("\nClassification Report:")
print(classification_report(y_test, y_pred,
    target_names=['Safe', 'Phishing']))

# 2 — Confusion matrix
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm,
    display_labels=['Safe', 'Phishing'])
disp.plot(ax=axes[0], colorbar=False)
axes[0].set_title('Confusion Matrix')

# 3 — ROC Curve
fpr, tpr, thresholds = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
axes[1].plot(fpr, tpr, color='darkorange', lw=2,
    label=f'ROC curve (AUC = {roc_auc:.3f})')
axes[1].plot([0, 1], [0, 1], color='navy', lw=1, linestyle='--')
axes[1].set_xlabel('False Positive Rate')
axes[1].set_ylabel('True Positive Rate')
axes[1].set_title('ROC Curve')
axes[1].legend(loc='lower right')

# 4 — Feature importance
importances = model.feature_importances_
feat_imp = pd.DataFrame({
    'feature': feature_names,
    'importance': importances
}).sort_values('importance', ascending=True)

axes[2].barh(feat_imp['feature'], feat_imp['importance'],
    color='steelblue')
axes[2].set_title('Feature Importance')
axes[2].set_xlabel('Importance Score')

plt.tight_layout()
plt.savefig('evaluation/model_evaluation.png', dpi=150,
    bbox_inches='tight')
print("Charts saved → evaluation/model_evaluation.png")

# 5 — Threshold analysis
print("\n[5/5] Threshold analysis...")
print(f"\nROC-AUC Score: {roc_auc:.4f}")
print("\nThreshold comparison:")
print(f"{'Threshold':<12} {'Phishing Recall':<18} {'False Alarm Rate'}")
print("-" * 48)
for thresh in [0.3, 0.35, 0.4, 0.5, 0.6]:
    y_thresh = (y_prob >= thresh).astype(int)
    cm_t = confusion_matrix(y_test, y_thresh)
    recall = cm_t[1,1] / (cm_t[1,0] + cm_t[1,1])
    fpr_t = cm_t[0,1] / (cm_t[0,0] + cm_t[0,1])
    print(f"{thresh:<12} {recall:.3f}{'':12} {fpr_t:.3f}")

print("\n" + "="*50)
print("EVALUATION COMPLETE")
print(f"AUC: {roc_auc:.4f}")
print("Charts: evaluation/model_evaluation.png")
print("="*50)
