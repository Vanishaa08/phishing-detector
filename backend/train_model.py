import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, RandomizedSearchCV
from sklearn.metrics import accuracy_score, classification_report
import joblib
import sys, os, time

sys.path.append(os.path.dirname(__file__))
from features import extract_features

print("="*50)
print("PHISHING DETECTOR — MODEL TRAINING")
print("="*50)

# Load dataset
print("\n[1/6] Loading dataset...")
df = pd.read_csv('data.csv/phishing_site_urls.csv')
print(f"Total rows: {len(df)}")
print(f"Columns: {list(df.columns)}")

# Label distribution
print(f"\nLabel distribution:")
print(df['Label'].value_counts())

# Convert labels
df['label'] = df['Label'].apply(lambda x: 1 if str(x).strip().lower() == 'bad' else 0)
print(f"\nPhishing (1): {df['label'].sum()}")
print(f"Safe    (0): {(df['label']==0).sum()}")

# Extract features
print("\n[2/6] Extracting features from 549k URLs...")
print("This will take 3-5 minutes. Please wait...")
start = time.time()

feature_list = []
errors = 0
for i, url in enumerate(df['URL']):
    try:
        feature_list.append(extract_features(str(url)))
    except:
        feature_list.append(extract_features('http://error.com'))
        errors += 1
    if (i+1) % 50000 == 0:
        elapsed = time.time() - start
        print(f"  Processed {i+1:,} / {len(df):,} URLs ({elapsed:.0f}s elapsed)")

print(f"  Done. Errors skipped: {errors}")

# Build feature matrix
feature_df = pd.DataFrame(feature_list)
X = feature_df
y = df['label']
print(f"\nFeature matrix shape: {X.shape}")
print(f"Features used: {list(X.columns)}")

# 70 / 15 / 15 split
print("\n[3/6] Splitting data 70/15/15...")
X_temp, X_test, y_temp, y_test = train_test_split(
    X, y, test_size=0.15, random_state=42, stratify=y)
X_train, X_val, y_train, y_val = train_test_split(
    X_temp, y_temp, test_size=0.1765, random_state=42, stratify=y_temp)

print(f"Train : {len(X_train):,} rows")
print(f"Val   : {len(X_val):,} rows")
print(f"Test  : {len(X_test):,} rows")

# Hyperparameter tuning
print("\n[4/6] Hyperparameter tuning (RandomizedSearchCV)...")
param_dist = {
    'n_estimators': [100, 200, 300],
    'max_depth': [None, 20, 30, 40],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4],
    'max_features': ['sqrt', 'log2']
}
rf = RandomForestClassifier(random_state=42, n_jobs=-1)
search = RandomizedSearchCV(rf, param_dist, n_iter=10,
    cv=3, scoring='accuracy', random_state=42, n_jobs=-1, verbose=1)
search.fit(X_train, y_train)
print(f"Best params: {search.best_params_}")
print(f"Best CV accuracy: {search.best_score_*100:.2f}%")

# Train best model
print("\n[5/6] Training final model with best params...")
best_model = search.best_estimator_
best_model.fit(X_train, y_train)

# Evaluate
print("\n[6/6] Evaluating...")
val_acc = accuracy_score(y_val, best_model.predict(X_val))
test_acc = accuracy_score(y_test, best_model.predict(X_test))
print(f"\nValidation accuracy : {val_acc*100:.2f}%")
print(f"Test accuracy       : {test_acc*100:.2f}%")
print("\nClassification Report (Test Set):")
print(classification_report(y_test, best_model.predict(X_test),
    target_names=['Safe', 'Phishing']))

# Cross validation
print("5-Fold Cross Validation...")
cv_scores = cross_val_score(best_model, X_train, y_train, cv=5, scoring='accuracy', n_jobs=-1)
print(f"CV Scores: {[f'{s*100:.2f}%' for s in cv_scores]}")
print(f"CV Mean  : {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

# Save
os.makedirs('model', exist_ok=True)
joblib.dump(best_model, 'model/phishing_model.pkl')
joblib.dump(list(X.columns), 'model/feature_names.pkl')
print(f"\nModel saved → model/phishing_model.pkl")
print(f"Features saved → model/feature_names.pkl")
print("\n" + "="*50)
print(f"FINAL TEST ACCURACY: {test_acc*100:.2f}%")
print("="*50)
