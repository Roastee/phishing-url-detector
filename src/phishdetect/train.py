
"""Model training and evaluation module."""
import json
import os
from datetime import datetime
from typing import List
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
from .features import FEATURE_NAMES, extract_features

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "raw", "PhiUSIIL_URL.csv")
MODELS_PATH = os.path.join(PROJECT_ROOT, "models")
REPORTS_PATH = os.path.join(PROJECT_ROOT, "reports")

def load_data(path: str = DATA_PATH) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found at {path}.")
    df = pd.read_csv(path)
    return df

def extract_features_to_df(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    labels = []
    for _, row in df.iterrows():
        rows.append(extract_features(str(row["URL"])))
        labels.append(row["Label"])
    result = pd.DataFrame(rows)
    result["label"] = labels
    return result

def get_domains(urls) -> List[str]:
    import tldextract
    result = []
    for u in urls:
        ex = tldextract.extract(str(u))
        result.append(f"{ex.domain}.{ex.suffix}" if ex.domain else "unknown")
    return result

def train_models(X_train, y_train):
    models = {}
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)
    lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    lr.fit(X_scaled, y_train)
    models["LogisticRegression"] = {"model": lr, "scaler": scaler}
    
    rf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
    rf.fit(X_train, y_train)
    models["RandomForest"] = {"model": rf}
    
    xgb_m = xgb.XGBClassifier(n_estimators=100, max_depth=5, scale_pos_weight=3, objective="binary:logistic", n_jobs=-1, random_state=42)
    xgb_m.fit(X_train, y_train)
    models["XGBoost"] = {"model": xgb_m}
    return models

def evaluate_model(model, X, y, threshold=0.5):
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[:, 1]
        pred = (proba >= threshold).astype(int)
    else:
        pred = model.predict(X)
        proba = pred
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "roc_auc": roc_auc_score(y, proba) if len(np.unique(y)) > 1 else 0.0,
        "confusion_matrix": confusion_matrix(y, pred).tolist(),
    }, proba

def select_best_model(models, X_val, y_val):
    best_m, best_name, best_rec = None, None, 0
    for n, m in models.items():
        _, p = evaluate_model(m["model"], X_val, y_val)
        pred = (p >= 0.5).astype(int)
        rec = recall_score(y_val, pred)
        prec = precision_score(y_val, pred, zero_division=0)
        if rec > best_rec and prec >= 0.5:
            best_rec = rec
            best_m, best_name = m["model"], n
    return best_name, best_m, 0.5

def save_model(model, name, meta):
    os.makedirs(MODELS_PATH, exist_ok=True)
    joblib.dump(model, os.path.join(MODELS_PATH, "model.joblib"))
    with open(os.path.join(MODELS_PATH, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved {name}")

def save_metrics(m):
    os.makedirs(REPORTS_PATH, exist_ok=True)
    with open(os.path.join(REPORTS_PATH, "metrics.json"), "w") as f:
        json.dump(m, f, indent=2)

def main():
    print("Training Pipeline")
    df = load_data()
    feat_df = extract_features_to_df(df)
    X = feat_df[FEATURE_NAMES].values
    y = feat_df["label"].values
    
    np.random.seed(42)
    idx = np.random.permutation(len(X))
    train_end, val_end = int(0.7 * len(X)), int(0.85 * len(X))
    ti, vi, te = idx[:train_end], idx[train_end:val_end], idx[val_end:]
    
    print(f"Train: {len(ti)}, Val: {len(vi)}, Test: {len(te)}")
    models = train_models(X[ti], y[ti])
    
    results = {}
    for n, m in models.items():
        res, _ = evaluate_model(m["model"], X[vi], y[vi])
        results[n] = res
        print(f"{n}: F1={res['f1']:.3f}")
    
    best_n, best_m, thresh = select_best_model(models, X[vi], y[vi])
    print(f"Best: {best_n}")
    final, _ = evaluate_model(best_m, X[te], y[te], thresh)
    
    meta = {"model_name": best_n, "feature_names": FEATURE_NAMES, "threshold": thresh, "training_date": datetime.now().isoformat()}
    save_model(best_m, best_n, meta)
    save_metrics({"in_distribution_test": final, "model_comparison": results, "decision_threshold": thresh})
    print("Done!")
    return best_m, final

if __name__ == "__main__":
    main()
