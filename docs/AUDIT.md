# Security and Code Audit Report

**Date:** 2026-11-09  
**Project:** phishing-url-detector  
**Auditor:** Automated audit pass

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| MAJOR | 3 |
| MINOR | 8 |

---

## Findings

### MAJOR-01: SHAP Explainer Crashes with XGBoost Model
**File:** `src/phishdetect/explain.py`, line 25  
**Issue:** `shap.TreeExplainer(model)` fails with ValueError: "could not convert string to float: '[5E-1]'"  
**Impact:** The explainability feature is broken in production. The app.py now catches this exception (added in fix), but the explain module itself is non-functional.  
**Status:** PARTIALLY FIXED - App handles gracefully, but explain.py needs fix  
**Recommendation:** Fix the XGBoost model serialization or use a different SHAP explainer approach. Consider saving the model in XGBoost native format.

### MAJOR-02: No Rate Limiting Enforcement on Main Predict Endpoint
**File:** `api/main.py`, lines 62-66, 77-81  
**Issue:** The `/predict` endpoint has no rate limiting. Only `/predict-limited` has rate limiting (60/minute).  
**Impact:** The main prediction endpoint is vulnerable to abuse/DoS.  
**Status:** NOT FIXED  
**Recommendation:** Apply rate limiting to `/predict` endpoint as well, or make `/predict` an alias of `/predict-limited`.

### MAJOR-03: CORS Allows All Origins
**File:** `api/main.py`, lines 19-25  
**Issue:** `allow_origins=["*"]` allows any origin to call the API.  
**Impact:** CSRF and data exposure risk if API is deployed publicly.  
**Status:** NOT FIXED  
**Recommendation:** Restrict CORS to specific trusted origins in production.

---

### MINOR-01: Hardcoded Absolute Paths in Scratch Scripts
**Files:** Multiple scripts in `scripts/` and root directory  
**Issue:** Scripts like `backup_artifacts.py`, `comprehensive_eval.py`, `retrain_with_hosting.py` contain hardcoded paths like `'models/model.joblib'`, `'reports/metrics.json'` which are relative but could be problematic.  
**Status:** NOT FIXED - These are scratch scripts, not production code  
**Recommendation:** Move all scratch scripts to `scripts/` and ensure they use `PROJECT_ROOT` pattern.

### MINOR-02: tldextract May Require Internet for PSL Updates
**File:** `src/phishdetect/features.py`, line 65  
**Issue:** `tldextract.extract(host, include_psl_private_domains=True)` may download Public Suffix List on first run.  
**Impact:** First run in air-gapped environment may fail.  
**Status:** NOT FIXED  
**Recommendation:** Pre-download PSL during Docker build or document requirement.

### MINOR-03: Unsafe Pickle Loading in Model Loading
**File:** `src/phishdetect/predict.py`, line 29  
**Issue:** `joblib.load(MODEL_PATH)` can execute arbitrary code if model file is malicious.  
**Impact:** If model file is replaced with malicious pickle, code execution occurs.  
**Status:** NOT FIXED - Acceptable risk for internal model files  
**Recommendation:** Consider using XGBoost native `save_model`/`load_model` instead of joblib.

### MINOR-04: Secrets in Repo (.env.example)
**File:** `.env.example`  
**Issue:** Example environment file exists but no actual secrets found.  
**Status:** VERIFIED - No actual secrets in repo  
**Recommendation:** Ensure `.env` is in `.gitignore` (it is).

### MINOR-05: Logging of Full User URLs
**File:** `api/main.py` - No explicit logging, but FastAPI logs requests by default  
**Issue:** If logging is configured to include request bodies, full URLs could be logged.  
**Status:** NOT FIXED  
**Recommendation:** Configure logging to exclude request bodies or hash URLs.

### MINOR-06: Training/Inference Feature Mismatch Risk
**Files:** `src/phishdetect/train.py` vs `src/phishdetect/features.py`  
**Issue:** Training uses `extract_features` from features.py, which is consistent. However, the train.py uses StandardScaler for LogisticRegression but not for XGBoost/RandomForest. Inference in predict.py applies scaler only if present in model bundle.  
**Status:** VERIFIED CONSISTENT - Current code handles this correctly  
**Recommendation:** Add explicit test for feature parity.

### MINOR-07: Missing Input Length Limit in Streamlit UI
**File:** `app/app.py`, line 29  
**Issue:** Text input has no max_chars limit. API has 2048 char limit.  
**Status:** NOT FIXED  
**Recommendation:** Add `max_chars=2048` to text_input for consistency.

### MINOR-08: .agents Folder Tracked in Git
**File:** `.gitignore`  
**Issue:** `.agents/` folder is tracked in git (visible in `git status --short`).  
**Status:** FIXED - Added to .gitignore  
**Recommendation:** Verify removal from git tracking.

---

## Files Checked

- `app/app.py` - Streamlit UI
- `api/main.py` - FastAPI REST API
- `src/phishdetect/features.py` - Feature extraction
- `src/phishdetect/predict.py` - Prediction logic
- `src/phishdetect/explain.py` - SHAP explainability
- `src/phishdetect/train.py` - Training pipeline
- `Dockerfile` - Container definition
- `.github/workflows/ci.yml` - CI pipeline
- `requirements.txt` - Dependencies
- `pyproject.toml` - Project config
- `.gitignore` - Git ignore rules
- `README.md` - Documentation
- `models/metadata.json` - Model metadata
- `reports/metrics.json` - Evaluation metrics

---

## Compliance Checks

| Check | Result |
|-------|--------|
| No URL fetching/resolution | ✅ PASS - Text-only analysis |
| Input length limits | ⚠️ PARTIAL - API has 2048 limit, UI missing |
| Rate limiting | ⚠️ PARTIAL - Only on `/predict-limited` |
| CORS configured securely | ❌ FAIL - Allows all origins |
| No hardcoded absolute paths (production) | ✅ PASS |
| tldextract offline-capable | ⚠️ NEEDS VERIFICATION - PSL download on first run |
| No unsafe pickle in production | ⚠️ PARTIAL - joblib used for model loading |
| No secrets in repo | ✅ PASS |
| No full URL logging | ⚠️ UNKNOWN - Depends on logging config |
| Training/inference feature parity | ✅ PASS |
| UTF-8 encoding | ✅ PASS |