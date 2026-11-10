"""FastAPI REST API for phishing URL detection."""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, ValidationError
from slowapi import Limiter
from slowapi.util import get_remote_address
import os

from phishdetect.predict import predict_url, batch_predict, _load_model

app = FastAPI(
    title="Phishing URL Detector API",
    description="Detect whether URLs are phishing or legitimate",
    version="0.1.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
app.state.limiter = limiter
app.add_exception_handler(ValidationError, lambda r, e: JSONResponse(status_code=422, content={"detail": str(e)}))


class URLRequest(BaseModel):
    url: str
    
    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        if not v or not v.strip():
            raise ValueError("URL must not be empty")
        if len(v) > 2048:
            raise ValueError("URL must not exceed 2048 characters")
        return v


class BatchRequest(BaseModel):
    urls: list


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    model_version = "0.1.0"
    try:
        import phishdetect
        model_version = phishdetect.__version__
    except Exception:
        pass
    return {"status": "ok", "model_version": model_version}


@app.get("/")
async def root():
    """Serve the self-contained HTML page."""
    html_path = os.path.join(os.path.dirname(__file__), "html_page.html")
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


@app.get("/model-info")
async def model_info():
    """Get model metadata and independent test metrics."""
    model, metadata = _load_model()
    
    # Try to load independent test metrics
    independent_test = None
    independent_metrics_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "reports", "independent_metrics.json")
    if os.path.exists(independent_metrics_path):
        try:
            import json
            with open(independent_metrics_path) as f:
                independent_test = json.load(f)
        except Exception:
            pass
    
    return {
        "model_type": metadata.get("deployed_model", "XGBoost"),
        "threshold": metadata.get("threshold", 0.5),
        "feature_count": metadata.get("feature_count", 17),
        "independent_test": independent_test
    }


@app.post("/predict")
@limiter.limit("60/minute")
async def predict(request: Request, url_request: URLRequest):
    """Predict whether a single URL is phishing."""
    result = predict_url(url_request.url)
    return result


@app.post("/predict/batch")
async def predict_batch(request: BatchRequest):
    """Predict for multiple URLs (max 100)."""
    if len(request.urls) > 100:
        raise HTTPException(status_code=422, detail="Maximum 100 URLs per batch")
    return {"results": batch_predict(request.urls)}


@limiter.limit("60/minute")
@app.post("/predict-limited")
async def predict_limited(request: URLRequest):
    """Rate-limited predict endpoint."""
    return await predict(request)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)