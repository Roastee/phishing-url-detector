"""FastAPI REST API for phishing URL detection."""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, ValidationError
from slowapi import Limiter
from slowapi.util import get_remote_address

from phishdetect.predict import predict_url, batch_predict

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