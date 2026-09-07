from fastapi import FastAPI

from api.routes.email import router as email_router
from api.routes.forensics import router as forensics_router
from api.routes.url_analysis import router as url_analysis_router

app = FastAPI(
    title="AI-Powered Email Threat Detection API",
    description="Backend API for the SIH Email Threat Detection Platform",
    version="1.0.0",
)

app.include_router(email_router)
app.include_router(forensics_router)
app.include_router(url_analysis_router)


@app.get("/")
def root():
    return {
        "message": "SIH Email Threat Detection API is running"
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Email Threat Detection Backend"
    }
