from fastapi import APIRouter, HTTPException, status

from models.url_analysis import (
    UrlAnalysisError,
    UrlAnalysisRequest,
    UrlAnalysisResponse,
)
from services.url_analyzer import MAX_URLS_PER_REQUEST, analyze_urls

router = APIRouter(prefix="/api/email", tags=["URL Analysis"])


@router.post(
    "/url-analysis",
    response_model=UrlAnalysisResponse,
    responses={
        400: {"model": UrlAnalysisError, "description": "Invalid URL analysis request"},
        422: {"description": "Request body is not valid JSON with a urls list"},
    },
    summary="Analyze extracted email URLs for passive threat indicators",
)
async def analyze_email_urls(payload: UrlAnalysisRequest) -> UrlAnalysisResponse:
    if not isinstance(payload.urls, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_urls",
                "detail": "The urls field must be a list of strings.",
            },
        )

    if len(payload.urls) > MAX_URLS_PER_REQUEST:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "too_many_urls",
                "detail": f"A maximum of {MAX_URLS_PER_REQUEST} URLs can be analyzed per request.",
            },
        )

    try:
        return analyze_urls(payload.urls)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "url_analysis_failed",
                "detail": "The URL list could not be analyzed.",
            },
        ) from exc
