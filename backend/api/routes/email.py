from fastapi import APIRouter, File, HTTPException, UploadFile, status

from models.email import EmailParseResponse, EmailUploadError
from services.email_parser import (
    MAX_EML_SIZE_BYTES,
    EmailParseError,
    parse_eml_bytes,
)

router = APIRouter(prefix="/api/email", tags=["Email Upload"])


@router.post(
    "/upload",
    response_model=EmailParseResponse,
    responses={
        400: {"model": EmailUploadError, "description": "Invalid or unreadable .eml file"},
        413: {"model": EmailUploadError, "description": "File too large"},
        422: {"description": "Missing file in multipart form"},
    },
    summary="Upload and parse an .eml file",
)
async def upload_email(
    file: UploadFile = File(..., description="Email file with a .eml extension"),
) -> EmailParseResponse:
    filename = file.filename or ""
    if not filename.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_file", "detail": "No file was provided."},
        )

    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_extension",
                "detail": "Only .eml files are accepted.",
            },
        )

    raw = await file.read()
    if len(raw) > MAX_EML_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail={
                "error": "file_too_large",
                "detail": f"File exceeds the {MAX_EML_SIZE_BYTES // (1024 * 1024)} MB limit.",
            },
        )

    try:
        return parse_eml_bytes(raw, filename)
    except EmailParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_eml", "detail": exc.message},
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "parse_failed",
                "detail": "The email file could not be processed.",
            },
        ) from exc
