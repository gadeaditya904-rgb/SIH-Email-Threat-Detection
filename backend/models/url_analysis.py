from pydantic import BaseModel, Field


class UrlIndicator(BaseModel):
    type: str
    severity: str
    message: str
    score: int


class UrlAnalysisResult(BaseModel):
    url: str
    scheme: str | None = None
    hostname: str | None = None
    port: int | None = None
    path: str | None = None
    has_query: bool = False
    has_fragment: bool = False
    is_ip_address: bool = False
    uses_https: bool = False
    subdomain_count: int = 0
    parse_ok: bool = True
    indicators: list[UrlIndicator] = Field(default_factory=list)
    score: int = 0
    risk_level: str = "low"


class UrlAnalysisRequest(BaseModel):
    urls: list[str] = Field(default_factory=list)


class UrlAnalysisResponse(BaseModel):
    total_urls: int
    analyzed_urls: int
    overall_score: int
    overall_risk_level: str
    results: list[UrlAnalysisResult] = Field(default_factory=list)


class UrlAnalysisError(BaseModel):
    error: str
    detail: str
