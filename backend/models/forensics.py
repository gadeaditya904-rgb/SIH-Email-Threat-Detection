from pydantic import BaseModel, Field


class ForensicSummary(BaseModel):
    risk_level: str
    score: int
    confidence: float
    max_score: int = 100


class SenderAnalysis(BaseModel):
    from_address: str | None = Field(default=None, alias="from")
    from_domain: str | None = None
    reply_to: str | None = None
    reply_to_domain: str | None = None
    return_path: str | None = None
    return_path_domain: str | None = None
    message_id: str | None = None
    message_id_domain: str | None = None
    findings: list[str] = Field(default_factory=list)

    model_config = {
        "populate_by_name": True,
        "serialize_by_alias": True,
    }


class AuthenticationAnalysis(BaseModel):
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    authentication_results: list[str] = Field(default_factory=list)
    received_spf: list[str] = Field(default_factory=list)
    dkim_signature_present: bool = False


class ObservedIP(BaseModel):
    ip: str
    version: int
    classification: str
    confidence: str = "observed"


class ReceivedHop(BaseModel):
    hop_index: int
    raw: str
    observed_ips: list[ObservedIP] = Field(default_factory=list)
    position: str | None = None
    notes: list[str] = Field(default_factory=list)


class ForensicIndicator(BaseModel):
    type: str
    severity: str
    description: str
    evidence: str
    confidence: str = "analytical_finding"


class HeaderForensicsResponse(BaseModel):
    summary: ForensicSummary
    sender_analysis: SenderAnalysis
    authentication: AuthenticationAnalysis
    received_chain: list[ReceivedHop] = Field(default_factory=list)
    indicators: list[ForensicIndicator] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    observed_evidence: list[str] = Field(default_factory=list)
    score_breakdown: list[str] = Field(default_factory=list)
