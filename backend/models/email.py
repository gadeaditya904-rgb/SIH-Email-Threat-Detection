from pydantic import BaseModel, Field


class EmailHeaders(BaseModel):
    from_address: str | None = Field(default=None, alias="from")
    to: str | None = None
    cc: str | None = None
    subject: str | None = None
    date: str | None = None
    reply_to: str | None = Field(default=None, alias="reply-to")
    message_id: str | None = Field(default=None, alias="message-id")
    return_path: str | None = Field(default=None, alias="return-path")
    received: list[str] = Field(default_factory=list)
    authentication_results: list[str] = Field(
        default_factory=list, alias="authentication-results"
    )
    received_spf: list[str] = Field(default_factory=list, alias="received-spf")
    dkim_signature: list[str] = Field(default_factory=list, alias="dkim-signature")

    model_config = {
        "populate_by_name": True,
        "serialize_by_alias": True,
    }


class EmailBody(BaseModel):
    plain_text: str | None = None
    html: str | None = None


class EmailParseResponse(BaseModel):
    filename: str
    headers: EmailHeaders
    body: EmailBody
    urls: list[str] = Field(default_factory=list)


class EmailUploadError(BaseModel):
    detail: str
    error: str
