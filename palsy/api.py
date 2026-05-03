from __future__ import annotations

import logging
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from fastapi.responses import FileResponse, HTMLResponse

from .models import (
    AssessmentRequest,
    AssessmentResponse,
    Permit,
    ReviewApprovalRequest,
    ReviewApprovalResponse,
    ReviewItem,
    RevokeRequest,
    RevokeResponse,
)
from .pypi_client import PyPIClientError
from .service import FirewallService
from .settings import Settings, get_settings


@lru_cache(maxsize=1)
def get_service() -> FirewallService:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return FirewallService(settings)


def require_api_token(
    settings: Settings = Depends(get_settings),
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> None:
    if not settings.require_api_token:
        return
    if not settings.api_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PALSY_API_TOKEN must be configured before using protected endpoints",
        )
    supplied = x_api_token
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization.split(" ", 1)[1]
    if supplied != settings.api_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing API token")


app = FastAPI(
    title="Palsy",
    version="0.1.0",
    description="PyPI artefact firewall with quarantine, static scanning, optional sandboxing, policy decisions, signed permits, and an internal simple index.",
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/v1/artifacts/pypi/assess",
    response_model=AssessmentResponse,
    dependencies=[Depends(require_api_token)],
)
async def assess_pypi(
    request: AssessmentRequest,
    service: FirewallService = Depends(get_service),
) -> AssessmentResponse:
    try:
        return await service.assess(request)
    except PyPIClientError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.get("/v1/permits/{permit_id}", response_model=Permit)
def get_permit(permit_id: str, service: FirewallService = Depends(get_service)) -> Permit:
    permit = service.permit_by_id(permit_id)
    if not permit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="permit not found or invalid")
    return permit


@app.get("/v1/permits/by-digest/{digest}", response_model=Permit)
def get_permit_by_digest(
    digest: str,
    environment: str | None = None,
    service: FirewallService = Depends(get_service),
) -> Permit:
    permit = service.permit_for_digest(digest, environment)
    if not permit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="valid permit not found")
    return permit


@app.post(
    "/v1/revocations",
    response_model=RevokeResponse,
    dependencies=[Depends(require_api_token)],
)
def revoke(request: RevokeRequest, service: FirewallService = Depends(get_service)) -> RevokeResponse:
    return service.revoke(request.digest, request.reason, request.actor)


@app.get(
    "/v1/reviews",
    response_model=list[ReviewItem],
    dependencies=[Depends(require_api_token)],
)
def reviews(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    service: FirewallService = Depends(get_service),
) -> list[ReviewItem]:
    return service.review_queue(limit)


@app.post(
    "/v1/reviews/{digest}/approve",
    response_model=ReviewApprovalResponse,
    dependencies=[Depends(require_api_token)],
)
def approve_review(
    digest: str,
    request: ReviewApprovalRequest,
    service: FirewallService = Depends(get_service),
) -> ReviewApprovalResponse:
    try:
        return service.approve_review(digest, request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.get("/v1/blast-radius/{digest}")
def blast_radius(digest: str, service: FirewallService = Depends(get_service)) -> dict:
    return service.blast_radius(digest)


@app.get("/simple/{project}/", response_class=HTMLResponse)
def simple_index(project: str, service: FirewallService = Depends(get_service)) -> HTMLResponse:
    return HTMLResponse(service.simple_index(project))


@app.get("/files/{digest}/{filename}")
def files(digest: str, filename: str, service: FirewallService = Depends(get_service)) -> FileResponse:
    path = service.file_by_digest(digest, filename)
    if not path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="artefact not found or not allowed")
    return FileResponse(path, filename=filename)


@app.get("/v1/public-key")
def public_key(service: FirewallService = Depends(get_service)) -> dict[str, str]:
    return {"alg": "Ed25519", "public_key": service.signer.public_key_b64}


@app.get("/")
def root() -> Response:
    return Response(
        content="Palsy. Use /docs for API docs; use /simple/{project}/ for the approved PyPI mirror.\n",
        media_type="text/plain",
    )
