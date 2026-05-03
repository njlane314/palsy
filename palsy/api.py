from __future__ import annotations

import logging
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from . import __version__
from .models import (
    AssessmentRequest,
    AssessmentResponse,
    LockfileAssessmentRequest,
    LockfileAssessmentResponse,
    Permit,
    ProviderInfo,
    ReviewApprovalRequest,
    ReviewApprovalResponse,
    ReviewItem,
    RevokeRequest,
    RevokeResponse,
    UniversalAssessmentRequest,
    UniversalAssessmentResponse,
)
from .pypi_client import PyPIClientError
from .providers import ProviderError
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
    version=__version__,
    description="Self-hosted package-ingress firewall for PyPI/npm dependency admission, quarantine scanning, signed permits, and internal mirrors where supported.",
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/ecosystems", response_model=list[ProviderInfo])
def ecosystems(service: FirewallService = Depends(get_service)) -> list[ProviderInfo]:
    return service.provider_infos()


@app.post(
    "/v1/artifacts/assess",
    response_model=UniversalAssessmentResponse,
    dependencies=[Depends(require_api_token)],
)
async def assess_universal(
    request: UniversalAssessmentRequest,
    service: FirewallService = Depends(get_service),
) -> UniversalAssessmentResponse:
    try:
        return await service.assess_universal(request)
    except ProviderError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


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


@app.post(
    "/v1/lockfiles/assess",
    response_model=LockfileAssessmentResponse,
    dependencies=[Depends(require_api_token)],
)
async def assess_lockfile(
    request: LockfileAssessmentRequest,
    service: FirewallService = Depends(get_service),
) -> LockfileAssessmentResponse:
    try:
        return await service.assess_lockfile(request)
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


@app.get("/npm/{package:path}")
def npm_packument(
    package: str,
    request: Request,
    service: FirewallService = Depends(get_service),
) -> JSONResponse:
    base_url = str(request.base_url).rstrip("/")
    return JSONResponse(service.npm_packument(package, base_url=base_url))


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
        content=(
            "Palsy. Use /docs for API docs, /simple/{project}/ for approved PyPI, "
            "/npm/{package} for approved npm packuments, and /v1/lockfiles/assess for build permits.\n"
        ),
        media_type="text/plain",
    )
