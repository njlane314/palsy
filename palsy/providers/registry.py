from __future__ import annotations

from ..models import Ecosystem, ProviderInfo
from ..settings import Settings
from .base import ArtifactProvider, ProviderError
from .generic import GenericURLProvider
from .npm import NpmProvider
from .oci import OCIProvider
from .pypi import PyPIProvider


class ProviderRegistry:
    def __init__(self, settings: Settings):
        self._providers: dict[Ecosystem, ArtifactProvider] = {
            Ecosystem.pypi: PyPIProvider(
                settings.upstream_pypi,
                timeout_seconds=settings.http_timeout_seconds,
                allow_http=settings.allow_insecure_upstream_http,
            ),
            Ecosystem.npm: NpmProvider(
                settings.upstream_npm,
                timeout_seconds=settings.http_timeout_seconds,
                allow_http=settings.allow_insecure_upstream_http,
                token=settings.npm_token,
            ),
            Ecosystem.oci: OCIProvider(
                timeout_seconds=settings.http_timeout_seconds,
                allow_http=settings.allow_insecure_upstream_http,
                username=settings.oci_username,
                password=settings.oci_password,
            ),
            Ecosystem.generic: GenericURLProvider(
                timeout_seconds=settings.http_timeout_seconds,
                allow_http=settings.allow_insecure_upstream_http,
            ),
        }

    def get(self, ecosystem: Ecosystem) -> ArtifactProvider:
        provider = self._providers.get(ecosystem)
        if not provider:
            raise ProviderError(f"unsupported ecosystem: {ecosystem}")
        return provider

    def infos(self) -> list[ProviderInfo]:
        return [
            ProviderInfo(
                ecosystem=provider.ecosystem,
                upstream=getattr(provider, "upstream", None),
                mirrorable=getattr(provider, "mirrorable", False),
                notes=(
                    "internal PyPI/npm mirror available" if getattr(provider, "mirrorable", False)
                    else "assessment/permit mode; no registry mirror implemented"
                ),
            )
            for provider in self._providers.values()
        ]
