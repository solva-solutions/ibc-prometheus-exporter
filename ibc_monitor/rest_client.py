from __future__ import annotations

import logging
import threading
from typing import List, Optional, Set

import requests

logger = logging.getLogger(__name__)


class RESTClientError(Exception):
    """Base error for REST client failures."""


class RESTQueryError(RESTClientError):
    """Raised when a query cannot be completed against any REST endpoint."""

    def __init__(self, path: str, endpoint: str, cause: Exception | None = None):
        self.path = path
        self.endpoint = endpoint
        self.cause = cause
        self.status_code = getattr(getattr(cause, "response", None), "status_code", None)
        msg = f"REST query failed for {path} on {endpoint or '<empty endpoint>'}"
        if cause is not None:
            msg = f"{msg}: {cause}"
        super().__init__(msg)


class RESTClient:
    """Simple REST client with fallback endpoint support.

    The client will attempt to use the configured primary endpoint and fall back
    to additional endpoints defined in the Cosmos chain-registry if the primary
    becomes unavailable.  Health checks are performed against the gRPC-gateway
    ``node_info`` endpoint which exposes the chain ID of the node.
    """

    def __init__(
        self,
        primary_endpoint: str,
        expected_chain_id: str,
        chain_name: str,
        fallback_endpoints: Optional[List[str]] = None,
        enable_chain_registry_fallbacks: bool = False,
    ):
        self.primary = (primary_endpoint or "").strip().rstrip("/")
        self.expected_chain_id = expected_chain_id
        self.chain_name = chain_name
        self.fallbacks: List[str] = []
        for endpoint in fallback_endpoints or []:
            endpoint = endpoint.strip().rstrip("/")
            if endpoint and endpoint != self.primary and endpoint not in self.fallbacks:
                self.fallbacks.append(endpoint)
        if not self.primary and not self.fallbacks and not enable_chain_registry_fallbacks:
            raise ValueError(f"No REST endpoints configured for chain {expected_chain_id}")
        self.endpoint = self.primary or (self.fallbacks[0] if self.fallbacks else "")
        self.enable_chain_registry_fallbacks = enable_chain_registry_fallbacks
        self._loaded_fallbacks = not enable_chain_registry_fallbacks
        self.unhealthy: Set[str] = set()
        self._lock = threading.Lock()

    def _load_fallbacks(self) -> None:
        """Load REST fallbacks from the Cosmos chain-registry."""
        if not self.enable_chain_registry_fallbacks:
            self._loaded_fallbacks = True
            return
        try:
            url = (
                "https://raw.githubusercontent.com/cosmos/chain-registry/master/"
                f"{self.chain_name}/chain.json"
            )
            resp = requests.get(url, timeout=3)
            resp.raise_for_status()
            data = resp.json()
            for api in data.get("apis", {}).get("rest", []):
                addr = api.get("address", "").strip().rstrip("/")
                if addr and addr != self.primary and addr not in self.fallbacks:
                    self.fallbacks.append(addr)
            logger.info(
                "Loaded %d fallback REST endpoint(s) for chain %s",
                len(self.fallbacks),
                self.chain_name,
            )
        except Exception as e:  # pragma: no cover - network failures
            logger.warning("Failed to load fallback REST endpoints for %s: %s", self.chain_name, e)
        finally:
            self._loaded_fallbacks = True

    def health(self) -> bool:
        """Check the health of the current endpoint and switch if necessary."""
        if not self._loaded_fallbacks:
            self._load_fallbacks()
        endpoints = self.endpoints()
        if not endpoints:
            return False
        with self._lock:
            if len(self.unhealthy) >= len(endpoints):
                self.unhealthy.clear()
        for ep in endpoints:
            with self._lock:
                skip = ep in self.unhealthy
            if skip:
                continue
            try:
                url = f"{ep}/cosmos/base/tendermint/v1beta1/node_info"
                resp = requests.get(url, timeout=3)
                resp.raise_for_status()
                chain_id = resp.json().get("default_node_info", {}).get("network", "")
                if chain_id != self.expected_chain_id:
                    logger.error(
                        "Chain ID mismatch on %s: got %s, expected %s",
                        ep,
                        chain_id,
                        self.expected_chain_id,
                    )
                    with self._lock:
                        self.unhealthy.add(ep)
                    continue
                with self._lock:
                    if ep != self.endpoint:
                        logger.info("Switching endpoint from %s to %s", self.endpoint, ep)
                        self.endpoint = ep
                return True
            except Exception as e:  # pragma: no cover - network failures
                logger.warning("REST health check failed for %s: %s", ep, e)
                with self._lock:
                    self.unhealthy.add(ep)
                continue
        return False

    def endpoints(self) -> List[str]:
        """Return all known endpoints, preserving primary-first ordering."""
        if not self._loaded_fallbacks:
            self._load_fallbacks()
        endpoints = []
        for endpoint in [self.primary] + self.fallbacks:
            if endpoint and endpoint not in endpoints:
                endpoints.append(endpoint)
        if self.endpoint not in endpoints and endpoints:
            self.endpoint = endpoints[0]
        return endpoints

    def query(self, path: str, params: Optional[dict] = None, timeout: int = 3) -> dict:
        """Perform a GET request on the current REST endpoint."""
        if not path.startswith("/"):
            raise ValueError(f"REST query path must start with '/': {path}")

        attempts = 0
        last_error: Exception | None = None
        endpoints = self.endpoints()
        if not endpoints:
            raise RESTQueryError(path, self.endpoint, ValueError("no REST endpoints available"))
        while attempts < len(endpoints):
            url = f"{self.endpoint}{path}"
            logger.debug("GET %s params=%s", url, params)
            try:
                r = requests.get(url, params=params or {}, timeout=timeout)
                logger.debug("Response %s -> %s", url, r.status_code)
                r.raise_for_status()
                return r.json()
            except Exception as e:  # pragma: no cover - network failures
                last_error = e
                logger.warning("REST query failed for %s: %s", url, e)
                with self._lock:
                    self.unhealthy.add(self.endpoint)
                if not self.health():
                    break
                endpoints = self.endpoints()
            attempts += 1
        logger.error("All REST endpoints failed for %s", path)
        raise RESTQueryError(path, self.endpoint, last_error)
