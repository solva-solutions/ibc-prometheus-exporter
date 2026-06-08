from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional

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

    Unhealthy endpoints are suppressed for ``unhealthy_ttl`` seconds, after
    which they are automatically retried.  If every known endpoint is marked
    unhealthy before the TTL expires (total-outage case), all entries are
    cleared so that the next ``health()`` call probes them all again.

    When ``enable_chain_registry_fallbacks`` is True the chain-registry list is
    re-fetched every ``registry_refresh_interval`` seconds so that newly-added
    public endpoints are discovered without a process restart.  Existing
    endpoints are never removed from the list; only new ones are appended.
    """

    def __init__(
        self,
        primary_endpoint: str,
        expected_chain_id: str,
        chain_name: str,
        fallback_endpoints: Optional[List[str]] = None,
        enable_chain_registry_fallbacks: bool = False,
        unhealthy_ttl: float = 300.0,
        registry_refresh_interval: float = 3600.0,
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

        # endpoint -> monotonic timestamp when it was marked unhealthy
        self.unhealthy: Dict[str, float] = {}
        self._unhealthy_ttl = unhealthy_ttl

        self._lock = threading.Lock()

        # Chain-registry refresh state
        self._loaded_fallbacks = not enable_chain_registry_fallbacks
        self._fallbacks_last_loaded: float = 0.0
        self._registry_refresh_interval = registry_refresh_interval
        # Prevents concurrent registry fetches (acquire non-blocking; others skip)
        self._fallbacks_lock = threading.Lock()

    # ---- chain-registry ----

    def _load_fallbacks(self) -> None:
        """Load (or refresh) REST fallbacks from the Cosmos chain-registry.

        Only one thread performs the HTTP fetch at a time.  If the lock is
        already held (another thread is refreshing) this call returns
        immediately without blocking.
        """
        if not self.enable_chain_registry_fallbacks:
            self._loaded_fallbacks = True
            return

        if not self._fallbacks_lock.acquire(blocking=False):
            return  # another thread is already refreshing

        try:
            now = time.monotonic()
            # Skip if the list was loaded recently (but always run on first load)
            if self._loaded_fallbacks and now - self._fallbacks_last_loaded < self._registry_refresh_interval:
                return
            try:
                url = (
                    "https://raw.githubusercontent.com/cosmos/chain-registry/master/"
                    f"{self.chain_name}/chain.json"
                )
                resp = requests.get(url, timeout=3)
                resp.raise_for_status()
                data = resp.json()
                added = 0
                for api in data.get("apis", {}).get("rest", []):
                    addr = api.get("address", "").strip().rstrip("/")
                    if addr and addr != self.primary and addr not in self.fallbacks:
                        self.fallbacks.append(addr)
                        added += 1
                if added:
                    logger.info(
                        "Discovered %d new fallback REST endpoint(s) for chain %s (total: %d)",
                        added,
                        self.chain_name,
                        len(self.fallbacks),
                    )
                else:
                    logger.debug(
                        "Chain-registry refresh for %s: no new endpoints", self.chain_name
                    )
            except Exception as e:  # pragma: no cover - network failures
                logger.warning(
                    "Failed to load fallback REST endpoints for %s: %s", self.chain_name, e
                )
            finally:
                self._fallbacks_last_loaded = now
                self._loaded_fallbacks = True
        finally:
            self._fallbacks_lock.release()

    def _registry_refresh_due(self) -> bool:
        return (
            self.enable_chain_registry_fallbacks
            and time.monotonic() - self._fallbacks_last_loaded >= self._registry_refresh_interval
        )

    # ---- endpoint management ----

    def health(self) -> bool:
        """Check the health of the current endpoint and switch if necessary."""
        if not self._loaded_fallbacks or self._registry_refresh_due():
            self._load_fallbacks()

        endpoints = self.endpoints()
        if not endpoints:
            return False

        now = time.monotonic()
        with self._lock:
            # Evict TTL-expired entries so individual endpoints get a second chance
            expired = [ep for ep, ts in self.unhealthy.items() if now - ts >= self._unhealthy_ttl]
            for ep in expired:
                del self.unhealthy[ep]
                logger.debug("Endpoint %s unhealthy TTL expired; retrying", ep)

            # Total-outage recovery: if every endpoint is still unhealthy, clear all and retry
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
                        self.unhealthy[ep] = time.monotonic()
                    continue
                with self._lock:
                    if ep != self.endpoint:
                        logger.info("Switching endpoint from %s to %s", self.endpoint, ep)
                        self.endpoint = ep
                return True
            except Exception as e:  # pragma: no cover - network failures
                logger.warning("REST health check failed for %s: %s", ep, e)
                with self._lock:
                    self.unhealthy[ep] = time.monotonic()
                continue
        return False

    def endpoints(self) -> List[str]:
        """Return all known endpoints, preserving primary-first ordering."""
        if not self._loaded_fallbacks or self._registry_refresh_due():
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
                    self.unhealthy[self.endpoint] = time.monotonic()
                if not self.health():
                    break
                endpoints = self.endpoints()
            attempts += 1
        logger.error("All REST endpoints failed for %s", path)
        raise RESTQueryError(path, self.endpoint, last_error)
