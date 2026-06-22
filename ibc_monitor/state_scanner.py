from __future__ import annotations

import time
import logging
from typing import List, Tuple, Dict, Set, Optional
import fnmatch
from requests.exceptions import HTTPError
from urllib.parse import quote_plus
from ibc_monitor.rest_client import RESTClient, RESTQueryError

logger = logging.getLogger(__name__)


class PaginationError(RuntimeError):
    """Raised when a paginated REST endpoint does not make progress."""


ACTIVE_CLIENT_STATUSES = {"active"}
CLOSED_CHANNEL_STATES = {"closed"}


def normalize_ibc_enum(value: str | None, prefix: str = "") -> str:
    """Normalize protobuf enum/status strings into compact lowercase labels."""
    if not value:
        return "unknown"
    normalized = str(value).strip()
    if not normalized:
        return "unknown"
    normalized = normalized.split(".")[-1]
    if prefix and normalized.upper().startswith(prefix.upper()):
        normalized = normalized[len(prefix):]
    normalized = normalized.strip("_").lower()
    return normalized or "unknown"


class StateScanner:
    """
    Scans IBC state starting from a single *home* chain and then explicitly
    queries counterparties using the connection IDs discovered on the home chain.

    Home chain flow:
      client_states (paginated) -> filter by counterparty chain_id (allowlist)
      -> client_connections/{cid} (paginated)
      -> connections/{conn} (single)
      -> channels for {conn} (paginated)

    Counterparty flow:
      For each counterparty chain_id, use the *derived* counterparty.connection_id
      from the home connection state and list channels for that connection.
      No enumeration of /client_states on counterparties.
    """

    def __init__(
        self,
        client: RESTClient,                     # home chain REST client
        cfg,
        counterparty_chain_ids: List[str],
        rest_by_chain: Optional[Dict[str, RESTClient]] = None,  # cp chain_id -> RESTClient
        home_chain_id: Optional[str] = None,
        cp_chain_cfgs: Optional[Dict[str, object]] = None,
    ):
        self.rest = client
        self.cfg = cfg
        self.counterparty_chain_ids = set(counterparty_chain_ids)
        self.rest_by_chain = rest_by_chain or {}
        self.cp_chain_cfgs = cp_chain_cfgs or {}
        self.home_chain_id = home_chain_id or getattr(self.rest, "expected_chain_id", "")

        self.last_scan = 0

        # home-side state (kept for backward compatibility with exporter)
        self.clients: List[str] = []
        self.connections: List[str] = []
        self.client_chain_map: Dict[str, str] = {}
        self.client_status_map: Dict[str, str] = {}
        self.client_counterparty_client_ids: Dict[str, str] = {}
        self.connection_client_map: Dict[str, str] = {}
        # (connection, port, channel, counterparty_port, counterparty_channel, counterparty_chain)
        self.channels: List[Tuple[str, str, str, str, str, str]] = []
        # (chain_id, connection, port, channel) -> state
        self.channel_state_map: Dict[Tuple[str, str, str, str], str] = {}

        # counterparty-side state (optional, informational)
        # cp_connections: chain_id -> list of cp connection ids we scanned
        self.cp_connections: Dict[str, List[str]] = {}
        # (chain_id, client_id) -> status
        self.cp_client_status_map: Dict[Tuple[str, str], str] = {}
        # (cp_chain, connection, port, channel, counterparty_port, counterparty_channel, counterparty_chain)
        self.cp_channels: List[Tuple[str, str, str, str, str, str, str]] = []
        # (chain_id, connection, port, channel) -> state
        self.cp_channel_state_map: Dict[Tuple[str, str, str, str], str] = {}

    # ------------- helpers -------------

    def _max_pages(self) -> int:
        return int(getattr(self.cfg, "max_pagination_pages", 1000))

    def _pagination_limit(self) -> int | None:
        return getattr(self.cfg, "pagination_limit", None)

    @staticmethod
    def _page_path(path: str, next_key: str | None, limit: int | None) -> str:
        params = []
        if next_key:
            params.append(f"pagination.key={quote_plus(next_key)}")
        if limit:
            params.append(f"pagination.limit={limit}")
        if not params:
            return path
        return f"{path}{'&' if '?' in path else '?'}{'&'.join(params)}"

    def _query_all(self, path: str, list_key: str, timeout: int, ignore_404: bool = False):
        """
        Follow pagination.next_key for list endpoints on the *home* REST client.
        Expects: { "<list_key>": [...], "pagination": {"next_key": "<base64>|null"} }
        """
        items: List = []
        next_key = None
        seen_next_keys: Set[str] = set()
        pages = 0
        while True:
            pages += 1
            if pages > self._max_pages():
                raise PaginationError(f"Exceeded max pages for {path}")
            qpath = self._page_path(path, next_key, self._pagination_limit())
            try:
                res = self.rest.query(qpath, timeout=timeout)
            except HTTPError as e:
                if ignore_404 and e.response is not None and e.response.status_code == 404:
                    return []
                raise
            except RESTQueryError as e:
                if ignore_404 and e.status_code == 404:
                    return []
                raise
            items.extend(res.get(list_key, []) or [])
            next_key = (res.get("pagination") or {}).get("next_key")
            if not next_key:
                break
            if next_key in seen_next_keys:
                raise PaginationError(f"Repeated pagination.next_key for {path}")
            seen_next_keys.add(next_key)
        return items

    def _query_all_on(self, rc: RESTClient, path: str, list_key: str, timeout: int, ignore_404: bool = False):
        """Follow pagination.next_key for list endpoints on a *given* REST client (counterparty)."""
        items: List = []
        next_key = None
        seen_next_keys: Set[str] = set()
        pages = 0
        while True:
            pages += 1
            if pages > self._max_pages():
                raise PaginationError(f"Exceeded max pages for {path}")
            qpath = self._page_path(path, next_key, self._pagination_limit())
            try:
                res = rc.query(qpath, timeout=timeout)
            except HTTPError as e:
                if ignore_404 and e.response is not None and e.response.status_code == 404:
                    return []
                raise
            except RESTQueryError as e:
                if ignore_404 and e.status_code == 404:
                    return []
                raise
            items.extend(res.get(list_key, []) or [])
            next_key = (res.get("pagination") or {}).get("next_key")
            if not next_key:
                break
            if next_key in seen_next_keys:
                raise PaginationError(f"Repeated pagination.next_key for {path}")
            seen_next_keys.add(next_key)
        return items

    def _filter_list(self, items: List[str], whitelist: List[str], blacklist: List[str]) -> List[str]:
        if whitelist:
            return [i for i in items if any(fnmatch.fnmatch(i, pat) for pat in whitelist)]
        return [i for i in items if not any(fnmatch.fnmatch(i, pat) for pat in blacklist)]

    def _match_any(self, item: str, whitelist: List[str], blacklist: List[str]) -> bool:
        if whitelist:
            return any(fnmatch.fnmatch(item, pat) for pat in whitelist)
        return not any(fnmatch.fnmatch(item, pat) for pat in blacklist)

    def _cp_channel_filters(self, cp_chain: str):
        cp_cfg = self.cp_chain_cfgs.get(cp_chain)
        if cp_cfg is None:
            return [], []
        return cp_cfg.whitelist_channels, cp_cfg.blacklist_channels

    def _omit_inactive_clients(self) -> bool:
        return bool(getattr(self.cfg, "omit_inactive_clients", False))

    def _omit_closed_channels(self) -> bool:
        return bool(getattr(self.cfg, "omit_closed_channels", False))

    def _client_status_on(self, rc: RESTClient, client_id: str, timeout: int, required: bool) -> str:
        try:
            res = rc.query(
                f"/ibc/core/client/v1/client_status/{quote_plus(client_id)}",
                timeout=timeout,
            )
            return normalize_ibc_enum(res.get("status"), "STATUS_")
        except Exception:
            if required:
                raise
            logger.debug("Unable to fetch status for client %s", client_id, exc_info=True)
            return "unknown"

    @staticmethod
    def _channel_state(channel: dict) -> str:
        return normalize_ibc_enum(channel.get("state"), "STATE_")

    # ------------- main scan -------------

    def scan(self) -> bool:
        now = time.time()
        if now - self.last_scan < self.cfg.state_refresh_interval:
            return True

        # Only scan fully when this scanner runs on the designated *home* chain.
        current_chain = getattr(self.rest, "expected_chain_id", "")
        if current_chain != self.home_chain_id:
            logger.debug(
                "Skipping full scan on non-home chain %s (home=%s)",
                current_chain, self.home_chain_id
            )
            self.last_scan = now
            return True

        home_chain_id = self.home_chain_id
        logger.debug("Scanning IBC state (home=%s)", home_chain_id)

        try:
            # 1) HOME: list all clients, keep only those whose client_state.chain_id is in the counterparty allowlist
            all_clients = self._query_all(
                "/ibc/core/client/v1/client_states",
                "client_states",
                timeout=self.cfg.state_scan_timeout,
            )

            client_chain_map: Dict[str, str] = {}
            local_clients: List[str] = []
            for c in all_clients:
                cid = c.get("client_id")
                chain_id = (c.get("client_state") or {}).get("chain_id")
                if not cid or not chain_id:
                    continue
                if chain_id not in self.counterparty_chain_ids:
                    logger.debug("Skipping client %s with counterparty chain %s", cid, chain_id)
                    continue
                local_clients.append(cid)
                client_chain_map[cid] = chain_id

            filtered_clients = self._filter_list(
                local_clients,
                self.cfg.whitelist_clients,
                self.cfg.blacklist_clients,
            )
            client_status_map: Dict[str, str] = {}
            if filtered_clients:
                active_clients: List[str] = []
                for cid in filtered_clients:
                    status = self._client_status_on(
                        self.rest,
                        cid,
                        self.cfg.state_scan_timeout,
                        required=self._omit_inactive_clients(),
                    )
                    client_status_map[cid] = status
                    if self._omit_inactive_clients() and status not in ACTIVE_CLIENT_STATUSES:
                        logger.debug("Skipping inactive client %s with status %s", cid, status)
                        continue
                    active_clients.append(cid)
                filtered_clients = active_clients
            filtered_client_chain_map = {cid: client_chain_map[cid] for cid in filtered_clients}
            client_status_map = {cid: client_status_map.get(cid, "unknown") for cid in filtered_clients}
            logger.debug("Relevant clients (home): %s", filtered_clients)

            # 2) HOME: for each relevant client -> client_connections (paginated) -> connection state
            connection_client_map: Dict[str, str] = {}
            client_cp_client_ids: Dict[str, str] = {}
            all_conns: List[str] = []
            cp_conn_per_chain: Dict[str, Dict[str, str]] = {}

            for cid in filtered_clients:
                conn_ids = self._query_all(
                    f"/ibc/core/connection/v1/client_connections/{cid}",
                    "connection_paths",
                    timeout=self.cfg.state_scan_timeout,
                    ignore_404=True,
                )
                if not conn_ids:
                    logger.debug("No connections for client %s", cid)
                    continue

                for conn in conn_ids:
                    connection_client_map[conn] = cid
                    try:
                        conn_res = self.rest.query(
                            f"/ibc/core/connection/v1/connections/{conn}",
                            timeout=self.cfg.state_scan_timeout,
                        ).get("connection", {}) or {}
                    except HTTPError as e:
                        if e.response is not None and e.response.status_code == 404:
                            conn_res = {}
                        else:
                            raise
                    except RESTQueryError as e:
                        if e.status_code == 404:
                            conn_res = {}
                        else:
                            raise

                    cp = conn_res.get("counterparty") or {}
                    cp_client_id = cp.get("client_id", "")
                    cp_connection_id = cp.get("connection_id", "")

                    if cp_client_id and cid not in client_cp_client_ids:
                        client_cp_client_ids[cid] = cp_client_id

                    cp_chain = filtered_client_chain_map.get(cid)
                    if cp_chain and cp_connection_id:
                        cp_conn_per_chain.setdefault(cp_chain, {})[cp_connection_id] = cp_client_id

                all_conns.extend(conn_ids)

            filtered_conns = self._filter_list(
                all_conns,
                self.cfg.whitelist_connections,
                self.cfg.blacklist_connections,
            )
            logger.debug("Relevant connections (home): %s", filtered_conns)

            # 3) HOME: channels per relevant connection (paginated)
            chan_list: List[Tuple[str, str, str, str, str, str]] = []
            channel_state_map: Dict[Tuple[str, str, str, str], str] = {}
            for conn in filtered_conns:
                chs = self._query_all(
                    f"/ibc/core/channel/v1/connections/{conn}/channels",
                    "channels",
                    timeout=self.cfg.state_scan_timeout,
                    ignore_404=True,
                )
                if not chs:
                    logger.debug("No channels for connection %s", conn)
                    continue

                local_client = connection_client_map.get(conn, "")
                cp_chain = filtered_client_chain_map.get(local_client, "")
                for ch in chs:
                    port, channel = ch.get("port_id"), ch.get("channel_id")
                    if not port or not channel:
                        continue
                    state = self._channel_state(ch)
                    if self._omit_closed_channels() and state in CLOSED_CHANNEL_STATES:
                        logger.debug("Skipping closed channel %s/%s on %s", port, channel, home_chain_id)
                        continue
                    cp = ch.get("counterparty") or {}
                    cp_port = cp.get("port_id", "")
                    cp_channel = cp.get("channel_id", "")
                    chan_list.append((conn, port, channel, cp_port, cp_channel, cp_chain))
                    channel_state_map[(home_chain_id, conn, port, channel)] = state

            filtered_channels = [
                (conn, p, c, cp_p, cp_c, cp_chain)
                for (conn, p, c, cp_p, cp_c, cp_chain) in chan_list
                if self._match_any(f"{p}/{c}", self.cfg.whitelist_channels, self.cfg.blacklist_channels)
            ]
            filtered_channel_keys = {
                (home_chain_id, conn, p, c)
                for (conn, p, c, _cp_p, _cp_c, _cp_chain) in filtered_channels
            }
            channel_state_map = {
                key: state for key, state in channel_state_map.items()
                if key in filtered_channel_keys
            }

            # 4) COUNTERPARTIES: scan explicitly using cp connection ids from the *home* connection state
            cp_connections: Dict[str, List[str]] = {}
            cp_client_status_map: Dict[Tuple[str, str], str] = {}
            cp_channels: List[Tuple[str, str, str, str, str, str, str]] = []
            cp_channel_state_map: Dict[Tuple[str, str, str, str], str] = {}

            for cp_chain, cp_conn_clients in cp_conn_per_chain.items():
                rc = self.rest_by_chain.get(cp_chain)
                if not rc:
                    logger.debug("No REST client configured for counterparty chain %s; skipping", cp_chain)
                    continue

                try:
                    cp_conn_ids = []
                    for cp_conn, cp_client_id in cp_conn_clients.items():
                        if cp_client_id:
                            status = self._client_status_on(
                                rc,
                                cp_client_id,
                                self.cfg.state_scan_timeout,
                                required=self._omit_inactive_clients(),
                            )
                            cp_client_status_map[(cp_chain, cp_client_id)] = status
                            if self._omit_inactive_clients() and status not in ACTIVE_CLIENT_STATUSES:
                                logger.debug(
                                    "Skipping counterparty connection %s on %s for inactive client %s (%s)",
                                    cp_conn,
                                    cp_chain,
                                    cp_client_id,
                                    status,
                                )
                                continue
                        cp_conn_ids.append(cp_conn)

                    cp_conn_ids_filtered = self._filter_list(
                        cp_conn_ids,
                        self.cfg.whitelist_connections,
                        self.cfg.blacklist_connections,
                    )
                    cp_connections[cp_chain] = cp_conn_ids_filtered

                    for cp_conn in cp_conn_ids_filtered:
                        chs = self._query_all_on(
                            rc,
                            f"/ibc/core/channel/v1/connections/{cp_conn}/channels",
                            "channels",
                            timeout=self.cfg.state_scan_timeout,
                            ignore_404=True,
                        )
                        if not chs:
                            logger.debug("No channels on %s for counterparty %s", cp_conn, cp_chain)
                            continue

                        for ch in chs:
                            port, channel = ch.get("port_id"), ch.get("channel_id")
                            if not port or not channel:
                                continue
                            state = self._channel_state(ch)
                            if self._omit_closed_channels() and state in CLOSED_CHANNEL_STATES:
                                logger.debug("Skipping closed channel %s/%s on %s", port, channel, cp_chain)
                                continue
                            cp = ch.get("counterparty") or {}
                            cp_port = cp.get("port_id", "")
                            cp_channel = cp.get("channel_id", "")
                            cp_whitelist, cp_blacklist = self._cp_channel_filters(cp_chain)
                            if not self._match_any(f"{port}/{channel}", cp_whitelist, cp_blacklist):
                                logger.debug(
                                    "Skipping blacklisted counterparty channel %s/%s on %s",
                                    port,
                                    channel,
                                    cp_chain,
                                )
                                continue
                            cp_channels.append((cp_chain, cp_conn, port, channel, cp_port, cp_channel, home_chain_id))
                            cp_channel_state_map[(cp_chain, cp_conn, port, channel)] = state
                except Exception:
                    logger.warning(
                        "State scan failed for counterparty %s; keeping previous state for this chain",
                        cp_chain,
                        exc_info=True,
                    )
                    # Preserve previous cp state for this chain so the rest of the scan is unaffected
                    if cp_chain in self.cp_connections:
                        cp_connections[cp_chain] = self.cp_connections[cp_chain]
                    for k, v in self.cp_client_status_map.items():
                        if k[0] == cp_chain:
                            cp_client_status_map.setdefault(k, v)
                    for prev_ch in self.cp_channels:
                        if prev_ch[0] == cp_chain:
                            cp_channels.append(prev_ch)
                    for k, v in self.cp_channel_state_map.items():
                        if k[0] == cp_chain:
                            cp_channel_state_map.setdefault(k, v)
        except Exception:
            logger.exception("State scan failed for home chain %s; keeping previous state", home_chain_id)
            return False

        self.clients = filtered_clients
        self.client_chain_map = filtered_client_chain_map
        self.client_status_map = client_status_map
        self.connection_client_map = connection_client_map
        self.client_counterparty_client_ids = client_cp_client_ids
        self.connections = filtered_conns
        self.channels = filtered_channels
        self.channel_state_map = channel_state_map
        self.cp_connections = cp_connections
        self.cp_client_status_map = cp_client_status_map
        self.cp_channels = cp_channels
        self.cp_channel_state_map = cp_channel_state_map
        self.last_scan = now

        logger.info(
            "StateScanner[%s] -> home: %d clients, %d connections, %d channels | "
            "cp: %d chains, %d connections, %d channels",
            home_chain_id,
            len(self.clients), len(self.connections), len(self.channels),
            len(self.cp_connections), sum(len(v) for v in self.cp_connections.values()), len(self.cp_channels)
        )
        return True
