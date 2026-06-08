from __future__ import annotations

import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus
from decimal import Decimal, InvalidOperation
from prometheus_client import start_http_server
from ibc_monitor.rest_client import RESTClient
from ibc_monitor.config import Config, ChainConfig
from ibc_monitor.state_scanner import (
    ACTIVE_CLIENT_STATUSES,
    StateScanner,
    normalize_ibc_enum,
)
from ibc_monitor.metrics import (
    REST_HEALTH,
    CLIENT_TRUSTING_PERIOD,
    CLIENT_LAST_UPDATE,
    CLIENT_STATUS,
    CHANNEL_STATE,
    BACKLOG_SIZE,
    BACKLOG_OLDEST_SEQ,
    BACKLOG_OLDEST_TIMESTAMP,
    ACK_BACKLOG_SIZE,
    ACK_OLDEST_SEQ,
    ACK_OLDEST_TIMESTAMP,
    BACKLOG_UPDATED,
    UPDATE_DURATION,
    UPDATE_ERRORS,
)
import datetime
import re

logger = logging.getLogger(__name__)

DURATION_RE = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")
SECONDS_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)s$")

def parse_duration(dur: str) -> int:
    dur = (dur or "").strip()
    if not dur:
        return 0
    seconds_match = SECONDS_DURATION_RE.fullmatch(dur)
    if seconds_match:
        try:
            return int(Decimal(seconds_match.group(1)))
        except InvalidOperation:
            return 0
    m = DURATION_RE.fullmatch(dur)
    if not m or not any(m.groups()):
        return 0
    hours = int(m.group(1) or 0)
    minutes = int(m.group(2) or 0)
    seconds = int(m.group(3) or 0)
    return hours * 3600 + minutes * 60 + seconds

# RFC3339 (with arbitrary fractional seconds) -> epoch seconds
_TS_TZ_RE = re.compile(r"^(?P<prefix>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?(?P<tz>Z|[+\-]\d{2}:\d{2})$")

def _parse_rfc3339_to_epoch(ts: str) -> int | None:
    """
    Parse timestamps like '2025-08-11T11:02:48.284737546+00:00' or with 'Z'.
    We trim fractional seconds to microseconds since datetime.fromisoformat
    only supports up to 6 digits.
    """
    if not ts:
        return None
    try:
        m = _TS_TZ_RE.match(ts.replace("z", "Z"))
        if not m:
            # last resort: try replacing trailing 'Z' and drop fractional part entirely
            t = ts.replace("Z", "+00:00")
            if "." in t:
                base, rest = t.split(".", 1)
                if "+" in rest:
                    _, tz = rest.split("+", 1)
                    t = f"{base}+{tz}"
                elif "-" in rest:
                    _, tz = rest.split("-", 1)
                    t = f"{base}-{tz}"
            return int(datetime.datetime.fromisoformat(t).timestamp())
        prefix = m.group("prefix")
        frac = (m.group("frac") or "")
        tz = m.group("tz")
        if tz == "Z":
            tz = "+00:00"
        if frac:
            # keep up to 6 digits (microseconds), right-pad if needed
            digits = frac[1:]
            digits = (digits[:6]).ljust(6, "0")
            ts_norm = f"{prefix}.{digits}{tz}"
        else:
            ts_norm = f"{prefix}{tz}"
        return int(datetime.datetime.fromisoformat(ts_norm).timestamp())
    except Exception as e:
        logger.debug("Failed to parse RFC3339 timestamp '%s': %s", ts, e)
        return None

BATCH = 100  # sequences per filtered-ack/unreceived_acks request

def _chunked(seqs):
    seqs = list(seqs)
    for i in range(0, len(seqs), BATCH):
        yield seqs[i:i+BATCH]

def _params_repeat(key: str, values):
    return "&".join(f"{key}={quote_plus(str(v))}" for v in values)

class IBCExporter:
    def __init__(self, cfg: Config):
        self.cfg = cfg

        # Determine home chain and counterparties from config
        self.home_chain_cfg: ChainConfig = cfg.home_chain
        self.cp_chain_cfgs = [c for c in cfg.chains if not c.home_chain]
        self.cp_chain_ids = [c.chain_id for c in self.cp_chain_cfgs]

        # Build one REST client for the home chain
        if not self.home_chain_cfg.rests:
            raise ValueError(f"No REST endpoints configured for home chain {self.home_chain_cfg.chain_id}")
        self.home_client = RESTClient(
            self.home_chain_cfg.rests[0],
            self.home_chain_cfg.chain_id,
            self.home_chain_cfg.name,
            fallback_endpoints=self.home_chain_cfg.rests[1:],
            enable_chain_registry_fallbacks=self.cfg.enable_chain_registry_fallbacks,
            unhealthy_ttl=float(getattr(self.cfg, "unhealthy_endpoint_ttl", 300)),
            registry_refresh_interval=float(getattr(self.cfg, "chain_registry_refresh_interval", 3600)),
        )

        # Build REST clients for counterparties (one per chain)
        self.rest_by_chain = {}
        for c in self.cp_chain_cfgs:
            if not c.rests and not self.cfg.enable_chain_registry_fallbacks:
                logger.warning(
                    "No REST endpoints configured for counterparty chain %s; it will be skipped",
                    c.chain_id,
                )
                continue
            primary_rest = c.rests[0] if c.rests else ""
            self.rest_by_chain[c.chain_id] = RESTClient(
                primary_rest,
                c.chain_id,
                c.name,
                fallback_endpoints=c.rests[1:],
                enable_chain_registry_fallbacks=self.cfg.enable_chain_registry_fallbacks,
                unhealthy_ttl=float(getattr(self.cfg, "unhealthy_endpoint_ttl", 300)),
                registry_refresh_interval=float(getattr(self.cfg, "chain_registry_refresh_interval", 3600)),
            )

        # Single scanner rooted at the *home* chain; scanner itself will explicitly query CPs.
        self.scanner = StateScanner(
            client=self.home_client,
            cfg=self.home_chain_cfg,
            counterparty_chain_ids=self.cp_chain_ids,
            rest_by_chain=self.rest_by_chain,
            home_chain_id=self.home_chain_cfg.chain_id,
            cp_chain_cfgs={c.chain_id: c for c in self.cp_chain_cfgs},
        )

        # in-memory tracking
        # key: (chain_id, conn, port, channel) -> {seq: first_seen_ts}
        self.pending_packets = {}
        self.pending_acks = {}
        self._rest_health_labelsets = set()
        self._backlog_labelsets = set()
        self._client_status_labelsets = set()
        self._channel_state_labelsets = set()

    # -------- helpers --------

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

    def _query_all_list(
        self,
        client: RESTClient,
        path: str,
        list_key: str,
        timeout: int | None = None,
    ):
        items = []
        next_key = None
        seen_next_keys = set()
        pages = 0
        limit = getattr(self.cfg, "pagination_limit", None)
        max_pages = getattr(self.cfg, "max_pagination_pages", 1000)
        while True:
            pages += 1
            if pages > max_pages:
                raise RuntimeError(f"Exceeded max pages for {path}")
            qpath = self._page_path(path, next_key, limit)
            res = client.query(qpath, timeout=timeout or 3)
            items.extend(res.get(list_key, []) or [])
            next_key = (res.get("pagination") or {}).get("next_key")
            if not next_key:
                break
            if next_key in seen_next_keys:
                raise RuntimeError(f"Repeated pagination.next_key for {path}")
            seen_next_keys.add(next_key)
        return items

    @staticmethod
    def _parse_sequences(items, channel: str):
        seqs = []
        for item in items:
            try:
                seqs.append(int(item["sequence"]))
            except (KeyError, TypeError, ValueError):
                logger.warning("Skipping malformed packet commitment on %s: %s", channel, item)
        return seqs

    def _set_rest_health(self, chain_id: str, endpoint: str, healthy: bool) -> None:
        if not hasattr(self, "_rest_health_labelsets"):
            self._rest_health_labelsets = set()
        endpoint = endpoint or "unavailable"
        for old_chain_id, old_endpoint in list(self._rest_health_labelsets):
            if old_chain_id == chain_id and old_endpoint != endpoint:
                REST_HEALTH.labels(chain_id=old_chain_id, endpoint=old_endpoint).set(0)
        REST_HEALTH.labels(chain_id=chain_id, endpoint=endpoint).set(1 if healthy else 0)
        self._rest_health_labelsets.add((chain_id, endpoint))

    @staticmethod
    def _metric_labels_tuple(
        chain_id: str,
        connection_id: str,
        port_id: str,
        channel_id: str,
        counterparty_chain_id: str,
        counterparty_port_id: str,
        counterparty_channel_id: str,
    ):
        return (
            chain_id,
            connection_id,
            port_id,
            channel_id,
            counterparty_chain_id,
            counterparty_port_id,
            counterparty_channel_id,
        )

    @staticmethod
    def _metric_labels_dict(label_values):
        return dict(
            chain_id=label_values[0],
            connection_id=label_values[1],
            port_id=label_values[2],
            channel_id=label_values[3],
            counterparty_chain_id=label_values[4],
            counterparty_port_id=label_values[5],
            counterparty_channel_id=label_values[6],
        )

    def _record_send_backlog(self, label_values, pending_key, valid_seqs, now: int) -> None:
        pending = self.pending_packets.setdefault(pending_key, {})
        valid_seq_set = set(valid_seqs)
        for s in list(pending.keys()):
            if s not in valid_seq_set:
                del pending[s]
        for s in valid_seqs:
            if s not in pending:
                pending[s] = now

        size = len(pending)
        oldest_seq = min(pending) if pending else 0
        oldest_ts = pending.get(oldest_seq, 0)
        labels = self._metric_labels_dict(label_values)
        BACKLOG_SIZE.labels(**labels).set(size)
        BACKLOG_OLDEST_SEQ.labels(**labels).set(oldest_seq)
        BACKLOG_OLDEST_TIMESTAMP.labels(**labels).set(oldest_ts)

    def _record_ack_backlog(self, label_values, pending_key, unreceived, now: int) -> None:
        apending = self.pending_acks.setdefault(pending_key, {})
        for s in list(apending.keys()):
            if s not in unreceived:
                del apending[s]
        for s in unreceived:
            if s not in apending:
                apending[s] = now

        aoldest_seq = min(apending) if apending else 0
        aoldest_ts = apending.get(aoldest_seq, 0)
        labels = self._metric_labels_dict(label_values)
        ACK_BACKLOG_SIZE.labels(**labels).set(len(apending))
        ACK_OLDEST_SEQ.labels(**labels).set(aoldest_seq)
        ACK_OLDEST_TIMESTAMP.labels(**labels).set(aoldest_ts)

    def _remove_stale_labelsets(self, metric, attr_name: str, active_labelsets) -> None:
        if not hasattr(self, attr_name):
            setattr(self, attr_name, set())
        previous = getattr(self, attr_name)
        for label_values in previous - active_labelsets:
            try:
                metric.remove(*label_values)
            except KeyError:
                pass
        setattr(self, attr_name, active_labelsets)

    def _record_client_status(
        self,
        active_labelsets,
        chain_id: str,
        client_id: str,
        counterparty_chain_id: str,
        counterparty_client_id: str,
        status: str,
    ) -> None:
        label_values = (
            client_id,
            chain_id,
            counterparty_chain_id,
            counterparty_client_id,
            status or "unknown",
        )
        CLIENT_STATUS.labels(
            client_id=client_id,
            chain_id=chain_id,
            counterparty_chain_id=counterparty_chain_id,
            counterparty_client_id=counterparty_client_id,
            status=status or "unknown",
        ).set(1)
        active_labelsets.add(label_values)

    def _record_channel_state(self, active_labelsets, label_values, state: str) -> None:
        state = state or "unknown"
        labels = self._metric_labels_dict(label_values)
        labels["state"] = state
        CHANNEL_STATE.labels(**labels).set(1)
        active_labelsets.add(tuple(label_values) + (state,))

    def _remove_stale_backlog_metrics(self, active_labelsets) -> None:
        if not hasattr(self, "_backlog_labelsets"):
            self._backlog_labelsets = set()
        stale_labelsets = self._backlog_labelsets - active_labelsets
        for label_values in stale_labelsets:
            for metric in (
                BACKLOG_SIZE,
                BACKLOG_OLDEST_SEQ,
                BACKLOG_OLDEST_TIMESTAMP,
                ACK_BACKLOG_SIZE,
                ACK_OLDEST_SEQ,
                ACK_OLDEST_TIMESTAMP,
            ):
                try:
                    metric.remove(*label_values)
                except KeyError:
                    pass
        self._backlog_labelsets = active_labelsets

    @staticmethod
    def _pending_summary(pending, now: int):
        oldest_seq = min(pending) if pending else 0
        oldest_ts = pending.get(oldest_seq, 0)
        return oldest_seq, oldest_ts, now - oldest_ts if oldest_ts else 0

    @staticmethod
    def _query_client_status(rc: RESTClient, client_id: str, timeout: int) -> str:
        res = rc.query(
            f"/ibc/core/client/v1/client_status/{quote_plus(client_id)}",
            timeout=timeout,
        )
        return normalize_ibc_enum(res.get("status"), "STATUS_")

    def _filtered_ack_sequences(self, client: RESTClient, port: str, channel: str, seqs):
        acked = set()
        if not seqs:
            return acked
        base = f"/ibc/core/channel/v1/channels/{quote_plus(channel)}/ports/{quote_plus(port)}/packet_acknowledgements"
        for batch in _chunked(seqs):
            q = _params_repeat("packet_commitment_sequences", batch)
            res = client.query(f"{base}?{q}")
            for a in res.get("acknowledgements", []) or []:
                try:
                    acked.add(int(a.get("sequence", 0)))
                except (TypeError, ValueError):
                    continue
        return acked

    def _unreceived_acks(self, client: RESTClient, port: str, channel: str, ack_seqs):
        unreceived = set()
        if not ack_seqs:
            return unreceived

        base = f"/ibc/core/channel/v1/channels/{quote_plus(channel)}/ports/{quote_plus(port)}/packet_commitments/{{seqs}}/unreceived_acks"
        for batch in _chunked(ack_seqs):
            seqs_seg = ",".join(str(s) for s in batch)
            res = client.query(base.format(seqs=quote_plus(seqs_seg)))
            for s in res.get("sequences", []) or []:
                try:
                    unreceived.add(int(s))
                except (TypeError, ValueError):
                    continue
        return unreceived

    # ---- consensus timestamp helpers ----

    def _latest_consensus_timestamp(self, rc: RESTClient, client_id: str, now: int) -> int | None:
        # 1) via latest_height from client_state
        try:
            cs = rc.query(f"/ibc/core/client/v1/client_states/{client_id}")
            st = (cs.get("client_state") or {})
            h = (st.get("latest_height") or {})
            rev = h.get("revision_number")
            hei = h.get("revision_height")
            if rev is not None and hei is not None:
                res = rc.query(
                    f"/ibc/core/client/v1/consensus_states/{client_id}/revision/{rev}/height/{hei}"
                )
                ts = ((res.get("consensus_state") or {}).get("timestamp") or "")
                epoch = _parse_rfc3339_to_epoch(ts)
                if epoch is not None:
                    return epoch
        except Exception as e:
            logger.debug("latest consensus by client_state.latest_height failed for %s: %s", client_id, e)

        # 2) fallback: list endpoint -> pick the highest height
        try:
            res = rc.query(f"/ibc/core/client/v1/consensus_states/{client_id}")
            lst = res.get("consensus_states")
            if isinstance(lst, list) and lst:
                def _hkey(el):
                    hh = (el.get("height") or {})
                    return (int(hh.get("revision_number") or 0), int(hh.get("revision_height") or 0))
                last = max(lst, key=_hkey)
                ts = ((last.get("consensus_state") or {}).get("timestamp") or "")
                epoch = _parse_rfc3339_to_epoch(ts)
                if epoch is not None:
                    return epoch
            # some LCDs/tests return a single object at top-level
            ts = ((res.get("consensus_state") or {}).get("timestamp") or "")
            epoch = _parse_rfc3339_to_epoch(ts)
            if epoch is not None:
                return epoch
        except Exception as e:
            logger.debug("fallback consensus states list fetch failed for %s: %s", client_id, e)

        # 3) last resort -> unknown
        return None

    # ---- concurrency helpers ----

    def _check_chain_health(self, chain_id: str, client: RESTClient) -> bool:
        """Run a health check for one chain. Safe to call from a thread pool."""
        try:
            return client.health()
        except Exception:
            logger.exception("Chain %s health check failed", chain_id)
            self._inc_error(chain_id, "health")
            return False

    def _update_home_client_metrics(
        self,
        cid: str,
        home_chain_id: str,
        now: int,
        active_client_status_labelsets: set,
    ) -> None:
        """Fetch and record client-state metrics for a single home-chain client."""
        cp_chain = self.scanner.client_chain_map.get(cid, "")
        cp_client = self.scanner.client_counterparty_client_ids.get(cid, "")
        status = getattr(self.scanner, "client_status_map", {}).get(cid, "unknown")
        self._record_client_status(
            active_client_status_labelsets,
            home_chain_id,
            cid,
            cp_chain,
            cp_client,
            status,
        )
        try:
            cs = self.home_client.query(f"/ibc/core/client/v1/client_states/{cid}")
            client_state = cs.get("client_state", {}) or {}
            tp_str = client_state.get("trusting_period", "") or ""
            tp = parse_duration(tp_str)
            cp_chain = client_state.get("chain_id", "") or cp_chain
            CLIENT_TRUSTING_PERIOD.labels(
                client_id=cid,
                chain_id=home_chain_id,
                counterparty_chain_id=cp_chain,
                counterparty_client_id=cp_client,
            ).set(tp)
            last_ts = self._latest_consensus_timestamp(self.home_client, cid, now)
            if last_ts is not None:
                CLIENT_LAST_UPDATE.labels(
                    client_id=cid,
                    chain_id=home_chain_id,
                    counterparty_chain_id=cp_chain,
                    counterparty_client_id=cp_client,
                ).set(last_ts)
        except Exception as e:
            self._inc_error(home_chain_id, "client_state")
            logger.warning("Home client metrics failed for %s: %s", cid, e)

    def _update_cp_client_metrics(
        self,
        cp_chain: str,
        pairs: set,
        home_chain_id: str,
        now: int,
        active_client_status_labelsets: set,
        health_by_chain: dict,
    ) -> None:
        """Fetch and record client-state metrics for all clients on one counterparty chain."""
        rc = self.rest_by_chain.get(cp_chain)
        if not rc or not health_by_chain.get(cp_chain, False):
            return
        for cp_client, home_client in pairs:
            status = getattr(self.scanner, "cp_client_status_map", {}).get((cp_chain, cp_client))
            if not status:
                try:
                    status = self._query_client_status(
                        rc, cp_client, self.home_chain_cfg.state_scan_timeout
                    )
                except Exception as e:
                    self._inc_error(cp_chain, "client_status")
                    if getattr(self.cfg, "omit_inactive_clients", False):
                        logger.warning(
                            "Counterparty client status failed for %s on %s: %s",
                            cp_client, cp_chain, e,
                        )
                        continue
                    status = "unknown"
            if getattr(self.cfg, "omit_inactive_clients", False) and status not in ACTIVE_CLIENT_STATUSES:
                continue
            self._record_client_status(
                active_client_status_labelsets,
                cp_chain,
                cp_client,
                home_chain_id,
                home_client,
                status,
            )
            try:
                cs_cp = rc.query(f"/ibc/core/client/v1/client_states/{cp_client}")
                cp_state = cs_cp.get("client_state", {}) or {}
                tp_str_cp = cp_state.get("trusting_period", "") or ""
                tp_cp = parse_duration(tp_str_cp)
                CLIENT_TRUSTING_PERIOD.labels(
                    client_id=cp_client,
                    chain_id=cp_chain,
                    counterparty_chain_id=self.home_chain_cfg.chain_id,
                    counterparty_client_id=home_client,
                ).set(tp_cp)
            except Exception as e:
                self._inc_error(cp_chain, "client_state")
                logger.debug("cp client_states failed for %s on %s: %s", cp_client, cp_chain, e)
                continue
            try:
                last_ts_cp = self._latest_consensus_timestamp(rc, cp_client, now)
                if last_ts_cp is not None:
                    CLIENT_LAST_UPDATE.labels(
                        client_id=cp_client,
                        chain_id=cp_chain,
                        counterparty_chain_id=home_chain_id,
                        counterparty_client_id=home_client,
                    ).set(last_ts_cp)
            except Exception as e:
                self._inc_error(cp_chain, "client_state")
                logger.debug("cp consensus_states failed for %s on %s: %s", cp_client, cp_chain, e)

    def _process_home_channel_backlog(
        self,
        channel_info: tuple,
        home_chain_id: str,
        now: int,
        health_by_chain: dict,
        active_labelsets: set,
        active_channel_state_labelsets: set,
        failed_backlog_chains: set,
    ) -> None:
        """Query and record send+ack backlog for a single home-chain channel."""
        conn, port, channel, cp_port, cp_channel, cp_chain = channel_info
        key_home = (home_chain_id, conn, port, channel)
        label_values = self._metric_labels_tuple(
            home_chain_id, conn, port, channel, cp_chain, cp_port, cp_channel
        )
        self._record_channel_state(
            active_channel_state_labelsets,
            label_values,
            getattr(self.scanner, "channel_state_map", {}).get(key_home, "unknown"),
        )
        try:
            sp_items = self._query_all_list(
                self.home_client,
                f"/ibc/core/channel/v1/channels/{channel}/ports/{port}/packet_commitments",
                "commitments",
                timeout=self.home_chain_cfg.state_scan_timeout,
            )
            seqs = self._parse_sequences(sp_items, channel)
            valid_seqs = [
                s for s in seqs
                if not self.cfg.excluded_sequences.is_excluded(channel, s, home_chain_id)
            ]
            self._record_send_backlog(label_values, key_home, valid_seqs, now)
            active_labelsets.add(label_values)
        except Exception as e:
            failed_backlog_chains.add(home_chain_id)
            self._inc_error(home_chain_id, "backlog")
            logger.warning("Send backlog query failed for %s/%s on %s: %s", port, channel, home_chain_id, e)
            return

        rc = self.rest_by_chain.get(cp_chain)
        if not valid_seqs:
            self._record_ack_backlog(label_values, key_home, set(), now)
        elif rc and health_by_chain.get(cp_chain, False):
            try:
                acked_on_cp = self._filtered_ack_sequences(rc, cp_port, cp_channel, valid_seqs)
                unreceived = self._unreceived_acks(self.home_client, port, channel, acked_on_cp)
                self._record_ack_backlog(label_values, key_home, unreceived, now)
            except Exception as e:
                failed_backlog_chains.add(home_chain_id)
                self._inc_error(home_chain_id, "ack")
                logger.warning("Ack backlog query failed for %s/%s on %s: %s", port, channel, home_chain_id, e)
        else:
            failed_backlog_chains.add(home_chain_id)
            self._inc_error(home_chain_id, "ack")
            logger.warning(
                "Ack backlog skipped for %s/%s on %s: counterparty chain %s is unavailable",
                port, channel, home_chain_id, cp_chain,
            )

        pending = self.pending_packets.get(key_home, {})
        apending = self.pending_acks.get(key_home, {})
        oldest_seq, oldest_ts, oldest_age = self._pending_summary(pending, now)
        aoldest_seq, aoldest_ts, aoldest_age = self._pending_summary(apending, now)
        logger.info(
            "[%s %s/%s] backlog=%d oldest=%d age=%ds ack_backlog=%d ack_oldest=%d ack_age=%ds",
            home_chain_id, port, channel,
            len(pending), oldest_seq, oldest_age,
            len(apending), aoldest_seq, aoldest_age,
        )

    def _process_cp_channel_backlog(
        self,
        channel_info: tuple,
        now: int,
        health_by_chain: dict,
        active_labelsets: set,
        active_channel_state_labelsets: set,
        failed_backlog_chains: set,
    ) -> None:
        """Query and record send+ack backlog for a single counterparty-chain channel."""
        cp_chain, cp_conn, port, channel, cp_port, cp_channel, home_chain_id = channel_info
        rc = self.rest_by_chain.get(cp_chain)
        label_values = self._metric_labels_tuple(
            cp_chain, cp_conn, port, channel, home_chain_id, cp_port, cp_channel
        )
        self._record_channel_state(
            active_channel_state_labelsets,
            label_values,
            getattr(self.scanner, "cp_channel_state_map", {}).get(
                (cp_chain, cp_conn, port, channel), "unknown"
            ),
        )
        if not rc or not health_by_chain.get(cp_chain, False):
            failed_backlog_chains.add(cp_chain)
            return

        key_cp = (cp_chain, cp_conn, port, channel)
        try:
            sp_items = self._query_all_list(
                rc,
                f"/ibc/core/channel/v1/channels/{channel}/ports/{port}/packet_commitments",
                "commitments",
                timeout=self.home_chain_cfg.state_scan_timeout,
            )
            seqs = self._parse_sequences(sp_items, channel)
            valid_seqs = [
                s for s in seqs
                if not self.cfg.excluded_sequences.is_excluded(channel, s, cp_chain)
            ]
            self._record_send_backlog(label_values, key_cp, valid_seqs, now)
            active_labelsets.add(label_values)
        except Exception as e:
            failed_backlog_chains.add(cp_chain)
            self._inc_error(cp_chain, "backlog")
            logger.warning("Send backlog query failed for %s/%s on %s: %s", port, channel, cp_chain, e)
            return

        if not valid_seqs:
            self._record_ack_backlog(label_values, key_cp, set(), now)
        else:
            try:
                acked_on_home = self._filtered_ack_sequences(
                    self.home_client, cp_port, cp_channel, valid_seqs
                )
                unreceived_cp = self._unreceived_acks(rc, port, channel, acked_on_home)
                self._record_ack_backlog(label_values, key_cp, unreceived_cp, now)
            except Exception as e:
                failed_backlog_chains.add(cp_chain)
                self._inc_error(cp_chain, "ack")
                logger.warning("Ack backlog query failed for %s/%s on %s: %s", port, channel, cp_chain, e)

        pending = self.pending_packets.get(key_cp, {})
        apending = self.pending_acks.get(key_cp, {})
        oldest_seq, oldest_ts, oldest_age = self._pending_summary(pending, now)
        aoldest_seq, aoldest_ts, aoldest_age = self._pending_summary(apending, now)
        logger.info(
            "[%s %s/%s] backlog=%d oldest=%d age=%ds ack_backlog=%d ack_oldest=%d ack_age=%ds",
            cp_chain, port, channel,
            len(pending), oldest_seq, oldest_age,
            len(apending), aoldest_seq, aoldest_age,
        )

    def run(self):
        # start prometheus server
        start_http_server(self.cfg.port, addr=self.cfg.address)
        logger.info(f"Exporter listening on {self.cfg.address}:{self.cfg.port}")
        while True:
            self.update_metrics()
            time.sleep(self.cfg.update_interval)

    @staticmethod
    def _inc_error(chain_id: str, stage: str) -> None:
        UPDATE_ERRORS.labels(chain_id=chain_id, stage=stage).inc()

    def update_metrics(self):
        started = time.monotonic()
        now = int(time.time())
        home_chain_id = self.home_chain_cfg.chain_id
        active_labelsets = set()
        active_client_status_labelsets = set()
        active_channel_state_labelsets = set()
        failed_backlog_chains = set()
        health_by_chain = {}

        # Health checks for home + counterparties — all chains in parallel
        all_chain_clients = [(home_chain_id, self.home_client)] + list(self.rest_by_chain.items())
        with ThreadPoolExecutor(max_workers=len(all_chain_clients)) as executor:
            health_futures = {
                executor.submit(self._check_chain_health, cid, rc): (cid, rc)
                for cid, rc in all_chain_clients
            }
            for future in as_completed(health_futures):
                cid, rc = health_futures[future]
                healthy = future.result()
                health_by_chain[cid] = healthy
                self._set_rest_health(cid, rc.endpoint, healthy)
        home_healthy = health_by_chain.get(home_chain_id, False)

        if not home_healthy:
            logger.debug("Home chain %s endpoint unhealthy; skipping scan/metrics this cycle", home_chain_id)
            UPDATE_DURATION.labels(chain_id=home_chain_id).set(time.monotonic() - started)
            return

        # Refresh state (home + explicit CP scans)
        if not self.scanner.scan():
            self._inc_error(home_chain_id, "scan")
            UPDATE_DURATION.labels(chain_id=home_chain_id).set(time.monotonic() - started)
            return

        # Build cp-client map (needed by both client-metrics and channel-backlog phases)
        cp_clients_by_chain: dict = {}
        for local_cid in self.scanner.clients:
            cp_chain = self.scanner.client_chain_map.get(local_cid, "")
            cp_client = self.scanner.client_counterparty_client_ids.get(local_cid, "")
            if cp_chain and cp_client:
                cp_clients_by_chain.setdefault(cp_chain, set()).add((cp_client, local_cid))

        # -------- client state metrics (home + counterparties in parallel) --------
        client_tasks: list = [
            (self._update_home_client_metrics, (cid, home_chain_id, now, active_client_status_labelsets))
            for cid in self.scanner.clients
        ] + [
            (self._update_cp_client_metrics, (cp_chain, pairs, home_chain_id, now,
                                               active_client_status_labelsets, health_by_chain))
            for cp_chain, pairs in cp_clients_by_chain.items()
        ]
        n_client_workers = min(getattr(self.cfg, "max_workers", 16), max(len(client_tasks), 1))
        with ThreadPoolExecutor(max_workers=n_client_workers) as executor:
            client_futures = [executor.submit(fn, *args) for fn, args in client_tasks]
            for future in as_completed(client_futures):
                try:
                    future.result()
                except Exception:
                    logger.exception("Unexpected error in client metrics task")

        # -------- backlog metrics (home + counterparty channels in parallel) --------
        n_channels = len(self.scanner.channels) + len(self.scanner.cp_channels)
        n_channel_workers = min(getattr(self.cfg, "max_workers", 16), max(n_channels, 1))
        with ThreadPoolExecutor(max_workers=n_channel_workers) as executor:
            channel_futures = [
                executor.submit(
                    self._process_home_channel_backlog,
                    ch, home_chain_id, now, health_by_chain,
                    active_labelsets, active_channel_state_labelsets, failed_backlog_chains,
                )
                for ch in self.scanner.channels
            ] + [
                executor.submit(
                    self._process_cp_channel_backlog,
                    ch, now, health_by_chain,
                    active_labelsets, active_channel_state_labelsets, failed_backlog_chains,
                )
                for ch in self.scanner.cp_channels
            ]
            for future in as_completed(channel_futures):
                try:
                    future.result()
                except Exception:
                    logger.exception("Unexpected error in channel backlog task")

        if not failed_backlog_chains:
            self._remove_stale_backlog_metrics(active_labelsets)
        else:
            if not hasattr(self, "_backlog_labelsets"):
                self._backlog_labelsets = set()
            self._backlog_labelsets |= active_labelsets
        self._remove_stale_labelsets(
            CLIENT_STATUS,
            "_client_status_labelsets",
            active_client_status_labelsets,
        )
        self._remove_stale_labelsets(
            CHANNEL_STATE,
            "_channel_state_labelsets",
            active_channel_state_labelsets,
        )

        for cid, healthy in health_by_chain.items():
            if healthy and cid not in failed_backlog_chains:
                BACKLOG_UPDATED.labels(chain_id=cid).set(now)
        UPDATE_DURATION.labels(chain_id=home_chain_id).set(time.monotonic() - started)

        logger.info("Metrics updated")
