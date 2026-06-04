#!/usr/bin/env python3
"""
IBC Slack Alert Bot

Polls the Prometheus metrics endpoint of ibc-prometheus-exporter and sends
Slack webhook alerts for:

  - Pending send packets on any path older than a configurable threshold
  - Pending ack packets on any path older than a configurable threshold
  - IBC light client approaching expiry (configurable % thresholds: 50/75/90)
  - IBC light client expired

State is persisted to a JSON file so alerts survive restarts without re-firing.
"""

import argparse
import io
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import toml
from prometheus_client.parser import text_fd_to_metric_families

logger = logging.getLogger("ibc_alertbot")


# ── Config ────────────────────────────────────────────────────────────────────


@dataclass
class Config:
    metrics_url: str
    webhook_url: str
    state_file: str = "alertbot_state.json"
    poll_interval_seconds: int = 60

    # Thresholds
    pending_packet_age_minutes: int = 10
    pending_ack_age_minutes: int = 10
    client_expiry_warn_pct: List[int] = field(default_factory=lambda: [50, 75, 90])
    repeat_interval_minutes: int = 60

    @classmethod
    def from_toml(cls, path: str) -> "Config":
        with open(path) as f:
            data = toml.load(f)

        exporter = data.get("exporter", {})
        slack = data.get("slack", {})
        thresholds = data.get("thresholds", {})

        webhook_url = slack.get("webhook_url", "")
        if not webhook_url:
            raise SystemExit("slack.webhook_url must be set in config")

        return cls(
            metrics_url=exporter.get("metrics_url", "http://localhost:8000/metrics"),
            webhook_url=webhook_url,
            state_file=exporter.get("state_file", "alertbot_state.json"),
            poll_interval_seconds=exporter.get("poll_interval_seconds", 60),
            pending_packet_age_minutes=thresholds.get("pending_packet_age_minutes", 10),
            pending_ack_age_minutes=thresholds.get("pending_ack_age_minutes", 10),
            client_expiry_warn_pct=thresholds.get("client_expiry_warn_pct", [50, 75, 90]),
            repeat_interval_minutes=thresholds.get("repeat_interval_minutes", 60),
        )


# ── Metrics parsing ───────────────────────────────────────────────────────────


MetricSamples = Dict[str, List[Tuple[Dict[str, str], float]]]


def fetch_metrics(url: str) -> MetricSamples:
    """Fetch and parse Prometheus text format into {metric_name: [(labels, value)]}."""
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
    except Exception as exc:
        logger.error("Failed to fetch metrics from %s: %s", url, exc)
        return {}

    result: MetricSamples = {}
    for family in text_fd_to_metric_families(io.StringIO(resp.text)):
        for sample in family.samples:
            result.setdefault(sample.name, []).append((dict(sample.labels), sample.value))
    return result


def get_value(metrics: MetricSamples, metric: str, labels: Dict[str, str]) -> Optional[float]:
    """Return the value of a metric matching the given labels, or None."""
    for sample_labels, value in metrics.get(metric, []):
        if all(sample_labels.get(k) == v for k, v in labels.items()):
            return value
    return None


# ── Data models ───────────────────────────────────────────────────────────────


@dataclass
class PacketAlert:
    chain_id: str
    counterparty_chain_id: str
    connection_id: str
    port_id: str
    channel_id: str
    counterparty_port_id: str
    counterparty_channel_id: str
    size: int
    oldest_sequence: int
    oldest_timestamp: float  # Unix seconds (first time exporter saw this seq)
    kind: str                # "send" or "ack"

    @property
    def path_key(self) -> str:
        return (
            f"{self.kind}|{self.chain_id}|{self.counterparty_chain_id}"
            f"|{self.port_id}|{self.channel_id}"
        )


@dataclass
class ClientState:
    client_id: str
    chain_id: str
    counterparty_chain_id: str
    counterparty_client_id: str
    trusting_period: float   # seconds
    last_update: float       # Unix seconds
    status: str              # "active", "expired", …

    @property
    def client_key(self) -> str:
        return f"client|{self.chain_id}|{self.client_id}"

    def pct_elapsed(self, now: float) -> float:
        if self.trusting_period <= 0:
            return 0.0
        return (now - self.last_update) / self.trusting_period * 100

    def time_until_expiry(self, now: float) -> float:
        return (self.last_update + self.trusting_period) - now


# ── Metrics extraction ────────────────────────────────────────────────────────

_CHANNEL_LABELS = [
    "chain_id", "connection_id", "port_id", "channel_id",
    "counterparty_chain_id", "counterparty_port_id", "counterparty_channel_id",
]
_CLIENT_LABELS = ["client_id", "chain_id", "counterparty_chain_id", "counterparty_client_id"]


def extract_packet_alerts(metrics: MetricSamples) -> Tuple[List[PacketAlert], List[PacketAlert]]:
    """Return (send_alerts, ack_alerts) for all paths with a non-zero backlog."""
    send_alerts: List[PacketAlert] = []
    ack_alerts: List[PacketAlert] = []

    for kind, size_metric, seq_metric, ts_metric, out_list in [
        (
            "send",
            "ibc_send_packet_backlog_size",
            "ibc_send_packet_backlog_oldest_sequence",
            "ibc_send_packet_backlog_oldest_timestamp_seconds",
            send_alerts,
        ),
        (
            "ack",
            "ibc_ack_packet_backlog_size",
            "ibc_ack_packet_backlog_oldest_sequence",
            "ibc_ack_packet_backlog_oldest_timestamp_seconds",
            ack_alerts,
        ),
    ]:
        for labels, size in metrics.get(size_metric, []):
            if size <= 0:
                continue
            oldest_ts = get_value(metrics, ts_metric, labels)
            oldest_seq = get_value(metrics, seq_metric, labels)
            if oldest_ts is None or oldest_seq is None or oldest_ts <= 0:
                continue
            out_list.append(
                PacketAlert(
                    chain_id=labels.get("chain_id", ""),
                    counterparty_chain_id=labels.get("counterparty_chain_id", ""),
                    connection_id=labels.get("connection_id", ""),
                    port_id=labels.get("port_id", ""),
                    channel_id=labels.get("channel_id", ""),
                    counterparty_port_id=labels.get("counterparty_port_id", ""),
                    counterparty_channel_id=labels.get("counterparty_channel_id", ""),
                    size=int(size),
                    oldest_sequence=int(oldest_seq),
                    oldest_timestamp=oldest_ts,
                    kind=kind,
                )
            )

    return send_alerts, ack_alerts


def extract_client_states(metrics: MetricSamples) -> List[ClientState]:
    """Return a ClientState for every client with trusting period data."""
    clients: List[ClientState] = []

    for labels, trusting_period in metrics.get("ibc_client_trusting_period_seconds", []):
        last_update = get_value(metrics, "ibc_client_last_update_timestamp_seconds", labels)
        if last_update is None or last_update <= 0:
            continue

        # Find which status label has value 1
        status = "unknown"
        for s_labels, val in metrics.get("ibc_client_status", []):
            if (
                val > 0.5
                and s_labels.get("client_id") == labels.get("client_id")
                and s_labels.get("chain_id") == labels.get("chain_id")
            ):
                status = s_labels.get("status", "unknown")
                break

        clients.append(
            ClientState(
                client_id=labels.get("client_id", ""),
                chain_id=labels.get("chain_id", ""),
                counterparty_chain_id=labels.get("counterparty_chain_id", ""),
                counterparty_client_id=labels.get("counterparty_client_id", ""),
                trusting_period=trusting_period,
                last_update=last_update,
                status=status,
            )
        )

    return clients


# ── State persistence ─────────────────────────────────────────────────────────


def load_state(state_file: str) -> Dict[str, Any]:
    path = Path(state_file)
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception as exc:
            logger.warning("Could not load state file %s: %s — starting fresh", state_file, exc)
    return {"packets": {}, "clients": {}}


def save_state(state: Dict[str, Any], state_file: str) -> None:
    Path(state_file).write_text(json.dumps(state, indent=2))


# ── Slack formatting ──────────────────────────────────────────────────────────


def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 3600:
        return f"{seconds // 60}m"
    elif seconds < 86400:
        h, m = divmod(seconds, 3600)
        return f"{h}h {m // 60}m" if m else f"{h}h"
    else:
        d, rem = divmod(seconds, 86400)
        h = rem // 3600
        return f"{d}d {h}h" if h else f"{d}d"


def _send_blocks(webhook_url: str, blocks: List[Dict], fallback: str, dry_run: bool) -> bool:
    if dry_run:
        logger.info("[DRY RUN] Would send: %s", fallback)
        return True
    payload = {"text": fallback, "blocks": blocks}
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code != 200:
            logger.error("Slack webhook returned %d: %s", resp.status_code, resp.text)
            return False
        return True
    except Exception as exc:
        logger.error("Failed to send Slack message: %s", exc)
        return False


def _packet_blocks(entry: PacketAlert, age_seconds: float) -> Tuple[List[Dict], str]:
    if entry.kind == "send":
        title = f":warning: Unreceived packets from *{entry.chain_id}* to *{entry.counterparty_chain_id}*"
        fallback = f"Unreceived packets from {entry.chain_id} to {entry.counterparty_chain_id}"
    else:
        title = f":warning: Unacknowledged packets from *{entry.chain_id}* to *{entry.counterparty_chain_id}*"
        fallback = f"Unacknowledged packets from {entry.chain_id} to {entry.counterparty_chain_id}"

    if entry.size == 1:
        summary = f"Sequence `{entry.oldest_sequence}` stuck for *{_fmt_duration(age_seconds)}*"
    else:
        summary = (
            f"*{entry.size}* packets pending  •  "
            f"oldest seq `{entry.oldest_sequence}` stuck for *{_fmt_duration(age_seconds)}*"
        )

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*From:*\n`{entry.chain_id}`"},
                {"type": "mrkdwn", "text": f"*To:*\n`{entry.counterparty_chain_id}`"},
                {"type": "mrkdwn", "text": f"*Port:*\n`{entry.port_id}`"},
                {"type": "mrkdwn", "text": f"*Channel:*\n`{entry.channel_id}`"},
            ],
        },
        {"type": "context", "elements": [{"type": "mrkdwn", "text": summary}]},
        {"type": "divider"},
    ]
    return blocks, fallback


def _client_expiry_blocks(
    client: ClientState, pct_elapsed: float, time_until_expiry: float
) -> Tuple[List[Dict], str]:
    if pct_elapsed >= 90:
        icon, label = ":rotating_light:", "CRITICAL"
    elif pct_elapsed >= 75:
        icon, label = ":warning:", "WARNING"
    else:
        icon, label = ":large_yellow_circle:", "INFO"

    title = (
        f"{icon} IBC client expiry {label}: "
        f"`{client.client_id}` on *{client.chain_id}*"
    )
    fallback = (
        f"IBC client {client.client_id} on {client.chain_id} "
        f"is {pct_elapsed:.0f}% through trusting period"
    )

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Chain:*\n`{client.chain_id}`"},
                {"type": "mrkdwn", "text": f"*Counterparty:*\n`{client.counterparty_chain_id}`"},
                {"type": "mrkdwn", "text": f"*Client ID:*\n`{client.client_id}`"},
                {"type": "mrkdwn", "text": f"*CP Client:*\n`{client.counterparty_client_id}`"},
                {"type": "mrkdwn", "text": f"*Elapsed:*\n`{pct_elapsed:.1f}%`"},
                {
                    "type": "mrkdwn",
                    "text": f"*Expires in:*\n`{_fmt_duration(time_until_expiry)}`",
                },
            ],
        },
        {"type": "divider"},
    ]
    return blocks, fallback


def _client_expired_blocks(client: ClientState) -> Tuple[List[Dict], str]:
    title = f":red_circle: IBC client *EXPIRED*: `{client.client_id}` on *{client.chain_id}*"
    fallback = f"IBC client {client.client_id} on {client.chain_id} has EXPIRED"

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Chain:*\n`{client.chain_id}`"},
                {"type": "mrkdwn", "text": f"*Counterparty:*\n`{client.counterparty_chain_id}`"},
                {"type": "mrkdwn", "text": f"*Client ID:*\n`{client.client_id}`"},
                {"type": "mrkdwn", "text": f"*CP Client:*\n`{client.counterparty_client_id}`"},
            ],
        },
        {"type": "divider"},
    ]
    return blocks, fallback


# ── Startup status ────────────────────────────────────────────────────────────


def _count_monitored(metrics: MetricSamples) -> Dict[str, int]:
    """Return counts of chains, open channels, and clients visible in metrics."""
    chains = {lbl.get("chain_id") for lbl, _ in metrics.get("ibc_rest_health", [])}
    chains.discard(None)

    # Count unique (chain_id, channel_id) pairs present in channel-state metrics
    channels: set = set()
    for lbl, _ in metrics.get("ibc_channel_state", []):
        cid = lbl.get("chain_id")
        ch = lbl.get("channel_id")
        if cid and ch:
            channels.add((cid, ch))
    # Fall back to backlog metrics when channel_state is absent
    if not channels:
        for metric in ("ibc_send_packet_backlog_size", "ibc_ack_packet_backlog_size"):
            for lbl, _ in metrics.get(metric, []):
                cid = lbl.get("chain_id")
                ch = lbl.get("channel_id")
                if cid and ch:
                    channels.add((cid, ch))

    clients = len(metrics.get("ibc_client_trusting_period_seconds", []))

    return {"chains": len(chains), "channels": len(channels), "clients": clients}


def _startup_blocks(config: Config, counts: Dict[str, int]) -> Tuple[List[Dict], str]:
    """Build a Slack message announcing that the bot has started."""
    fallback = "IBC Alert Bot started"

    expiry_pct = "  /  ".join(f"{p}%" for p in sorted(config.client_expiry_warn_pct))

    blocks: List[Dict] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": ":white_check_mark: *IBC Alert Bot started*"},
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Monitoring:*\n"
                        f"`{counts['chains']}` chain{'s' if counts['chains'] != 1 else ''}  •  "
                        f"`{counts['channels']}` channel{'s' if counts['channels'] != 1 else ''}  •  "
                        f"`{counts['clients']}` client{'s' if counts['clients'] != 1 else ''}"
                    ),
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Packet threshold:*\n"
                        f"`>{config.pending_packet_age_minutes}m`  •  "
                        f"repeat every `{config.repeat_interval_minutes}m`"
                    ),
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Client expiry alerts:*\n`{expiry_pct}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Poll interval:*\n`{config.poll_interval_seconds}s`",
                },
            ],
        },
        {"type": "divider"},
    ]
    return blocks, fallback


def run_startup(
    config: Config, state: Dict[str, Any], now: float, dry_run: bool = False
) -> None:
    """Send the startup status message followed by any currently active alerts."""
    metrics = fetch_metrics(config.metrics_url)
    if not metrics:
        logger.warning("Could not fetch metrics at startup — skipping startup message")
        return

    counts = _count_monitored(metrics)
    blocks, fallback = _startup_blocks(config, counts)
    _send_blocks(config.webhook_url, blocks, fallback, dry_run)
    logger.info(
        "Startup: monitoring %d chains, %d channels, %d clients",
        counts["chains"],
        counts["channels"],
        counts["clients"],
    )

    # Force-send all currently active alerts regardless of prior notification state
    _check_packets(config, state, metrics, now, dry_run, force=True)
    _check_clients(config, state, metrics, now, dry_run, force=True)


# ── Format preview ───────────────────────────────────────────────────────────


def send_preview(config: Config, dry_run: bool = False) -> None:
    """Send one example of every alert type so the message format can be verified."""
    now = time.time()

    # Derive a representative chain name from the metrics URL host (best-effort)
    import urllib.parse
    host = urllib.parse.urlparse(config.metrics_url).hostname or "home-chain"
    chain = host.split(".")[0]

    _send_blocks(
        config.webhook_url,
        [{"type": "section", "text": {"type": "mrkdwn", "text": ":eyes: *Alert format preview* — one example of each alert type"}}],
        "Alert format preview",
        dry_run,
    )

    # Send packet — single
    entry_single = PacketAlert(
        chain_id=chain, counterparty_chain_id="osmosis-1",
        connection_id="connection-8", port_id="transfer",
        channel_id="channel-8", counterparty_port_id="transfer",
        counterparty_channel_id="channel-122",
        size=1, oldest_sequence=634998,
        oldest_timestamp=now - 18 * 60, kind="send",
    )
    blocks, fb = _packet_blocks(entry_single, 18 * 60)
    _send_blocks(config.webhook_url, blocks, fb, dry_run)

    # Ack packet — multiple
    entry_multi = PacketAlert(
        chain_id=chain, counterparty_chain_id="cosmoshub-4",
        connection_id="connection-4", port_id="transfer",
        channel_id="channel-4", counterparty_port_id="transfer",
        counterparty_channel_id="channel-220",
        size=5, oldest_sequence=200,
        oldest_timestamp=now - 130 * 60, kind="ack",
    )
    blocks, fb = _packet_blocks(entry_multi, 130 * 60)
    _send_blocks(config.webhook_url, blocks, fb, dry_run)

    # Client expiry — one message per threshold level
    trusting = 86_400 * 14  # 14 days
    client = ClientState(
        client_id="07-tendermint-42", chain_id=chain,
        counterparty_chain_id="osmosis-1", counterparty_client_id="07-tendermint-7",
        trusting_period=trusting, last_update=0.0, status="active",
    )
    for pct_target in [55.0, 80.0, 93.0]:
        client.last_update = now - trusting * (pct_target / 100)
        pct = client.pct_elapsed(now)
        blocks, fb = _client_expiry_blocks(client, pct, client.time_until_expiry(now))
        _send_blocks(config.webhook_url, blocks, fb, dry_run)

    # Expired client
    client.last_update = now - trusting * 1.1
    client.status = "expired"
    blocks, fb = _client_expired_blocks(client)
    _send_blocks(config.webhook_url, blocks, fb, dry_run)

    logger.info("Preview: sent 7 example messages")


# ── Alert evaluation ──────────────────────────────────────────────────────────


def run_check(config: Config, state: Dict[str, Any], now: float, dry_run: bool = False) -> None:
    metrics = fetch_metrics(config.metrics_url)
    if not metrics:
        return

    _check_packets(config, state, metrics, now, dry_run)
    _check_clients(config, state, metrics, now, dry_run)


def _check_packets(
    config: Config,
    state: Dict[str, Any],
    metrics: MetricSamples,
    now: float,
    dry_run: bool,
    force: bool = False,
) -> None:
    send_entries, ack_entries = extract_packet_alerts(metrics)
    repeat_sec = config.repeat_interval_minutes * 60

    for kind, entries, age_threshold_min in [
        ("send", send_entries, config.pending_packet_age_minutes),
        ("ack", ack_entries, config.pending_ack_age_minutes),
    ]:
        age_threshold_sec = age_threshold_min * 60
        active_keys: set = set()

        for entry in entries:
            age_sec = now - entry.oldest_timestamp
            if age_sec < age_threshold_sec:
                continue

            key = entry.path_key
            active_keys.add(key)

            pstate = state["packets"].setdefault(key, {})
            last_notified = pstate.get("last_notified", 0)

            if force or now - last_notified >= repeat_sec:
                blocks, fallback = _packet_blocks(entry, age_sec)
                if _send_blocks(config.webhook_url, blocks, fallback, dry_run):
                    pstate["last_notified"] = now
                    pstate.setdefault("first_fired", now)
                    logger.info("Sent %s packet alert: %s", kind, key)

        # Prune resolved paths so their state doesn't grow forever
        stale = [k for k in list(state["packets"]) if k.startswith(f"{kind}|") and k not in active_keys]
        for k in stale:
            logger.info("Resolved %s packet alert: %s", kind, k)
            del state["packets"][k]


def _check_clients(
    config: Config,
    state: Dict[str, Any],
    metrics: MetricSamples,
    now: float,
    dry_run: bool,
    force: bool = False,
) -> None:
    clients = extract_client_states(metrics)

    for client in clients:
        key = client.client_key
        cstate = state["clients"].setdefault(
            key, {"thresholds_fired": [], "expired_notified": False}
        )

        if client.status == "expired":
            if force or not cstate.get("expired_notified"):
                blocks, fallback = _client_expired_blocks(client)
                if _send_blocks(config.webhook_url, blocks, fallback, dry_run):
                    cstate["expired_notified"] = True
                    logger.info("Sent expired alert: %s", key)
            continue

        # Client is active — reset expired flag in case it was resolved
        if cstate.get("expired_notified"):
            cstate["expired_notified"] = False

        if client.trusting_period <= 0:
            continue

        pct = client.pct_elapsed(now)
        time_left = client.time_until_expiry(now)

        # Trim thresholds that are no longer exceeded (client was updated)
        cstate["thresholds_fired"] = [t for t in cstate["thresholds_fired"] if t <= pct]

        # Fire the highest threshold that has been crossed (force bypasses already-fired check)
        thresholds = sorted(config.client_expiry_warn_pct, reverse=True)
        for threshold in thresholds:
            already_fired = threshold in cstate["thresholds_fired"]
            if pct >= threshold and (force or not already_fired):
                blocks, fallback = _client_expiry_blocks(client, pct, time_left)
                if _send_blocks(config.webhook_url, blocks, fallback, dry_run):
                    for t in config.client_expiry_warn_pct:
                        if t <= threshold and t not in cstate["thresholds_fired"]:
                            cstate["thresholds_fired"].append(t)
                    logger.info(
                        "Sent client expiry alert: %s at %.1f%% (threshold %d%%)",
                        key, pct, threshold,
                    )
                break  # only fire one threshold per cycle


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IBC Prometheus Exporter — Slack Alert Bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        default="alertbot/config.toml",
        help="Path to config TOML file (default: alertbot/config.toml)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single check and exit (useful for testing)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Evaluate alerts but do not send Slack messages",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Send one example of every alert type to verify formatting, then exit",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        config = Config.from_toml(args.config)
    except FileNotFoundError:
        sys.exit(f"Config file not found: {args.config}")

    logger.info(
        "Starting IBC alert bot — metrics: %s, poll: %ds, dry_run: %s",
        config.metrics_url,
        config.poll_interval_seconds,
        args.dry_run,
    )

    if args.preview:
        try:
            send_preview(config, dry_run=args.dry_run)
        except Exception:
            logger.exception("Unexpected error during preview")
        return

    state = load_state(config.state_file)
    try:
        run_startup(config, state, time.time(), dry_run=args.dry_run)
    except Exception:
        logger.exception("Unexpected error during startup")
    save_state(state, config.state_file)

    if args.once:
        return

    while True:
        state = load_state(config.state_file)
        try:
            run_check(config, state, time.time(), dry_run=args.dry_run)
        except Exception:
            logger.exception("Unexpected error during check")
        save_state(state, config.state_file)

        logger.debug("Next check in %ds", config.poll_interval_seconds)
        time.sleep(config.poll_interval_seconds)


if __name__ == "__main__":
    main()
