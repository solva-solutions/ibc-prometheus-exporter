"""
Tests for alertbot/alertbot.py

Run with:
    pytest tests/test_alertbot.py -v -s

The -s flag keeps stdout visible so the rendered Slack message payloads are
printed for manual inspection.
"""

import json
import textwrap
from typing import Any, Dict
from unittest.mock import call, patch

import pytest

from alertbot.alertbot import (
    ClientState,
    Config,
    MetricSamples,
    PacketAlert,
    _check_clients,
    _check_packets,
    _client_expired_blocks,
    _client_expiry_blocks,
    _count_monitored,
    _fmt_duration,
    _packet_blocks,
    _startup_blocks,
    extract_client_states,
    extract_packet_alerts,
    run_startup,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

NOW = 1_750_000_000.0  # fixed "current" time used throughout

_CHANNEL_LABELS = {
    "chain_id": "injective-1",
    "counterparty_chain_id": "osmosis-1",
    "connection_id": "connection-8",
    "port_id": "transfer",
    "channel_id": "channel-8",
    "counterparty_port_id": "transfer",
    "counterparty_channel_id": "channel-122",
}

_CLIENT_LABELS = {
    "client_id": "07-tendermint-42",
    "chain_id": "injective-1",
    "counterparty_chain_id": "osmosis-1",
    "counterparty_client_id": "07-tendermint-7",
}

TRUSTING_PERIOD = 86_400 * 14  # 14 days in seconds


def _fresh_state() -> Dict[str, Any]:
    return {"packets": {}, "clients": {}}


def _default_config(**overrides) -> Config:
    base = dict(
        metrics_url="http://unused",
        webhook_url="http://unused-webhook",
        pending_packet_age_minutes=10,
        pending_ack_age_minutes=10,
        client_expiry_warn_pct=[50, 75, 90],
        repeat_interval_minutes=60,
    )
    base.update(overrides)
    return Config(**base)


def _channel_metrics(
    kind: str,
    size: int,
    oldest_seq: int,
    oldest_ts: float,
    labels: Dict = None,
) -> MetricSamples:
    """Build a minimal MetricSamples dict for one packet backlog entry."""
    lbl = dict(_CHANNEL_LABELS if labels is None else labels)
    prefix = "ibc_send_packet_backlog" if kind == "send" else "ibc_ack_packet_backlog"
    return {
        f"{prefix}_size": [(lbl, float(size))],
        f"{prefix}_oldest_sequence": [(lbl, float(oldest_seq))],
        f"{prefix}_oldest_timestamp_seconds": [(lbl, oldest_ts)],
    }


def _client_metrics(
    trusting_period: float,
    last_update: float,
    status: str,
    labels: Dict = None,
) -> MetricSamples:
    """Build a minimal MetricSamples dict for one IBC client."""
    lbl = dict(_CLIENT_LABELS if labels is None else labels)
    status_lbl = {**lbl, "status": status}
    return {
        "ibc_client_trusting_period_seconds": [(lbl, trusting_period)],
        "ibc_client_last_update_timestamp_seconds": [(lbl, last_update)],
        "ibc_client_status": [(status_lbl, 1.0)],
    }


def _pp(blocks: list, fallback: str) -> None:
    """Pretty-print a Slack message payload to stdout."""
    print()
    print("  fallback:", fallback)
    print("  blocks:")
    for block in blocks:
        print(textwrap.indent(json.dumps(block, indent=4), "    "))
    print()


# ── _fmt_duration ─────────────────────────────────────────────────────────────


class TestFmtDuration:
    def test_minutes(self):
        assert _fmt_duration(15 * 60) == "15m"

    def test_hours_exact(self):
        assert _fmt_duration(3 * 3600) == "3h"

    def test_hours_and_minutes(self):
        assert _fmt_duration(3 * 3600 + 30 * 60) == "3h 30m"

    def test_days_exact(self):
        assert _fmt_duration(2 * 86400) == "2d"

    def test_days_and_hours(self):
        assert _fmt_duration(2 * 86400 + 5 * 3600) == "2d 5h"

    def test_zero(self):
        assert _fmt_duration(0) == "0m"


# ── Metrics extraction ────────────────────────────────────────────────────────


class TestExtractPacketAlerts:
    def test_send_packet_extracted(self):
        metrics = _channel_metrics("send", size=3, oldest_seq=100, oldest_ts=NOW - 900)
        sends, acks = extract_packet_alerts(metrics)
        assert len(sends) == 1
        assert len(acks) == 0
        e = sends[0]
        assert e.kind == "send"
        assert e.size == 3
        assert e.oldest_sequence == 100
        assert e.chain_id == "injective-1"
        assert e.counterparty_chain_id == "osmosis-1"

    def test_ack_packet_extracted(self):
        metrics = _channel_metrics("ack", size=1, oldest_seq=77, oldest_ts=NOW - 300)
        sends, acks = extract_packet_alerts(metrics)
        assert len(sends) == 0
        assert len(acks) == 1
        assert acks[0].kind == "ack"
        assert acks[0].oldest_sequence == 77

    def test_zero_size_skipped(self):
        metrics = _channel_metrics("send", size=0, oldest_seq=1, oldest_ts=NOW - 1000)
        sends, _ = extract_packet_alerts(metrics)
        assert len(sends) == 0

    def test_missing_timestamp_skipped(self):
        lbl = dict(_CHANNEL_LABELS)
        metrics: MetricSamples = {
            "ibc_send_packet_backlog_size": [(lbl, 2.0)],
            "ibc_send_packet_backlog_oldest_sequence": [(lbl, 5.0)],
            # oldest_timestamp intentionally absent
        }
        sends, _ = extract_packet_alerts(metrics)
        assert len(sends) == 0

    def test_zero_timestamp_skipped(self):
        metrics = _channel_metrics("send", size=1, oldest_seq=1, oldest_ts=0.0)
        sends, _ = extract_packet_alerts(metrics)
        assert len(sends) == 0


class TestExtractClientStates:
    def test_active_client(self):
        metrics = _client_metrics(TRUSTING_PERIOD, NOW - 1000, "active")
        clients = extract_client_states(metrics)
        assert len(clients) == 1
        c = clients[0]
        assert c.client_id == "07-tendermint-42"
        assert c.status == "active"
        assert c.trusting_period == TRUSTING_PERIOD

    def test_expired_client(self):
        metrics = _client_metrics(TRUSTING_PERIOD, NOW - TRUSTING_PERIOD - 3600, "expired")
        clients = extract_client_states(metrics)
        assert clients[0].status == "expired"

    def test_zero_last_update_skipped(self):
        metrics = _client_metrics(TRUSTING_PERIOD, 0.0, "active")
        assert extract_client_states(metrics) == []

    def test_pct_elapsed(self):
        last_update = NOW - TRUSTING_PERIOD * 0.75
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        clients = extract_client_states(metrics)
        assert abs(clients[0].pct_elapsed(NOW) - 75.0) < 0.01

    def test_time_until_expiry(self):
        last_update = NOW - TRUSTING_PERIOD * 0.9
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        c = extract_client_states(metrics)[0]
        expected = TRUSTING_PERIOD * 0.1
        assert abs(c.time_until_expiry(NOW) - expected) < 1


# ── Packet alert logic ────────────────────────────────────────────────────────


class TestCheckPackets:
    def _run(self, metrics, state=None, config=None, now=NOW):
        if state is None:
            state = _fresh_state()
        if config is None:
            config = _default_config()
        sent = []
        with patch("alertbot.alertbot._send_blocks", side_effect=lambda url, b, f, dr: sent.append((b, f)) or True):
            _check_packets(config, state, metrics, now, dry_run=False)
        return sent, state

    def test_fires_when_older_than_threshold(self):
        # Oldest packet 15 min old, threshold 10 min → should alert
        metrics = _channel_metrics("send", size=2, oldest_seq=50, oldest_ts=NOW - 900)
        sent, _ = self._run(metrics)
        assert len(sent) == 1
        assert "injective-1" in sent[0][1]

    def test_no_alert_when_younger_than_threshold(self):
        # Oldest packet 5 min old, threshold 10 min → no alert
        metrics = _channel_metrics("send", size=1, oldest_seq=50, oldest_ts=NOW - 300)
        sent, _ = self._run(metrics)
        assert len(sent) == 0

    def test_no_repeat_within_window(self):
        metrics = _channel_metrics("send", size=1, oldest_seq=50, oldest_ts=NOW - 900)
        state = _fresh_state()
        # First check fires
        sent1, state = self._run(metrics, state=state)
        assert len(sent1) == 1
        # Second check immediately after — still within 60-min repeat window
        sent2, _ = self._run(metrics, state=state, now=NOW + 60)
        assert len(sent2) == 0

    def test_repeats_after_window(self):
        metrics = _channel_metrics("send", size=1, oldest_seq=50, oldest_ts=NOW - 900)
        state = _fresh_state()
        sent1, state = self._run(metrics, state=state)
        assert len(sent1) == 1
        # Check again after the repeat window has elapsed
        sent2, _ = self._run(metrics, state=state, now=NOW + 3601)
        assert len(sent2) == 1

    def test_state_pruned_when_resolved(self):
        metrics = _channel_metrics("send", size=1, oldest_seq=50, oldest_ts=NOW - 900)
        state = _fresh_state()
        self._run(metrics, state=state)
        assert len(state["packets"]) == 1
        # Backlog drains to zero
        empty_metrics = _channel_metrics("send", size=0, oldest_seq=50, oldest_ts=NOW - 900)
        self._run(empty_metrics, state=state)
        assert len(state["packets"]) == 0

    def test_state_pruned_when_path_removed_from_metrics(self):
        """A path that disappears entirely from metrics (e.g. channel closed) is pruned."""
        metrics = _channel_metrics("send", size=2, oldest_seq=50, oldest_ts=NOW - 900)
        state = _fresh_state()
        self._run(metrics, state=state)
        assert len(state["packets"]) == 1
        # Path no longer present in metrics at all
        self._run({}, state=state)
        assert len(state["packets"]) == 0

    def test_new_path_fires_immediately(self):
        """A brand-new path above the threshold fires on its first appearance."""
        metrics = _channel_metrics("send", size=1, oldest_seq=99, oldest_ts=NOW - 900)
        sent, state = self._run(metrics)
        assert len(sent) == 1
        assert len(state["packets"]) == 1

    def test_ack_alert_fires_independently(self):
        send_m = _channel_metrics("send", size=0, oldest_seq=1, oldest_ts=NOW - 900)
        ack_m = _channel_metrics("ack", size=3, oldest_seq=200, oldest_ts=NOW - 1200)
        metrics = {**send_m, **ack_m}
        sent, _ = self._run(metrics)
        assert len(sent) == 1
        assert "Unacknowledged" in sent[0][1]


# ── Client alert logic ────────────────────────────────────────────────────────


class TestCheckClients:
    def _run(self, metrics, state=None, config=None, now=NOW):
        if state is None:
            state = _fresh_state()
        if config is None:
            config = _default_config()
        sent = []
        with patch("alertbot.alertbot._send_blocks", side_effect=lambda url, b, f, dr: sent.append((b, f)) or True):
            _check_clients(config, state, metrics, now, dry_run=False)
        return sent, state

    def test_no_alert_below_50pct(self):
        last_update = NOW - TRUSTING_PERIOD * 0.3
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        sent, _ = self._run(metrics)
        assert len(sent) == 0

    def test_fires_50pct_threshold(self):
        last_update = NOW - TRUSTING_PERIOD * 0.55
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        sent, _ = self._run(metrics)
        assert len(sent) == 1
        assert "07-tendermint-42" in sent[0][1]

    def test_fires_75pct_threshold_and_marks_50_done(self):
        last_update = NOW - TRUSTING_PERIOD * 0.80
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        sent, state = self._run(metrics)
        assert len(sent) == 1
        key = "client|injective-1|07-tendermint-42"
        # Both 50 and 75 should be recorded as fired
        assert 50 in state["clients"][key]["thresholds_fired"]
        assert 75 in state["clients"][key]["thresholds_fired"]

    def test_fires_90pct_threshold(self):
        last_update = NOW - TRUSTING_PERIOD * 0.92
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        sent, _ = self._run(metrics)
        assert len(sent) == 1

    def test_no_duplicate_threshold_alert(self):
        last_update = NOW - TRUSTING_PERIOD * 0.80
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        state = _fresh_state()
        sent1, state = self._run(metrics, state=state)
        assert len(sent1) == 1
        # Same check again — threshold already fired, no duplicate
        sent2, _ = self._run(metrics, state=state)
        assert len(sent2) == 0

    def test_threshold_resets_after_client_update(self):
        # Client is at 80% → fires 75% threshold
        last_update_high = NOW - TRUSTING_PERIOD * 0.80
        metrics_high = _client_metrics(TRUSTING_PERIOD, last_update_high, "active")
        state = _fresh_state()
        sent1, state = self._run(metrics_high, state=state)
        assert len(sent1) == 1

        # Relayer updates client: now only 30% elapsed — thresholds should reset
        last_update_low = NOW - TRUSTING_PERIOD * 0.30
        metrics_low = _client_metrics(TRUSTING_PERIOD, last_update_low, "active")
        sent2, state = self._run(metrics_low, state=state)
        assert len(sent2) == 0  # no alert: 30% < 50%

        # Client drifts back to 55% — 50% threshold should fire again
        last_update_mid = NOW - TRUSTING_PERIOD * 0.55
        metrics_mid = _client_metrics(TRUSTING_PERIOD, last_update_mid, "active")
        sent3, _ = self._run(metrics_mid, state=state)
        assert len(sent3) == 1

    def test_expired_fires_once(self):
        last_update = NOW - TRUSTING_PERIOD * 1.1
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "expired")
        state = _fresh_state()
        sent1, state = self._run(metrics, state=state)
        assert len(sent1) == 1
        assert "EXPIRED" in sent1[0][1]
        # Second check — already notified, should not re-fire
        sent2, _ = self._run(metrics, state=state)
        assert len(sent2) == 0

    def test_stale_client_state_pruned_when_removed_from_metrics(self):
        """Client that disappears from metrics has its state entry cleaned up."""
        last_update = NOW - TRUSTING_PERIOD * 0.55
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        state = _fresh_state()
        self._run(metrics, state=state)
        assert len(state["clients"]) == 1
        # Client no longer reported (path decommissioned / omit_inactive_clients)
        self._run({}, state=state)
        assert len(state["clients"]) == 0

    def test_new_client_fires_immediately(self):
        """A new client above a threshold fires on its first appearance."""
        last_update = NOW - TRUSTING_PERIOD * 0.80
        metrics = _client_metrics(TRUSTING_PERIOD, last_update, "active")
        sent, _ = self._run(metrics)
        assert len(sent) == 1

    def test_expired_flag_resets_if_client_recovers(self):
        # Start expired
        metrics_expired = _client_metrics(TRUSTING_PERIOD, NOW - TRUSTING_PERIOD * 1.1, "expired")
        state = _fresh_state()
        self._run(metrics_expired, state=state)
        key = "client|injective-1|07-tendermint-42"
        assert state["clients"][key]["expired_notified"] is True

        # Client somehow comes back active (flag should reset)
        metrics_active = _client_metrics(TRUSTING_PERIOD, NOW - TRUSTING_PERIOD * 0.1, "active")
        self._run(metrics_active, state=state)
        assert state["clients"][key]["expired_notified"] is False


# ── Startup ───────────────────────────────────────────────────────────────────


class TestStartup:
    def _make_full_metrics(self) -> MetricSamples:
        """Metrics with 2 chains, 2 channels, 2 clients — one alerting path and one expiring client."""
        lbl2 = {**_CHANNEL_LABELS, "chain_id": "cosmoshub-4", "counterparty_chain_id": "injective-1",
                "channel_id": "channel-220", "counterparty_channel_id": "channel-4"}
        client2_labels = {**_CLIENT_LABELS, "client_id": "07-tendermint-99",
                         "chain_id": "cosmoshub-4", "counterparty_chain_id": "injective-1",
                         "counterparty_client_id": "07-tendermint-42"}
        m: MetricSamples = {}
        # REST health for 2 chains
        m["ibc_rest_health"] = [
            ({"chain_id": "injective-1", "endpoint": "http://inj"}, 1.0),
            ({"chain_id": "cosmoshub-4", "endpoint": "http://cosmos"}, 1.0),
        ]
        # Channel state for 2 channels
        m["ibc_channel_state"] = [
            ({**_CHANNEL_LABELS, "state": "open"}, 1.0),
            ({**lbl2, "state": "open"}, 1.0),
        ]
        # One stuck send packet on injective path
        m.update(_channel_metrics("send", size=2, oldest_seq=50, oldest_ts=NOW - 900))
        # Two clients
        client1 = _client_metrics(TRUSTING_PERIOD, NOW - TRUSTING_PERIOD * 0.80, "active")
        client2_lbl = dict(_CLIENT_LABELS)
        client2_lbl.update(client2_labels)
        client2 = {
            "ibc_client_trusting_period_seconds": [(client2_labels, TRUSTING_PERIOD)],
            "ibc_client_last_update_timestamp_seconds": [(client2_labels, NOW - TRUSTING_PERIOD * 0.3)],
            "ibc_client_status": [({**client2_labels, "status": "active"}, 1.0)],
        }
        for k, v in client1.items():
            m.setdefault(k, []).extend(v)
        for k, v in client2.items():
            m.setdefault(k, []).extend(v)
        return m

    def test_count_monitored(self):
        metrics = self._make_full_metrics()
        counts = _count_monitored(metrics)
        assert counts["chains"] == 2
        assert counts["channels"] == 2
        assert counts["clients"] == 2

    def test_count_monitored_fallback_to_backlog(self):
        """When ibc_channel_state is absent, falls back to backlog metrics."""
        metrics = _channel_metrics("send", size=1, oldest_seq=1, oldest_ts=NOW - 600)
        # Add REST health
        metrics["ibc_rest_health"] = [
            ({"chain_id": "injective-1", "endpoint": "http://inj"}, 1.0),
        ]
        counts = _count_monitored(metrics)
        assert counts["chains"] == 1
        assert counts["channels"] == 1

    def test_startup_blocks_content(self):
        config = _default_config(
            pending_packet_age_minutes=10,
            client_expiry_warn_pct=[50, 75, 90],
            repeat_interval_minutes=60,
            poll_interval_seconds=60,
        )
        counts = {"chains": 2, "channels": 8, "clients": 4}
        blocks, fallback = _startup_blocks(config, counts)

        assert "started" in fallback.lower()
        body = json.dumps(blocks)
        assert "2" in body
        assert "8" in body
        assert "4" in body
        assert "10" in body        # packet threshold
        assert "60" in body        # repeat interval
        assert "50%" in body       # expiry thresholds formatted without Python list syntax
        assert "75%" in body
        assert "90%" in body
        assert "[50" not in body   # no raw Python list notation

    def test_run_startup_sends_status_and_active_alerts(self, capsys):
        metrics = self._make_full_metrics()
        state = _fresh_state()
        config = _default_config()
        sent = []

        with patch("alertbot.alertbot.fetch_metrics", return_value=metrics), \
             patch("alertbot.alertbot._send_blocks",
                   side_effect=lambda url, b, f, dr: sent.append(f) or True):
            run_startup(config, state, NOW, dry_run=False)

        # Should send: 1 startup status + 1 packet alert + 1 client expiry alert
        assert len(sent) == 3
        assert any("started" in s.lower() for s in sent)
        assert any("Unreceived" in s for s in sent)
        assert any("07-tendermint-42" in s for s in sent)

    def test_run_startup_resends_already_notified_alerts(self):
        """Startup always re-fires active alerts even if they were already notified."""
        metrics = _channel_metrics("send", size=1, oldest_seq=50, oldest_ts=NOW - 900)
        state = _fresh_state()
        config = _default_config()

        # Simulate a prior notification (cooldown active)
        key = f"send|injective-1|osmosis-1|transfer|channel-8"
        state["packets"][key] = {"last_notified": NOW - 30, "first_fired": NOW - 900}

        sent = []
        with patch("alertbot.alertbot.fetch_metrics", return_value=metrics), \
             patch("alertbot.alertbot._send_blocks",
                   side_effect=lambda url, b, f, dr: sent.append(f) or True):
            run_startup(config, state, NOW, dry_run=False)

        # Alert should appear despite cooldown (force=True on startup)
        assert any("Unreceived" in s for s in sent)


# ── Message rendering (prints all Slack payloads) ─────────────────────────────


class TestMessageRendering:
    """
    Renders every alert type and prints the resulting Slack block payloads.
    Run with pytest -s to see the output.
    """

    def _make_send_entry(self, size=1, oldest_seq=634998, age_min=18) -> PacketAlert:
        return PacketAlert(
            chain_id="injective-1",
            counterparty_chain_id="osmosis-1",
            connection_id="connection-8",
            port_id="transfer",
            channel_id="channel-8",
            counterparty_port_id="transfer",
            counterparty_channel_id="channel-122",
            size=size,
            oldest_sequence=oldest_seq,
            oldest_timestamp=NOW - age_min * 60,
            kind="send",
        )

    def _make_ack_entry(self, size=2, oldest_seq=500, age_min=25) -> PacketAlert:
        return PacketAlert(
            chain_id="injective-1",
            counterparty_chain_id="cosmoshub-4",
            connection_id="connection-4",
            port_id="transfer",
            channel_id="channel-4",
            counterparty_port_id="transfer",
            counterparty_channel_id="channel-220",
            size=size,
            oldest_sequence=oldest_seq,
            oldest_timestamp=NOW - age_min * 60,
            kind="ack",
        )

    def _make_client(self, pct: float, status="active") -> ClientState:
        last_update = NOW - TRUSTING_PERIOD * (pct / 100)
        return ClientState(
            client_id="07-tendermint-42",
            chain_id="injective-1",
            counterparty_chain_id="osmosis-1",
            counterparty_client_id="07-tendermint-7",
            trusting_period=TRUSTING_PERIOD,
            last_update=last_update,
            status=status,
        )

    # ── Individual message shape assertions ────────────────────────────────────

    def test_send_single_packet_message(self, capsys):
        entry = self._make_send_entry(size=1, oldest_seq=634998, age_min=18)
        blocks, fallback = _packet_blocks(entry, 18 * 60)

        print("\n=== SEND PACKET — single stuck packet ===")
        _pp(blocks, fallback)

        assert fallback == "Unreceived packets from injective-1 to osmosis-1"
        assert any(b.get("type") == "section" for b in blocks)
        context = next(b for b in blocks if b.get("type") == "context")
        assert "634998" in context["elements"][0]["text"]
        assert "18m" in context["elements"][0]["text"]

    def test_send_multi_packet_message(self, capsys):
        entry = self._make_send_entry(size=5, oldest_seq=634990, age_min=45)
        blocks, fallback = _packet_blocks(entry, 45 * 60)

        print("\n=== SEND PACKET — multiple stuck packets ===")
        _pp(blocks, fallback)

        context = next(b for b in blocks if b.get("type") == "context")
        assert "5" in context["elements"][0]["text"]
        assert "634990" in context["elements"][0]["text"]

    def test_ack_single_packet_message(self, capsys):
        entry = self._make_ack_entry(size=1, oldest_seq=200, age_min=12)
        blocks, fallback = _packet_blocks(entry, 12 * 60)

        print("\n=== ACK PACKET — single ===")
        _pp(blocks, fallback)

        assert "Unacknowledged" in fallback
        assert "cosmoshub-4" in fallback

    def test_ack_multi_packet_message(self, capsys):
        entry = self._make_ack_entry(size=7, oldest_seq=190, age_min=130)
        blocks, fallback = _packet_blocks(entry, 130 * 60)

        print("\n=== ACK PACKET — multiple (2h 10m) ===")
        _pp(blocks, fallback)

        context = next(b for b in blocks if b.get("type") == "context")
        text = context["elements"][0]["text"]
        assert "7" in text
        assert "2h 10m" in text

    def test_client_50pct_expiry_message(self, capsys):
        client = self._make_client(55.0)
        pct = client.pct_elapsed(NOW)
        time_left = client.time_until_expiry(NOW)
        blocks, fallback = _client_expiry_blocks(client, pct, time_left)

        print("\n=== CLIENT EXPIRY — INFO (55%) ===")
        _pp(blocks, fallback)

        assert "INFO" in fallback or "INFO" in json.dumps(blocks)
        assert "07-tendermint-42" in json.dumps(blocks)
        assert "large_yellow_circle" in json.dumps(blocks)

    def test_client_75pct_expiry_message(self, capsys):
        client = self._make_client(80.0)
        pct = client.pct_elapsed(NOW)
        time_left = client.time_until_expiry(NOW)
        blocks, fallback = _client_expiry_blocks(client, pct, time_left)

        print("\n=== CLIENT EXPIRY — WARNING (80%) ===")
        _pp(blocks, fallback)

        assert "WARNING" in json.dumps(blocks)
        assert ":warning:" in json.dumps(blocks)

    def test_client_90pct_expiry_message(self, capsys):
        client = self._make_client(93.0)
        pct = client.pct_elapsed(NOW)
        time_left = client.time_until_expiry(NOW)
        blocks, fallback = _client_expiry_blocks(client, pct, time_left)

        print("\n=== CLIENT EXPIRY — CRITICAL (93%) ===")
        _pp(blocks, fallback)

        assert "CRITICAL" in json.dumps(blocks)
        assert "rotating_light" in json.dumps(blocks)
        # Time left should be short (7% of 14 days ≈ 23h)
        fields_text = json.dumps(blocks)
        assert "23h" in fields_text or "h" in fields_text

    def test_client_expired_message(self, capsys):
        client = self._make_client(110.0, status="expired")
        blocks, fallback = _client_expired_blocks(client)

        print("\n=== CLIENT EXPIRED ===")
        _pp(blocks, fallback)

        assert "EXPIRED" in fallback
        assert "red_circle" in json.dumps(blocks)
        assert "07-tendermint-42" in json.dumps(blocks)

    def test_startup_message(self, capsys):
        config = _default_config(
            pending_packet_age_minutes=10,
            pending_ack_age_minutes=10,
            client_expiry_warn_pct=[50, 75, 90],
            repeat_interval_minutes=60,
            poll_interval_seconds=60,
        )
        counts = {"chains": 2, "channels": 8, "clients": 4}
        blocks, fallback = _startup_blocks(config, counts)

        print("\n=== STARTUP STATUS ===")
        _pp(blocks, fallback)

        assert "started" in fallback.lower()
        body = json.dumps(blocks)
        assert "50%" in body
        assert "75%" in body
        assert "90%" in body
        assert "[50" not in body
