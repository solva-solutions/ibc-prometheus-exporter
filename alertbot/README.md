# IBC Slack Alert Bot

Polls the Prometheus metrics endpoint of
[ibc-prometheus-exporter](../) and sends Slack webhook alerts for:

- **Unreceived send packets** on any path older than a configurable threshold
- **Unacknowledged (ack) packets** on any path older than a configurable threshold
- **IBC light client approaching expiry** — fires once at 50%, 75%, and 90% of the
  trusting period consumed (thresholds are configurable)
- **IBC light client expired**

Alert state is persisted to a JSON file so thresholds are not re-fired across
restarts. Pending-packet alerts repeat on a configurable interval (default: 1 h)
while the backlog remains unresolved.

On startup the bot sends a single status message summarising the chains,
channels, and clients being monitored, followed by any alerts that are
currently active.

---

## Requirements

- Python 3.9+
- A running `ibc-prometheus-exporter` instance
- A Slack app with an [Incoming Webhook](https://api.slack.com/messaging/webhooks)
  configured

---

## Setup

### 1. Create a virtual environment

```bash
cd alertbot
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure

```bash
cp config.example.toml config.toml
```

Open `config.toml` and fill in the two required values:

```toml
[slack]
webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

[exporter]
metrics_url = "http://localhost:8000/metrics"   # adjust port if needed
```

All other settings have sensible defaults — see
[`config.example.toml`](config.example.toml) for the full reference with
inline documentation.

---

## Running

```bash
# from the repo root, with the venv active
python3 alertbot/alertbot.py --config alertbot/config.toml
```

Useful flags:

| Flag | Description |
|---|---|
| `--once` | Run a single check and exit (useful for testing) |
| `--dry-run` | Evaluate alerts but do not send any Slack messages |
| `--preview` | Send one example of every alert type to verify formatting, then exit |
| `--log-level DEBUG` | Verbose output including every poll cycle |

### Verify alert formatting

Send one example of each alert type to your Slack channel without needing live
alert conditions:

```bash
python3 alertbot/alertbot.py --config alertbot/config.toml --preview
```

### Test your setup without sending messages

```bash
python3 alertbot/alertbot.py --config alertbot/config.toml --once --dry-run
```

---

## Running as a systemd service

Create `/etc/systemd/system/ibc-alertbot.service`:

```ini
[Unit]
Description=IBC Slack Alert Bot
After=network.target

[Service]
Type=simple
User=<your-user>
WorkingDirectory=/path/to/ibc-prometheus-exporter
ExecStart=/path/to/ibc-prometheus-exporter/alertbot/.venv/bin/python3 \
    alertbot/alertbot.py --config alertbot/config.toml
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ibc-alertbot
sudo journalctl -u ibc-alertbot -f
```

---

## Configuration reference

| Key | Default | Description |
|---|---|---|
| `slack.webhook_url` | *(required)* | Slack Incoming Webhook URL |
| `exporter.metrics_url` | `http://localhost:8000/metrics` | Prometheus endpoint to scrape |
| `exporter.poll_interval_seconds` | `60` | How often to poll |
| `exporter.state_file` | `alertbot_state.json` | Where alert state is persisted |
| `thresholds.pending_packet_age_minutes` | `10` | Min age before a send-packet alert fires |
| `thresholds.pending_ack_age_minutes` | `10` | Min age before an ack-packet alert fires |
| `thresholds.repeat_interval_minutes` | `60` | Re-alert interval for active packet backlogs |
| `thresholds.client_expiry_warn_pct` | `[50, 75, 90]` | Trusting-period % thresholds for client alerts |
