import ibc_monitor.metrics as metrics
from ibc_monitor.exporter import IBCExporter
from ibc_monitor.config import ChainConfig, ExcludedSequences, Config
import toml


# ---- Fakes for the home-anchored exporter ----

class FakeHomeClient:
    def __init__(self):
        self.endpoint = "http://home"
        self.fail_commitments = False

    def health(self):
        return True

    def query(self, path, params=None, timeout=None):
        # Local commitments: 1,2,3 (2 is excluded by config in the test)
        if "packet_commitments" in path and "unreceived_acks" not in path:
            if self.fail_commitments:
                raise RuntimeError("commitment query failed")
            return {"commitments": [{"sequence": "1"}, {"sequence": "2"}, {"sequence": "3"}]}

        # Accept ANY form of unreceived_acks request and always pretend "3" is unreceived.
        # This avoids coupling the test to the exact URL shape used by the exporter.
        if "unreceived_acks" in path:
            return {"sequences": ["3"]}

        # These are only hit if scanner.clients is non-empty; we keep it empty in the test
        if "/client/v1/client_states/" in path:
            return {"client_state": {"trusting_period": "1s", "chain_id": "chain-2"}}
        if "/client/v1/consensus_states/" in path:
            return {"consensus_state": {"timestamp": "2020-01-01T00:00:00Z"}}
        return {}


class FakeCounterpartyClient:
    def __init__(self):
        self.endpoint = "http://cp"

    def health(self):
        return True

    def query(self, path, params=None, timeout=None):
        # Simulate filtered acks endpoint (exporter calls with sequences filter).
        # Say CP has acks for sequences {2,3}. That's enough for the test logic.
        if "packet_acknowledgements" in path:
            return {"acknowledgements": [{"sequence": "2"}, {"sequence": "3"}]}
        return {}


class FakeScanner:
    def __init__(self):
        self.clients = ["client-1"]
        self.client_chain_map = {"client-1": "chain-2"}
        self.client_status_map = {"client-1": "active"}
        # One path: local (connection-1, port1/ch1) <-> counterparty (port2/ch2) on chain-2
        self.channels = [("connection-1", "port1", "ch1", "port2", "ch2", "chain-2")]
        self.channel_state_map = {("chain-1", "connection-1", "port1", "ch1"): "open"}
        self.client_counterparty_client_ids = {}  # home client -> list of cp clients
        # New exporter iterates this for CP-side metrics; keep empty for this test
        self.cp_channels = []
        self.cp_client_status_map = {}
        self.cp_channel_state_map = {}

    def scan(self):
        return True


def build_home_anchored_exporter():
    # Minimal config shell (only excluded_sequences used below)
    chain_cfg = ChainConfig(
        name="chain",
        chain_id="chain-1",
        rpcs=["http://rpc"],
        rests=["http://rest"],
        whitelist_clients=[],
        blacklist_clients=[],
        whitelist_connections=[],
        blacklist_connections=[],
        whitelist_channels=[],
        blacklist_channels=[],
        state_refresh_interval=1,
        state_scan_timeout=1,
    )

    exporter = IBCExporter.__new__(IBCExporter)
    exporter.cfg = type("Cfg", (), {})()
    exporter.cfg.excluded_sequences = ExcludedSequences({"chain-1": {"ch1": [2]}})
    exporter.cfg.address = "127.0.0.1"
    exporter.cfg.port = 0
    exporter.cfg.update_interval = 1
    exporter.cfg.omit_inactive_clients = False

    # Home-anchored attributes expected by the new exporter
    exporter.home_chain_cfg = chain_cfg
    exporter.home_client = FakeHomeClient()
    exporter.rest_by_chain = {"chain-2": FakeCounterpartyClient()}
    exporter.scanner = FakeScanner()

    # in-memory trackers
    exporter.pending_packets = {}
    exporter.pending_acks = {}

    return exporter


# ---- Tests ----

def test_excluded_sequences_filtered():
    metrics.BACKLOG_SIZE.clear()
    metrics.BACKLOG_OLDEST_SEQ.clear()
    metrics.ACK_BACKLOG_SIZE.clear()
    metrics.ACK_OLDEST_SEQ.clear()
    metrics.BACKLOG_UPDATED.clear()
    metrics.CLIENT_STATUS.clear()
    metrics.CHANNEL_STATE.clear()

    exporter = build_home_anchored_exporter()
    exporter.update_metrics()

    labels = dict(
        chain_id="chain-1",
        connection_id="connection-1",
        port_id="port1",
        channel_id="ch1",
        counterparty_chain_id="chain-2",
        counterparty_port_id="port2",
        counterparty_channel_id="ch2",
    )

    # Commitments: [1,2,3], exclude 2 => pending {1,3}
    assert metrics.BACKLOG_SIZE.labels(**labels)._value.get() == 2
    assert metrics.BACKLOG_OLDEST_SEQ.labels(**labels)._value.get() == 1

    # Fast-ack path: CP acks {2,3}; home unreceived_acks(...) => {3}; oldest = 3
    assert metrics.ACK_BACKLOG_SIZE.labels(**labels)._value.get() == 1
    assert metrics.ACK_OLDEST_SEQ.labels(**labels)._value.get() == 3
    assert metrics.CHANNEL_STATE.labels(**labels, state="open")._value.get() == 1
    assert metrics.CLIENT_STATUS.labels(
        chain_id="chain-1",
        client_id="client-1",
        counterparty_chain_id="chain-2",
        counterparty_client_id="",
        status="active",
    )._value.get() == 1


def test_home_client_metrics_omit_counterparty_client_id():
    metrics.CLIENT_STATUS.clear()
    metrics.CLIENT_TRUSTING_PERIOD.clear()
    metrics.CLIENT_LAST_UPDATE.clear()
    metrics.CHANNEL_STATE.clear()
    metrics.BACKLOG_SIZE.clear()
    metrics.BACKLOG_OLDEST_SEQ.clear()
    metrics.ACK_BACKLOG_SIZE.clear()
    metrics.ACK_OLDEST_SEQ.clear()
    metrics.BACKLOG_UPDATED.clear()

    exporter = build_home_anchored_exporter()
    exporter.scanner.client_counterparty_client_ids = {"client-1": ["cp-16", "cp-0"]}
    exporter.update_metrics()

    labels = dict(
        chain_id="chain-1",
        client_id="client-1",
        counterparty_chain_id="chain-2",
        counterparty_client_id="",
    )
    assert metrics.CLIENT_STATUS.labels(**labels, status="active")._value.get() == 1
    assert metrics.CLIENT_TRUSTING_PERIOD.labels(**labels)._value.get() == 1.0
    home_cp_ids = {
        sample.labels["counterparty_client_id"]
        for metric in (metrics.CLIENT_STATUS, metrics.CLIENT_TRUSTING_PERIOD)
        for family in metric.collect()
        for sample in family.samples
        if sample.labels.get("client_id") == "client-1"
        and sample.labels.get("chain_id") == "chain-1"
    }
    assert home_cp_ids == {""}


def test_failed_commitment_query_does_not_clear_existing_backlog():
    metrics.BACKLOG_SIZE.clear()
    metrics.BACKLOG_OLDEST_SEQ.clear()
    metrics.ACK_BACKLOG_SIZE.clear()
    metrics.ACK_OLDEST_SEQ.clear()
    metrics.BACKLOG_UPDATED.clear()

    exporter = build_home_anchored_exporter()
    exporter.update_metrics()
    exporter.home_client.fail_commitments = True
    exporter.update_metrics()

    labels = dict(
        chain_id="chain-1",
        connection_id="connection-1",
        port_id="port1",
        channel_id="ch1",
        counterparty_chain_id="chain-2",
        counterparty_port_id="port2",
        counterparty_channel_id="ch2",
    )
    assert metrics.BACKLOG_SIZE.labels(**labels)._value.get() == 2
    assert set(exporter.pending_packets[("chain-1", "connection-1", "port1", "ch1")]) == {1, 3}


def test_home_chain_counterparties(tmp_path):
    data = {
        "chains": [
            {"name": "h", "chain_id": "h-1", "rests": ["http://h"], "home_chain": True},
            {"name": "a", "chain_id": "a-1", "rests": ["http://a"], "home_chain": False},
            {"name": "b", "chain_id": "b-1", "rests": ["http://b"], "home_chain": False},
        ]
    }
    p = tmp_path / "c.toml"
    p.write_text(toml.dumps(data))
    cfg = Config(p)

    # Construct the real exporter; it won't hit the network until update_metrics()
    exp = IBCExporter(cfg)

    # New shape: one home-anchored scanner; counterparties are exposed via:
    #  - exp.scanner.counterparty_chain_ids
    #  - exp.rest_by_chain keys
    assert sorted(exp.scanner.counterparty_chain_ids) == ["a-1", "b-1"]
    assert set(exp.rest_by_chain.keys()) == {"a-1", "b-1"}


def test_chain_registry_fallback_builds_counterparty_clients_without_rest(tmp_path):
    data = {
        "chains": [
            {"name": "h", "chain_id": "h-1", "rests": ["http://h"], "home_chain": True},
            {"name": "a", "chain_id": "a-1", "rests": [""], "home_chain": False},
        ],
        "exporter": {"enable_chain_registry_fallbacks": True},
    }
    p = tmp_path / "c.toml"
    p.write_text(toml.dumps(data))
    cfg = Config(p)
    exp = IBCExporter(cfg)
    assert set(exp.rest_by_chain.keys()) == {"a-1"}
    assert exp.rest_by_chain["a-1"].endpoint == ""
