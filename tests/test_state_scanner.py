import pytest
from ibc_monitor.state_scanner import StateScanner
from requests.exceptions import HTTPError
from requests import Response


class DummyClient:
    def __init__(self, data):
        self._data = data
        self.expected_chain_id = 'unused'

    def query(self, path, params=None, timeout=None):
        # return based on path
        return self._data.get(path, {})

    def health(self):
        return True

class DummyCfg:
    whitelist_clients = []
    blacklist_clients = []
    whitelist_connections = []
    blacklist_connections = []
    whitelist_channels = []
    blacklist_channels = []
    state_refresh_interval = 0
    state_scan_timeout = 1
    omit_closed_channels = False
    omit_inactive_clients = False

@pytest.fixture
def scanner():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
                {'client_id': 'c2', 'client_state': {'chain_id': 'cp'}},
            ]
        },
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn1']
        },
        '/ibc/core/connection/v1/client_connections/c2': {
            'connection_paths': []
        },
        '/ibc/core/channel/v1/connections/conn1/channels': {
            'channels': [{'port_id': 'p', 'channel_id': 'c', 'counterparty': {'port_id': 'cp', 'channel_id': 'cc'}}]
        },
    }
    client = DummyClient(data)
    cfg = DummyCfg()
    return StateScanner(client, cfg, ['cp'])


def test_scan_all(scanner):
    scanner.scan()
    assert sorted(scanner.clients) == ['c1', 'c2']
    assert scanner.connections == ['conn1']
    assert ('conn1', 'p', 'c', 'cp', 'cc', 'cp') in scanner.channels
    assert scanner.client_status_map == {'c1': 'unknown', 'c2': 'unknown'}
    assert scanner.channel_state_map[('unused', 'conn1', 'p', 'c')] == 'unknown'


class DummyClientWith404(DummyClient):
    def __init__(self, data, error_paths):
        super().__init__(data)
        self.error_paths = error_paths

    def query(self, path, params=None, timeout=None):
        if path in self.error_paths:
            resp = Response()
            resp.status_code = 404
            raise HTTPError(response=resp)
        return super().query(path, params, timeout)


def test_scan_ignores_missing_connections():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
            ]
        },
    }
    client = DummyClientWith404(
        data, {'/ibc/core/connection/v1/client_connections/c1'}
    )
    cfg = DummyCfg()
    scanner = StateScanner(client, cfg, ['cp'])
    scanner.scan()
    assert scanner.clients == ['c1']
    assert scanner.connections == []
    assert scanner.channels == []


def test_scan_ignores_missing_channels():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
            ]
        },
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn1']
        },
    }
    client = DummyClientWith404(
        data, {'/ibc/core/channel/v1/connections/conn1/channels'}
    )
    cfg = DummyCfg()
    scanner = StateScanner(client, cfg, ['cp'])
    scanner.scan()
    assert scanner.clients == ['c1']
    assert scanner.connections == ['conn1']
    assert scanner.channels == []


def test_skips_wrong_counterparty():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
                {'client_id': 'c2', 'client_state': {'chain_id': 'other'}},
            ]
        },
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn1']
        },
        '/ibc/core/connection/v1/client_connections/c2': {
            'connection_paths': ['conn2']
        },
    }
    client = DummyClient(data)
    cfg = DummyCfg()
    scanner = StateScanner(client, cfg, ['cp'])
    scanner.scan()
    assert scanner.clients == ['c1']
    assert scanner.connections == ['conn1']


def test_scan_keeps_previous_state_on_failure():
    class FailingClient(DummyClient):
        def query(self, path, params=None, timeout=None):
            raise RuntimeError("boom")

    cfg = DummyCfg()
    scanner = StateScanner(FailingClient({}), cfg, ['cp'])
    scanner.clients = ['old-client']
    assert scanner.scan() is False
    assert scanner.clients == ['old-client']
    assert scanner.last_scan == 0


def test_scan_fails_on_repeated_pagination_key():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [],
            'pagination': {'next_key': 'same'},
        },
        '/ibc/core/client/v1/client_states?pagination.key=same': {
            'client_states': [],
            'pagination': {'next_key': 'same'},
        },
    }
    cfg = DummyCfg()
    scanner = StateScanner(DummyClient(data), cfg, ['cp'])
    assert scanner.scan() is False
    assert scanner.last_scan == 0


def test_omit_inactive_clients():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
                {'client_id': 'c2', 'client_state': {'chain_id': 'cp'}},
            ]
        },
        '/ibc/core/client/v1/client_status/c1': {'status': 'Active'},
        '/ibc/core/client/v1/client_status/c2': {'status': 'Expired'},
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn1']
        },
        '/ibc/core/channel/v1/connections/conn1/channels': {
            'channels': []
        },
    }

    class Cfg(DummyCfg):
        omit_inactive_clients = True

    scanner = StateScanner(DummyClient(data), Cfg(), ['cp'])
    assert scanner.scan() is True
    assert scanner.clients == ['c1']
    assert scanner.client_status_map == {'c1': 'active'}


def test_omit_closed_channels():
    data = {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
            ]
        },
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn1']
        },
        '/ibc/core/channel/v1/connections/conn1/channels': {
            'channels': [
                {
                    'port_id': 'p',
                    'channel_id': 'open',
                    'state': 'STATE_OPEN',
                    'counterparty': {'port_id': 'cp', 'channel_id': 'cc-open'},
                },
                {
                    'port_id': 'p',
                    'channel_id': 'closed',
                    'state': 'STATE_CLOSED',
                    'counterparty': {'port_id': 'cp', 'channel_id': 'cc-closed'},
                },
            ]
        },
    }

    class Cfg(DummyCfg):
        omit_closed_channels = True

    scanner = StateScanner(DummyClient(data), Cfg(), ['cp'])
    assert scanner.scan() is True
    assert scanner.channels == [('conn1', 'p', 'open', 'cp', 'cc-open', 'cp')]
    assert scanner.channel_state_map == {('unused', 'conn1', 'p', 'open'): 'open'}


def _two_connection_celestia_like_data():
    return {
        '/ibc/core/client/v1/client_states': {
            'client_states': [
                {'client_id': 'c1', 'client_state': {'chain_id': 'cp'}},
            ]
        },
        '/ibc/core/connection/v1/client_connections/c1': {
            'connection_paths': ['conn-a', 'conn-b']
        },
        '/ibc/core/connection/v1/connections/conn-a': {
            'connection': {
                'counterparty': {'client_id': 'cp-16', 'connection_id': 'cp-conn-3'},
            }
        },
        '/ibc/core/connection/v1/connections/conn-b': {
            'connection': {
                'counterparty': {'client_id': 'cp-0', 'connection_id': 'cp-conn-4'},
            }
        },
        '/ibc/core/channel/v1/connections/conn-a/channels': {
            'channels': [{
                'port_id': 'transfer',
                'channel_id': 'channel-161',
                'counterparty': {'port_id': 'transfer', 'channel_id': 'channel-3'},
            }]
        },
        '/ibc/core/channel/v1/connections/conn-b/channels': {
            'channels': [{
                'port_id': 'transfer',
                'channel_id': 'channel-162',
                'counterparty': {'port_id': 'transfer', 'channel_id': 'channel-4'},
            }]
        },
    }


def test_home_client_records_all_counterparty_clients():
    scanner = StateScanner(DummyClient(_two_connection_celestia_like_data()), DummyCfg(), ['cp'])
    assert scanner.scan() is True
    assert scanner.client_counterparty_client_ids == {'c1': ['cp-16', 'cp-0']}
    assert scanner.connections == ['conn-a', 'conn-b']
    assert ('conn-a', 'transfer', 'channel-161', 'transfer', 'channel-3', 'cp') in scanner.channels
    assert ('conn-b', 'transfer', 'channel-162', 'transfer', 'channel-4', 'cp') in scanner.channels


def test_blacklisted_home_connection_excludes_its_counterparty_client():
    class Cfg(DummyCfg):
        blacklist_connections = ['conn-a']

    scanner = StateScanner(DummyClient(_two_connection_celestia_like_data()), Cfg(), ['cp'])
    assert scanner.scan() is True
    assert scanner.connections == ['conn-b']
    assert scanner.client_counterparty_client_ids == {'c1': ['cp-0']}
    assert scanner.channels == [
        ('conn-b', 'transfer', 'channel-162', 'transfer', 'channel-4', 'cp')
    ]
