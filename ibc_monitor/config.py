from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import toml

ListStr = List[str]
DEFAULT_MAX_PAGINATION_PAGES = 1000
DEFAULT_PAGINATION_LIMIT = 100


class ChainConfig:
    def __init__(
        self,
        name: str,
        chain_id: str,
        rpcs: List[str],
        rests: List[str],
        whitelist_clients: ListStr,
        blacklist_clients: ListStr,
        whitelist_connections: ListStr,
        blacklist_connections: ListStr,
        whitelist_channels: ListStr,
        blacklist_channels: ListStr,
        state_refresh_interval: int,
        state_scan_timeout: int,
        home_chain: bool = False,
        max_pagination_pages: int = DEFAULT_MAX_PAGINATION_PAGES,
        pagination_limit: int = DEFAULT_PAGINATION_LIMIT,
        omit_closed_channels: bool = False,
        omit_inactive_clients: bool = False,
        excluded_sequences: Optional[Dict[str, List[Any]]] = None,
    ):
        self.name = name
        self.chain_id = chain_id
        self.rpcs = rpcs
        self.rests = rests
        self.whitelist_clients = whitelist_clients
        self.blacklist_clients = blacklist_clients
        self.whitelist_connections = whitelist_connections
        self.blacklist_connections = blacklist_connections
        self.whitelist_channels = whitelist_channels
        self.blacklist_channels = blacklist_channels
        self.state_refresh_interval = state_refresh_interval
        self.state_scan_timeout = state_scan_timeout
        self.home_chain = home_chain
        self.max_pagination_pages = max_pagination_pages
        self.pagination_limit = pagination_limit
        self.omit_closed_channels = omit_closed_channels
        self.omit_inactive_clients = omit_inactive_clients
        self.excluded_sequences = excluded_sequences or {}


class ExcludedSequences:
    def __init__(self, raw: Dict[str, Any]):
        self.map: Dict[str, Dict[str, set[int]]] = {}
        for key, value in raw.items():
            if not isinstance(key, str) or not key:
                raise ValueError("excluded_sequences keys must be non-empty strings")
            if isinstance(value, dict):
                for channel, seqs in value.items():
                    self._add_channel(key, channel, seqs)
            elif isinstance(value, list):
                # Backward-compatible flat form: [excluded_sequences] channel-0 = [...]
                self._add_channel("*", key, value)
            else:
                raise ValueError(
                    f"excluded_sequences.{key} must be a chain table or a legacy sequence list"
                )

    def _add_channel(self, chain_id: str, channel: str, seqs: Any) -> None:
        if not isinstance(channel, str) or not channel:
            raise ValueError(f"excluded_sequences.{chain_id} keys must be non-empty channel IDs")
        if not isinstance(seqs, list):
            raise ValueError(f"excluded_sequences.{chain_id}.{channel} must be a list")
        parsed: List[int] = []
        for s in seqs:
            if isinstance(s, str) and '-' in s:
                start, end = map(int, s.split('-', 1))
                if start <= 0 or end <= 0 or start > end:
                    raise ValueError(f"Invalid excluded sequence range {s!r} for {chain_id}/{channel}")
                parsed.extend(range(start, end + 1))
            else:
                seq = int(s)
                if seq <= 0:
                    raise ValueError(f"Invalid excluded sequence {s!r} for {chain_id}/{channel}")
                parsed.append(seq)
        self.map.setdefault(chain_id, {})[channel] = set(parsed)

    def is_excluded(self, channel: str, seq: int, chain_id: str | None = None) -> bool:
        if chain_id and seq in self.map.get(chain_id, {}).get(channel, set()):
            return True
        return seq in self.map.get("*", {}).get(channel, set())


class Config:
    def __init__(self, path: Path):
        try:
            import tomli
            with open(path, 'rb') as f:
                data = tomli.load(f)
        except ImportError:
            data = toml.load(path)
        raw_chains = data.get('chains', [])
        if not isinstance(raw_chains, list):
            raise ValueError('chains must be a list of chain tables')
        if 'excluded_sequences' in data:
            raise ValueError(
                'excluded_sequences must be configured inside each [[chains]] table'
            )
        exporter = data.get('exporter', {})
        if not isinstance(exporter, dict):
            raise ValueError('exporter must be a table')
        omit_closed_channels = self._bool(
            exporter.get('omit_closed_channels', False),
            'exporter.omit_closed_channels',
        )
        omit_inactive_clients = self._bool(
            exporter.get('omit_inactive_clients', False),
            'exporter.omit_inactive_clients',
        )

        self.chains: List[ChainConfig] = []
        excluded_sequences_by_chain: Dict[str, Dict[str, List[Any]]] = {}
        seen_chain_ids: set[str] = set()
        for c in raw_chains:
            if not isinstance(c, dict):
                raise ValueError('Each chain entry must be a table')
            name = self._required_str(c, 'name')
            chain_id = self._required_str(c, 'chain_id')
            if chain_id in seen_chain_ids:
                raise ValueError(f"Duplicate chain_id in config: {chain_id}")
            seen_chain_ids.add(chain_id)

            state_refresh_interval = self._positive_int(
                c.get('state_refresh_interval', 1800),
                f"{chain_id}.state_refresh_interval",
            )
            state_scan_timeout = self._positive_int(
                c.get('state_scan_timeout', 60),
                f"{chain_id}.state_scan_timeout",
            )
            chain_excluded_sequences = c.get('excluded_sequences', {})
            if not isinstance(chain_excluded_sequences, dict):
                raise ValueError(f"{chain_id}.excluded_sequences must be a table")
            if chain_excluded_sequences:
                excluded_sequences_by_chain[chain_id] = chain_excluded_sequences
            self.chains.append(
                ChainConfig(
                    name=name,
                    chain_id=chain_id,
                    rpcs=self._endpoint_list(c.get('rpcs', []), f"{chain_id}.rpcs"),
                    rests=self._endpoint_list(c.get('rests', []), f"{chain_id}.rests"),
                    whitelist_clients=self._str_list(c.get('whitelist_clients', []), f"{chain_id}.whitelist_clients"),
                    blacklist_clients=self._str_list(c.get('blacklist_clients', []), f"{chain_id}.blacklist_clients"),
                    whitelist_connections=self._str_list(c.get('whitelist_connections', []), f"{chain_id}.whitelist_connections"),
                    blacklist_connections=self._str_list(c.get('blacklist_connections', []), f"{chain_id}.blacklist_connections"),
                    whitelist_channels=self._str_list(c.get('whitelist_channels', []), f"{chain_id}.whitelist_channels"),
                    blacklist_channels=self._str_list(c.get('blacklist_channels', []), f"{chain_id}.blacklist_channels"),
                    state_refresh_interval=state_refresh_interval,
                    state_scan_timeout=state_scan_timeout,
                    home_chain=c.get('home_chain', False),
                    max_pagination_pages=self._positive_int(
                        c.get('max_pagination_pages', DEFAULT_MAX_PAGINATION_PAGES),
                        f"{chain_id}.max_pagination_pages",
                    ),
                    pagination_limit=self._positive_int(
                        c.get('pagination_limit', DEFAULT_PAGINATION_LIMIT),
                        f"{chain_id}.pagination_limit",
                    ),
                    omit_closed_channels=self._bool(
                        c.get('omit_closed_channels', omit_closed_channels),
                        f"{chain_id}.omit_closed_channels",
                    ),
                    omit_inactive_clients=self._bool(
                        c.get('omit_inactive_clients', omit_inactive_clients),
                        f"{chain_id}.omit_inactive_clients",
                    ),
                    excluded_sequences=chain_excluded_sequences,
                )
            )
        home = [c for c in self.chains if c.home_chain]
        if len(home) != 1:
            raise ValueError('Exactly one chain must be marked as home_chain')
        self.home_chain = home[0]
        if not self.home_chain.rests:
            raise ValueError(f"Home chain {self.home_chain.chain_id} must define at least one valid REST endpoint")
        self.excluded_sequences = ExcludedSequences(excluded_sequences_by_chain)
        self.address = self._optional_str(exporter.get('address', '0.0.0.0'), 'exporter.address')
        self.port = self._port(exporter.get('port', 8000))
        self.update_interval = self._positive_int(
            exporter.get('update_interval_seconds', 30),
            'exporter.update_interval_seconds',
        )
        self.log_level = self._optional_str(exporter.get('log_level', 'INFO'), 'exporter.log_level')
        self.enable_chain_registry_fallbacks = self._bool(
            exporter.get('enable_chain_registry_fallbacks', False),
            'exporter.enable_chain_registry_fallbacks',
        )
        self.max_pagination_pages = self._positive_int(
            exporter.get('max_pagination_pages', DEFAULT_MAX_PAGINATION_PAGES),
            'exporter.max_pagination_pages',
        )
        self.pagination_limit = self._positive_int(
            exporter.get('pagination_limit', DEFAULT_PAGINATION_LIMIT),
            'exporter.pagination_limit',
        )
        self.omit_closed_channels = omit_closed_channels
        self.omit_inactive_clients = omit_inactive_clients
        self.max_workers = self._positive_int(
            exporter.get('max_workers', 16),
            'exporter.max_workers',
        )

    @staticmethod
    def _required_str(data: Dict[str, Any], key: str) -> str:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Missing or invalid required string field: {key}")
        return value.strip()

    @staticmethod
    def _optional_str(value: Any, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _str_list(value: Any, name: str) -> List[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError(f"{name} must be a list of strings")
        out: List[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"{name} must contain only strings")
            item = item.strip()
            if item:
                out.append(item)
        return out

    @classmethod
    def _endpoint_list(cls, value: Any, name: str) -> List[str]:
        endpoints = []
        for endpoint in cls._str_list(value, name):
            parsed = urlparse(endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"{name} contains invalid URL: {endpoint}")
            endpoints.append(endpoint.rstrip("/"))
        return endpoints

    @staticmethod
    def _positive_int(value: Any, name: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{name} must be a positive integer")
        if parsed <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return parsed

    @staticmethod
    def _bool(value: Any, name: str) -> bool:
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be a boolean")
        return value

    @classmethod
    def _port(cls, value: Any) -> int:
        port = cls._positive_int(value, 'exporter.port')
        if port > 65535:
            raise ValueError('exporter.port must be between 1 and 65535')
        return port
