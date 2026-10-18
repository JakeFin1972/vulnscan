"""Cooperative scan cancellation.

A scan registers an Event when it is created; the cancel endpoint sets it; the scan loops poll it
between units of work (per file for static scans, per tool for dynamic scans) and raise
ScanCancelled. A tool that is already running (e.g. an nmap subprocess) finishes first."""
import threading

_events: dict[str, threading.Event] = {}
_lock = threading.Lock()


class ScanCancelled(Exception):
    """Raised inside a scan when the user asked it to stop."""


def register(scan_id: str) -> threading.Event:
    with _lock:
        return _events.setdefault(scan_id, threading.Event())


def request(scan_id: str) -> None:
    register(scan_id).set()


def is_requested(scan_id: str) -> bool:
    with _lock:
        ev = _events.get(scan_id)
    return bool(ev and ev.is_set())


def clear(scan_id: str) -> None:
    with _lock:
        _events.pop(scan_id, None)


def checker(scan_id: str):
    """A zero-argument callable for `should_stop=` parameters."""
    return lambda: is_requested(scan_id)
