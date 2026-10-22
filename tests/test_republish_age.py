"""The public seal log is republished on a schedule. Its age is Last-Modified."""

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit_surfaces", ROOT / "tools" / "audit_surfaces.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def test_a_recent_last_modified_is_a_few_hours():
    now = datetime(2026, 10, 22, 14, 0, tzinfo=timezone.utc)
    age = mod.republish_age_hours("Thu, 22 Oct 2026 13:50:01 GMT", now)
    assert age is not None
    assert abs(age - (10 / 60)) < 0.01


def test_a_missing_or_unparseable_header_is_not_an_age():
    now = datetime(2026, 10, 22, tzinfo=timezone.utc)
    assert mod.republish_age_hours(None, now) is None
    assert mod.republish_age_hours("not a date", now) is None


def test_thirty_days_of_silence_is_still_a_number_of_hours():
    now = datetime(2026, 10, 22, tzinfo=timezone.utc)
    then = now - timedelta(days=33)
    header = then.strftime("%a, %d %b %Y %H:%M:%S GMT")
    age = mod.republish_age_hours(header, now)
    assert age > 30 * 24
