"""providers.base.timeout_refused: a timeout no provider call can run under
is refused before anything starts (operator decision 2026-10-30).

The drain's fuzzer found every provider's review() raising OverflowError on
an infinite `timeout_s`, and `[llm].call_timeout_s = inf` loads (TOML has
`inf`). Measured the same day: `run_provider_subprocess` with `inf` or
`1e300` started the child, raised 0.02 s later, and left it running until it
ended by itself -- a review call nobody waited for."""
import math

import pytest

from aramid import config_keys
from aramid.providers import base


@pytest.mark.parametrize("timeout_s", [240.0, 240, 0.5, config_keys.CALL_TIMEOUT_MAX_S])
def test_a_usable_timeout_is_not_refused(timeout_s):
    assert base.timeout_refused(timeout_s) is None


@pytest.mark.parametrize("timeout_s", [math.inf, -math.inf, math.nan, 0, 0.0, -1.0, 1e300,
                                       config_keys.CALL_TIMEOUT_MAX_S + 0.5,
                                       True, "240", None])
def test_an_unusable_timeout_is_refused_with_its_reason(timeout_s):
    resp = base.timeout_refused(timeout_s)
    assert (resp.error, resp.text) == (base.ERR_ERROR, "")
    assert resp.detail == ("bad timeout: timeout_s must be a number above 0 and at most "
                           f"86400, got {timeout_s!r}")
    assert config_keys.CALL_TIMEOUT_MAX_S == 86400.0
