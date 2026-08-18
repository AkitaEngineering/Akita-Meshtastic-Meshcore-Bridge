from ammb.rate_limiter import RateLimiter, limiter_from_config
from tests.conftest import make_bridge_config


def test_rate_limiter_allows_up_to_max_then_blocks():
    limiter = RateLimiter(max_messages=2, time_window=60.0)
    assert limiter.check_rate_limit("src") is True
    assert limiter.check_rate_limit("src") is True
    assert limiter.check_rate_limit("src") is False
    assert limiter.get_stats()["violations"] == 1


def test_limiter_from_config_uses_configured_limits():
    config = make_bridge_config(
        rate_limit_max_messages=3,
        rate_limit_window_s=30.0,
    )
    limiter = limiter_from_config(config)
    assert limiter.max_messages == 3
    assert limiter.time_window == 30.0


def test_rate_limiter_reset_clears_state():
    limiter = RateLimiter(max_messages=1, time_window=60.0)
    assert limiter.check_rate_limit("src") is True
    assert limiter.check_rate_limit("src") is False
    limiter.reset()
    assert limiter.check_rate_limit("src") is True
