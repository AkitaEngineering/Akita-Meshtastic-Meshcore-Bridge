import asyncio
import threading
from unittest.mock import patch

import pytest

from ammb.bridge_async import AsyncBridge
from tests.conftest import make_bridge_config


class _FakeProductionBridge:
    def __init__(self, config):
        self.config = config
        self.started = threading.Event()
        self.stopped = False
        self.meshtastic_handler = None
        self.external_handler = None

    def run(self):
        self.started.set()
        self.started.wait(timeout=2)

    def stop(self):
        self.stopped = True
        self.started.set()


def test_async_bridge_runs_production_bridge():
    config = make_bridge_config(api_enabled=False)
    fake = _FakeProductionBridge(config)

    with patch("ammb.bridge_async.Bridge", return_value=fake):
        async_bridge = AsyncBridge(config)
        async_bridge.bridge = fake

        async def _run():
            task = asyncio.create_task(async_bridge.start())
            for _ in range(40):
                if fake.started.is_set():
                    break
                await asyncio.sleep(0.05)
            assert fake.started.is_set()
            await async_bridge.shutdown()
            await asyncio.wait_for(task, timeout=2)

        asyncio.run(_run())

    assert fake.stopped is True


def test_async_bridge_does_not_need_api_when_disabled():
    config = make_bridge_config(api_enabled=False)
    async_bridge = AsyncBridge(config)
    assert async_bridge.bridge.config is config


def test_async_bridge_disables_duplicate_sync_api():
    config = make_bridge_config(api_enabled=True)

    with patch("ammb.bridge_async.Bridge") as bridge_class:
        AsyncBridge(config)

    wrapped_config = bridge_class.call_args.args[0]
    assert wrapped_config.api_enabled is False
    assert config.api_enabled is True


@pytest.mark.parametrize("failure", [RuntimeError("API failed"), SystemExit(1)])
def test_async_api_failure_always_stops_bridge(failure):
    config = make_bridge_config(api_enabled=True)
    fake = _FakeProductionBridge(config)
    fake.shutdown_event = threading.Event()
    fake.run = lambda: fake.shutdown_event.wait(timeout=5)

    def stop():
        fake.stopped = True
        fake.shutdown_event.set()

    fake.stop = stop

    class FailingServer:
        def __init__(self, config):
            self.should_exit = False

        async def serve(self):
            raise failure

    with patch("ammb.bridge_async.Bridge", return_value=fake), patch(
        "uvicorn.Server", FailingServer
    ):
        bridge = AsyncBridge(config)
        with pytest.raises(RuntimeError):
            asyncio.run(bridge.start())
    assert fake.stopped
    assert not bridge._bridge_thread.is_alive()
