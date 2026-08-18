import threading
from unittest.mock import patch

from ammb.bridge import Bridge
from tests.conftest import make_bridge_config


class _FakeMeshtastic:
    def __init__(self, *args, **kwargs):
        self.connect_calls = 0
        self.started = False
        self.stopped = False
        self._is_connected = threading.Event()

    def connect(self):
        self.connect_calls += 1
        return False

    def start_sender(self):
        self.started = True

    def stop(self):
        self.stopped = True


class _FakeExternal:
    def __init__(self, *args, **kwargs):
        self._is_connected = threading.Event()
        self.started = False
        self.stopped = False

    def connect(self):
        return True

    def start_threads(self):
        self.started = True

    def start_publisher(self):
        self.started = True

    def stop(self):
        self.stopped = True


def test_bridge_retries_meshtastic_on_boot_without_exiting():
    config = make_bridge_config(meshtastic_retry_on_boot=True)
    fake_mt = _FakeMeshtastic()
    fake_ext = _FakeExternal()

    with patch("ammb.bridge.MeshtasticHandler", return_value=fake_mt), patch(
        "ammb.bridge.MeshcoreHandler", return_value=fake_ext
    ):
        bridge = Bridge(config)

        def _stop_soon():
            bridge.shutdown_event.wait(0.2)
            bridge.shutdown_event.set()

        stopper = threading.Thread(target=_stop_soon)
        stopper.start()
        bridge.run()
        stopper.join()

    assert fake_mt.connect_calls == 1
    assert fake_mt.started is True
    assert fake_ext.started is True
    assert fake_mt.stopped is True


def test_bridge_can_fail_closed_when_retry_disabled():
    config = make_bridge_config(meshtastic_retry_on_boot=False)
    fake_mt = _FakeMeshtastic()
    fake_ext = _FakeExternal()

    with patch("ammb.bridge.MeshtasticHandler", return_value=fake_mt), patch(
        "ammb.bridge.MeshcoreHandler", return_value=fake_ext
    ):
        bridge = Bridge(config)
        bridge.run()

    assert fake_mt.connect_calls == 1
    assert fake_mt.started is False
    assert fake_mt.stopped is True


def test_meshtastic_sender_reconnects_instead_of_dropping():
    from queue import Queue

    from ammb.meshtastic_handler import MeshtasticHandler

    config = make_bridge_config(meshtastic_retry_delay_s=1)
    shutdown = threading.Event()
    handler = MeshtasticHandler(
        config,
        to_external_queue=Queue(),
        from_external_queue=Queue(),
        shutdown_event=shutdown,
    )

    def _fail_and_stop():
        shutdown.set()
        return False

    handler.connect = _fail_and_stop
    handler._meshtastic_sender_loop()
    assert shutdown.is_set()
