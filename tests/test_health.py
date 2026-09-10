from ammb.health import HealthMonitor


def test_health_monitor_stops_promptly_and_restarts_without_old_worker():
    monitor = HealthMonitor(check_interval=60)
    monitor.start_monitoring()
    original = monitor._monitor_thread
    monitor.stop_monitoring()
    assert not original.is_alive()
    monitor.start_monitoring()
    try:
        assert monitor._monitor_thread is not original
        assert monitor._monitor_thread.is_alive()
        assert not original.is_alive()
    finally:
        monitor.stop_monitoring()
