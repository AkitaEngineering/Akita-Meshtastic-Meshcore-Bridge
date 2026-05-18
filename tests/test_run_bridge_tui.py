from pathlib import Path

import run_bridge_tui


def test_check_runtime_dependencies_deduplicates_missing_packages():
    def fake_import(module_name):
        if module_name in {"meshtastic", "meshtastic.serial_interface", "textual"}:
            raise ImportError(module_name)
        return object()

    missing = run_bridge_tui.check_runtime_dependencies(importer=fake_import)

    assert missing == ["meshtastic", "textual"]


def test_install_command_points_to_requirements_file(tmp_path):
    command = run_bridge_tui.install_command(str(tmp_path))

    assert command == f"pip install -r {tmp_path / 'requirements.txt'}"


def test_write_crash_report_persists_traceback(tmp_path):
    try:
        raise RuntimeError("boom")
    except RuntimeError as exc:
        crash_report = run_bridge_tui.write_crash_report(exc, str(tmp_path))

    report_path = Path(crash_report)
    report_text = report_path.read_text(encoding="utf-8")

    assert report_path.name == run_bridge_tui.CRASH_LOG_FILE
    assert "AMMB TUI crash" in report_text
    assert "RuntimeError: boom" in report_text