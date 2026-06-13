from pathlib import Path
from types import SimpleNamespace

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


def test_build_parser_accepts_operator_flags(tmp_path):
    config_path = tmp_path / "custom.ini"

    args = run_bridge_tui.build_parser().parse_args(
        ["--config", str(config_path), "--check", "--print-config"]
    )

    assert args.config == str(config_path)
    assert args.check is True
    assert args.print_config is True


def test_default_config_path_prefers_env(monkeypatch, tmp_path):
    config_path = tmp_path / "env.ini"
    monkeypatch.setenv("AMMB_CONFIG", str(config_path))

    assert run_bridge_tui.default_config_path() == str(config_path)


def test_main_check_prints_preflight_and_exits(monkeypatch, capsys, tmp_path):
    report = SimpleNamespace(ready=True)

    monkeypatch.setattr(
        run_bridge_tui,
        "run_preflight",
        lambda config, include_tui: report,
    )
    monkeypatch.setattr(
        run_bridge_tui,
        "format_preflight_report",
        lambda preflight_report: "ready report",
    )

    exit_code = run_bridge_tui.main(
        ["--config", str(tmp_path / "config.ini"), "--check"]
    )

    assert exit_code == 0
    assert capsys.readouterr().out == "ready report\n"
