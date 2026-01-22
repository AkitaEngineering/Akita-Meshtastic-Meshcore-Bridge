import importlib.util


def test_load_config_missing_default(tmp_path):
    cfgfile = tmp_path / "no_default.ini"
    cfgfile.write_text("[serial]\nSERIAL_PORT=/dev/ttyS1\n")

    spec = importlib.util.spec_from_file_location('config_handler', 'ammb/config_handler.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    cfg = mod.load_config(str(cfgfile))
    assert cfg is not None
    assert cfg.log_level == 'INFO'
