import importlib.util

spec = importlib.util.spec_from_file_location(
    "config_handler", "ammb/config_handler.py"
)
if spec is None or spec.loader is None:
    raise SystemExit("Failed to locate module spec for config_handler")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print("Using file: tmp_no_default.ini")
print(mod.load_config("tmp_no_default.ini"))
