import importlib.util
spec = importlib.util.spec_from_file_location('config_handler', 'ammb/config_handler.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print('Using file: tmp_no_default.ini')
print(mod.load_config('tmp_no_default.ini'))
