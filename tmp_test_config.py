from ammb import config_handler
path='tmp_no_default.ini'
with open(path,'w') as f:
    f.write('[serial]\nSERIAL_PORT=/dev/ttyS1\n')
print('Using file:', path)
cfg = config_handler.load_config(path)
print('Result:', cfg)
