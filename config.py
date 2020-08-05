import os
import sys
import yaml

config_file = "config/certman-sample.conf"

def load_config(config_file):
    if os.path.isfile(config_file):
        with open(config_file) as config_file:
            config = yaml.load(config_file, Loader=yaml.FullLoader)
            return config
    else:
        print('Config file ' + config_file + ' does not exist!')
        return False

c = load_config(config_file)