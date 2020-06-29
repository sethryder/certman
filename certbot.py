import os
import sys
import logging
from subprocess import Popen, PIPE
from helpers import *

logger = logging.getLogger('certman')

def generate_certificates(config_object, domain_objects):
    certbot_binary_path = config_object['certbot_binary_path']
    certbot_arguments = config_object['certbot_arguments']
    hash_file_directory = config_object['hash_file_directory']

    for primary_domain, config in domain_objects.items():
        if 'additional_domains' in config:
            config_hash = generate_hash(primary_domain, config['additional_domains'])
        else:
            config_hash = generate_hash(primary_domain)

        saved_hash = get_saved_hash(primary_domain, hash_file_directory)

        if saved_hash != config_hash:
            logger.info(primary_domain + ': Generating certificate(s)')

            command = certbot_binary_path + ' certonly ' + certbot_arguments
            command = command + " -d " + primary_domain

            if 'additional_domains' in config:
                for additional_domain in config['additional_domains']:
                    command = command + ' -d ' + additional_domain

            p = Popen(command, shell=True, stdout=PIPE)
            output = p.communicate()[0]

            if p.returncode != 0:
                logger.error(primary_domain + ": Unable to generate certificate(s). \r\nCommand:" + command + "\r\nOutput:" + output.decode('utf-8'))
            else:
                set_saved_hash(primary_domain, hash_file_directory, config_hash)

def renew_certificates(certbot_binary_path, certbot_arguments):

    command = certbot_binary_path + ' renew ' + certbot_arguments

    p = Popen(command, shell=True, stdout=PIPE)
    output = p.communicate()[0]

    if p.returncode != 0:
        logger.error(output)
    else:
        logger.info('Certificate renewel finished')
