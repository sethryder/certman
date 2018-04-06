import boto3
import yaml
import os
import sys
import logging
import hashlib
import json

logger = logging.getLogger('certman')

def create_aws_client(service):
    aws_client = boto3.client(service)
    return aws_client

def generate_hash(primary_domain, additional_domains = None):
    domain_object = {}
    domain_object['primary'] = primary_domain
    domain_object['additional_domains'] = additional_domains

    md5Hash = hashlib.md5(json.dumps(domain_object, sort_keys=True)).hexdigest()
    return md5Hash

def generate_cloudfront_hash(primary_domain, certificate_path):
    primary_path = certificate_path + '/' + primary_domain

    if os.path.isfile(primary_path + '/cert.pem'):
        with open(primary_path + '/cert.pem') as cert_file:
            cert = cert_file.read()
            cert_hash = hashlib.md5(cert).hexdigest()
        return cert_hash
    else:
        logger.error('Cert file does not exist. \r\n Primary Domain: ' + primary_domain + '\r\n Path: ' + certificate_path)
        return False

def get_saved_hash(primary_domain, hash_file_directory):
    hash_file_path = hash_file_directory + '/' + primary_domain + '.hash'

    if os.path.isfile(hash_file_path):
        target = open(hash_file_path, 'r')
        saved_hash = target.read()
        return saved_hash
    else:
        return False

def set_saved_hash(primary_domain, hash_file_directory, hash):
    hash_file_path = hash_file_directory + '/' + primary_domain + '.hash'

    if os.path.isdir(hash_file_directory):
        target = open(hash_file_path, 'w')
        target.truncate()
        target.write(hash)
        target.close()
        return True
    else:
        logger.error('Hash directory: ' + hash_file_directory + ' does not exist!')
    return False

def get_lastest_certificate_time(primary_domain, certificate_directory):
    certificate_file_path = certificate_directory + '/' + primary_domain + '/cert.pem'

    if os.path.isfile(certificate_file_path):
        modified_time = os.path.getmtime(certificate_file_path)
        return modified_time
    else:
        return False

def load_config(config_file):
    if os.path.isfile(config_file):
        with open(config_file) as config_file:
            config = yaml.load(config_file)
            return config
    else:
        print('Config file ' + config_file + ' does not exist!')
        return False

def load_domain_configs(config_directory):
    configs = {}
    if os.path.isdir(config_directory):
        os.chdir(config_directory)
        for file in os.listdir(config_directory):
            if file.endswith(".conf"):
                with open(file) as config_file:
                  config = yaml.load(config_file)
                if config['primary_domain']:
                    primary_domain = config['primary_domain']
                    configs[primary_domain] = {}
                    if 'distribution_id' in config:
                        configs[primary_domain]['distribution_id'] = config['distribution_id']
                    if 'additional_domains' in config:
                        additional_domains = []
                        for domain in config['additional_domains']:
                            additional_domains.append(domain)
                        configs[primary_domain]['additional_domains'] = additional_domains
                else:
                    logger.error('No primary domain set, invalid configuration file.')
    else:
        logger.error('Config directory ' + config_directory + ' does not exist!')
    return configs

def usage():
    print 'Usage: certman.py (option)'
    print ''
    print '-a, --all                                Run/do everything.'
    print '-c, --check-certificates                 Check and validate all known SSL certificates.'
    print '-g, --generate-certificates              Generate SSL certificates.'
    print '-r, --renew-certificates                 Renew SSL certificates.'
    print '-u, --upload-certificates                Upload SSL certificates to CloudFront.'
    print '-d, --update-cloudfront-distributions    Update CloudFront distributions with the latest SSL certificate.'
    print '-w, --add-well-known                     Add ./well-known origin and behavior to CloudFront distribution.'
    print '-p, --prune-certificates                 Prune old certificates that are no longer in use and are not the latest available.'
    print '-e, --generate-hash                      Generate the hash file for a domains config. Useful when importing an existing certificate.'
    print '-l, --list                               List certificates.'
    print '-q, --quiet                              No output, except for errors.'
    print ''
