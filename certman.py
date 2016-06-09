#!/usr/bin/python -W ignore::DeprecationWarning

import yaml, os, sys, logging
from subprocess import Popen, PIPE
from helpers import *

certbot_binary_path = "/Users/sethryder/dev/certman/test.sh"
domain_config_directory = "/Users/sethryder/dev/temp/conf"
hash_file_directory = '/Users/sethryder/dev/temp/hash'

def generateCertificates():

    domain_objects = loadConfigs(domain_config_directory)

    for primary_domain, config in domain_objects.iteritems():
        if 'additional_domains' in config:
            config_hash = generateHash(primary_domain, config['additional_domains'])
        else:
            config_hash = generateHash(primary_domain)

        saved_hash = getSavedHash(primary_domain, hash_file_directory)

        if saved_hash == config_hash:
            print "Making some certs!"

            command = certbot_binary_path + ' certonly --expand --agree-tos \
            --non-interactive -c /opt/letsencrypt/letsencrypt.ini'

            command = command + " -d " + primary_domain

            if 'additional_domains' in config:
                for additional_domain in config['additional_domains']:
                    command = command + ' -d ' + additional_domain

            p = Popen(command, shell=True, stdout=PIPE)
            output = p.communicate()[0]

            if p.returncode != 0:
                print "Something went wrong."
            else:
                print "All good!"
                setSavedHash(primary_domain, hash_file_directory, config_hash)
        else:
            print "Hashes matches, moving on!"

def renewCertificates():

    command = certbot_binary_path + ' renew --expand --agree-tos\
    --non-interactive -c /opt/letsencrypt/letsencrypt.ini'

    p = Popen(command, shell=True, stdout=PIPE)
    output = p.communicate()[0]

    if p.returncode != 0:
        print "Something went wrong."
    else:
        print "All good!"

generateCertificates()
#renewCertificates()
