#!/usr/bin/python -W ignore::DeprecationWarning

import getopt, sys
from helpers import *
from cloudfront import *
from certbot import *
import logging

config_file = "/etc/certman.conf"
config = loadConfig(config_file)
domain_objects = loadDomainConfigs(config['domain_config_directory'])

def certbot():
    ran = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ahgrudwv:", [
          "generate-certificates",
          "renew-certificates",
          "upload-certificates",
          "update-cloudfront-distributions",
          "help"])
    except getopt.GetoptError, err:
        print str(err) # will print something like "option -z not recognized"
        usage()
        sys.exit(2)
    for opt, arg in opts:
        ran = True
        if opt in ("-a", "--all"):
            updateCloudFrontWellKnown(domain_objects, config['certbot_server'])
            generateCertificates(config, domain_objects)
            renewCertificates(config['certbot_binary_path'], config['certbot_arguments'])
            uploadCloudFrontCertificates(domain_objects, config['certbot_certificate_path'])
            updateCloudFrontDistributions(domain_objects, config['certbot_certificate_path'])
        elif opt in ("-g", "--generate-certificates"):
            generateCertificates(config, domain_objects)
        elif opt in ("-r", "--renew-certificates"):
            renewCertificates(config['certbot_binary_path'], config['certbot_arguments'])
        elif opt in ("-u", "--upload-certificates"):
            uploadCloudFrontCertificates(domain_objects, config['certbot_certificate_path'])
        elif opt in ("-d", "--update-cloudfront-distributions"):
            updateCloudFrontDistributions(domain_objects, config['certbot_certificate_path'])
        elif opt in ("-w", "--add-well-known"):
            updateCloudFrontWellKnown(domain_objects, config['certbot_server'])
        elif opt in ("-l", "--list"):
            cert_info = listCertificates()
            if cert_info != False:
                print cert_info
        elif opt in ("-h", "--help"):
            usage()
        else:
           assert False, "unhandled option"

    if not ran:
        usage()

if __name__ == "__main__":
    certbot()
