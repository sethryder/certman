#!/usr/bin/python -W ignore::DeprecationWarning

import getopt, sys, logging
from helpers import *
from cloudfront import *
from certbot import *
from validator import *

config_file = "/etc/certman.conf"
config = loadConfig(config_file)
domain_objects = loadDomainConfigs(config['domain_config_directory'])

def certbot():
    ran = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "achgrudw", [
          "all",
          "check-certificates",
          "generate-certificates",
          "renew-certificates",
          "upload-certificates",
          "update-cloudfront-distributions",
          "list",
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
        elif opt in ("-c", "--check-certificates"):
            results = checkCertificates(domain_objects, config)
            report = buildCheckReport(results, config['template_directory'])
            print report
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
            for domain in domain_objects.keys():
                certs_info = listCertificates(domain)
                print("%s: " % domain)
                for i in certs_info:
                    for k,v in i.iteritems():
                       print("  %s: %s" % (k,v))
        elif opt in ("-h", "--help"):
            usage()
        else:
           assert False, "unhandled option"

    if not ran:
        usage()

if __name__ == "__main__":
    certbot()
