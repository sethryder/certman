#!/usr/bin/python -W ignore::DeprecationWarning

import getopt
import sys
from log import init_logger
from helpers import *
from cloudfront import *
from certbot import *
from validator import *

config_file = "config/certman-sample.conf"
config = load_config(config_file)
logger = init_logger('test.log', config['email_errors'], config['log_level'])
domain_objects = load_domain_configs(config['domain_config_directory'])

def certman():
    ran = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "achgrudpw", [
          "all",
          "check-certificates",
          "generate-certificates",
          "renew-certificates",
          "upload-certificates",
          "update-cloudfront-distributions",
          "prune-certificates",
          "list",
          "help"])
    except getopt.GetoptError, err:
        print str(err) # will print something like "option -z not recognized"
        usage()
        sys.exit(2)
    for opt, arg in opts:
        ran = True
        if opt in ("-a", "--all"):
            update_cloudfront_wellknown(domain_objects, config['certbot_server'])
            generate_certificates(config, domain_objects)
            renew_certificates(config['certbot_binary_path'], config['certbot_arguments'])
            upload_cloudfront_certificates(domain_objects, config['certbot_certificate_path'])
            update_cloudfront_distributions(domain_objects, config['certbot_certificate_path'])
        elif opt in ("-c", "--check-certificates"):
            results = check_certificates(domain_objects, config)
            report = build_check_report(results, config['template_directory'])
            print report
        elif opt in ("-g", "--generate-certificates"):
            generate_certificates(config, domain_objects)
        elif opt in ("-r", "--renew-certificates"):
            renew_certificates(config['certbot_binary_path'], config['certbot_arguments'])
        elif opt in ("-u", "--upload-certificates"):
            upload_cloudfront_certificates(domain_objects, config['certbot_certificate_path'])
        elif opt in ("-d", "--update-cloudfront-distributions"):
            update_cloudfront_distributions(domain_objects, config['certbot_certificate_path'])
        elif opt in ("-p", "--prune-certificates"):
            prune_old_certificates(domain_objects)
        elif opt in ("-w", "--add-well-known"):
            update_cloudfront_wellknown(domain_objects, config['certbot_server'])
        elif opt in ("-l", "--list"):
            for domain in domain_objects.keys():
                certs_info = list_certificates(domain)
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
    certman()
