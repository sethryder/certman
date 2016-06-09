import yaml, os, sys, logging, hashlib, json

def generateHash(primary_domain, additional_domains = None):
    domain_object = {}
    domain_object['primary'] = primary_domain
    domain_object['additional_domains'] = additional_domains

    md5Hash = hashlib.md5(json.dumps(domain_object, sort_keys=True)).hexdigest()
    return md5Hash

def getSavedHash(primary_domain, hash_file_directory):
    hash_file_path = hash_file_directory + '/' + primary_domain + '.hash'

    if os.path.isfile(hash_file_path):
        target = open(hash_file_path, 'r')
        saved_hash = target.read()
        return saved_hash
    else:
        return False

def setSavedHash(primary_domain, hash_file_directory, hash):
    hash_file_path = hash_file_directory + '/' + primary_domain + '.hash'

    if os.path.isdir(hash_file_directory):
        target = open(hash_file_path, 'w')
        target.truncate()
        target.write(hash)
        target.close()
        return True
    else:
        logError("Hash file directory does not exist.")
    return False

def getLastestCertificateTime(primary_domain, certificate_directory):
    certificate_file_path = certificate_directory + '/' + primary_domain + '/cert.pem'

    if os.path.isfile(certificate_file_path):
        modified_time = os.path.getmtime(certificate_file_path)
        return modified_time
    else:
        return False


def loadConfigs(config_directory):
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
                    logError("No primary domain set, invalid configuration file.")
    else:
        logError("Config directory does not exist.")
    return configs
