import boto3
import botocore
import datetime
import hashlib
import json
import os
import re
import time
import logging
from helpers import *

logger = logging.getLogger('certman')

def upload_cloudfront_certificates(domain_objects, certificate_path):
    logger.info("Starting CloudFront upload process")
    for primary_domain, config in domain_objects.iteritems():
        is_uploaded = False
        if 'distribution_id' in config:
            logger.info("%s: Starting upload check" % primary_domain)
            logger.info(primary_domain + ": Distribution_id set")
            certificate_hash = generate_cloudfront_hash(primary_domain, certificate_path)
            uploaded_certificates = list_certificates(primary_domain)

            if uploaded_certificates:
                logger.info(primary_domain + ": Checking if SSL has been uploaded")
                for uploaded_certificate in uploaded_certificates:
                    uploaded = re.search(certificate_hash, uploaded_certificate['ServerCertificateName'])

                if not uploaded:
                    logger.info(primary_domain + ": Uploading SSL")
                    upload_result = upload_certificate(primary_domain, certificate_path)
                else:
                    logger.info(primary_domain + ": SSL already exists in IAM")
            else:
                logger.info(primary_domain + ": Uploading SSL")
                upload_result = upload_certificate(primary_domain, certificate_path)
            logger.info(primary_domain + ": Finished upload process")
    logger.info("Finished upload process")

    return True

def update_cloudfront_distributions(domain_objects, certificate_path):
    for primary_domain, config in domain_objects.iteritems():
        if 'distribution_id' in config:
            latest_certificate = get_lastest_certificate(primary_domain)
            active_certificate = get_active_certficate_id(config['distribution_id'])

            if latest_certificate['id'] != active_certificate:
                updated = update_distribution_certificate(config['distribution_id'], latest_certificate['name'])
                if not updated:
                    logger.error("Unable to update certificate for " + primary_domain)
    return True

def update_cloudfront_wellknown(domain_objects, ssl_host):
    for primary_domain, config in domain_objects.iteritems():
        if 'distribution_id' in config:
            add_wellknown_origin(config['distribution_id'], ssl_host)
            add_wellknown_behavior(config['distribution_id'])
    return True

def add_wellknown_origin(distribution_id, ssl_host):
    cloudfront_client = create_aws_client('cloudfront')

    ssl_origin = {
    	'OriginPath': '',
        'CustomOriginConfig': {
    		'OriginProtocolPolicy': 'http-only',
    		'HTTPPort': 80,
    		'OriginSslProtocols': {
    		    'Items': ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
    		    'Quantity': 3
    		},
    		'HTTPSPort': 443
    	},
        'CustomHeaders': {
    		'Quantity': 0
    	},
    	'Id': 'Certbot-Server',
        'DomainName': ssl_host
    }

    logger.info(distribution_id +": Checking for Certbot Server origin")

    try:
        distribution = cloudfront_client.get_distribution(Id=distribution_id)
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        return False

    if distribution['Distribution']:
        has_ssl_origin = False
        correct_ssl_origin = False
        distribution_config = distribution['Distribution']['DistributionConfig']
        for origin in distribution_config['Origins']['Items']:
            if origin['Id'] == 'Certbot-Server':
                has_ssl_origin = True
                if origin['DomainName'] != ssl_host:
                    logger.info(distribution_id +": Certbot Server origin domain incorrect, updating")
                    origin['DomainName'] = ssl_host
                    try:
                        response = cloudfront_client.update_distribution(
                            DistributionConfig=distribution_config,
                            Id=distribution_id,
                            IfMatch=distribution['ETag'],
                        )
                        logger.info(distribution_id +": Certbot Server origin domain updated")
                        return True
                    except botocore.exceptions.ClientError as e:
                        logger.error(e)
                        return False

        if has_ssl_origin == False:
            logger.info(distribution_id +": Certbot Server origin does not exist, adding")
            distribution_config['Origins']['Items'].append(ssl_origin)
            origin_count = len(distribution_config['Origins']['Items'])
            distribution_config['Origins']['Quantity'] = origin_count

            try:
                response = cloudfront_client.update_distribution(
                    DistributionConfig=distribution_config,
                    Id=distribution_id,
                    IfMatch=distribution['ETag'],
                )
                logger.info(distribution_id +": Certbot Server origin added")
                return True
            except botocore.exceptions.ClientError as e:
                logger.error(e)
                return False
        else:
            logger.info(distribution_id +": Certbot Server origin already exists")
            return True

def add_wellknown_behavior(distribution_id):
    cloudfront_client = create_aws_client('cloudfront')

    well_known_behavior = {
        'TrustedSigners': {
            'Enabled': False,
            'Quantity': 0
        },
        'TargetOriginId': 'Certbot-Server',
        'ViewerProtocolPolicy': 'allow-all',
        'ForwardedValues': {
            'Headers': {
                'Quantity': 0
            },
            'Cookies': {
                'Forward': 'none'
            },
            'QueryString': False,
            "QueryStringCacheKeys": {
                "Quantity": 0
            }
        },
        'MaxTTL': 0,
        'PathPattern': '/.well-known/acme-challenge/*',
        'SmoothStreaming': False,
        'DefaultTTL': 0,
        'AllowedMethods': {
            'Items': ['HEAD', 'GET'],
            'CachedMethods': {
                'Items': ['HEAD', 'GET'],
                'Quantity': 2
            },
            'Quantity': 2
        },
        'MinTTL': 0,
        'Compress': False
    }

    try:
        distribution = cloudfront_client.get_distribution(Id=distribution_id)
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        return False

    if distribution['Distribution']:
        has_behavior = False
        update_distribution = False

        distribution_config = distribution['Distribution']['DistributionConfig']

        if distribution_config['CacheBehaviors']['Quantity'] > 0:
            for behavior in distribution_config['CacheBehaviors']['Items']:
                if behavior['PathPattern'] == '/.well-known/acme-challenge/*':
                    has_behavior = True
                    if behavior['TargetOriginId'] != 'Certbot-Server':
                        behavior['TargetOriginId'] = 'Certbot-Server'
                        update_distribution = True
            if has_behavior == False:
                distribution_config['CacheBehaviors']['Items'].append(well_known_behavior)
                origin_count = len(distribution_config['CacheBehaviors']['Items'])
                distribution_config['CacheBehaviors']['Quantity'] = origin_count
                update_distribution = True
        else:
            distribution_config['CacheBehaviors']['Items'] = [well_known_behavior]
            origin_count = len(distribution_config['CacheBehaviors']['Items'])
            distribution_config['CacheBehaviors']['Quantity'] = origin_count
            update_distribution = True

        if update_distribution:
            try:
                response = cloudfront_client.update_distribution(
                    DistributionConfig=distribution_config,
                    Id=distribution_id,
                    IfMatch=distribution['ETag'],
                )
                logger.info(distribution_id +": Certbot Server behavior updated")
                return True
            except botocore.exceptions.ClientError as e:
                logger.error(e)
                return False
        return True
    else:
        return False



def list_certificates(primary_domain):
    iam_client = create_aws_client('iam')
    response = iam_client.list_server_certificates(
        PathPrefix='/cloudfront/' + primary_domain + '/'
    )

    if response['ServerCertificateMetadataList']:
        return response['ServerCertificateMetadataList']
    else:
        return False

def upload_certificate(primary_domain, certificate_path):
    iam_client = create_aws_client('iam')
    primary_path = certificate_path + '/' + primary_domain

    if os.path.isfile(primary_path + '/cert.pem'):
        with open(certificate_path + '/' + primary_domain + '/cert.pem') as cert_file:
            cert = cert_file.read()
            cert_hash = hashlib.md5(cert).hexdigest()
    else:
        logger.error("Cert file does not exist for \r\nDomain: " + primary_domain + "\r\n Certificate Path: " + certificate_path)
        return False

    if os.path.isfile(primary_path + '/privkey.pem'):
        with open(certificate_path + '/' + primary_domain + '/privkey.pem') as cert_file:
            privkey = cert_file.read()
    else:
        logger.error("Private key file does not exist for \r\nDomain: " + primary_domain + "\r\n Certificate Path: " + certificate_path)
        return False

    if os.path.isfile(primary_path + '/chain.pem'):
        with open(certificate_path + '/' + primary_domain + '/chain.pem') as cert_file:
            chain = cert_file.read()
    else:
        logger.error("Chain file does not exist for \r\nDomain: " + primary_domain + "\r\n Certificate Path: " + certificate_path)
        return False

    try:
        response = iam_client.upload_server_certificate(
            Path='/cloudfront/' + primary_domain + '/',
            ServerCertificateName=primary_domain + '-' + cert_hash,
            CertificateBody=cert,
            PrivateKey=privkey,
            CertificateChain=chain
        )
        return response['ServerCertificateMetadata']['ServerCertificateId']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            logger.info("Certificate already exists on IAM. \r\nCertificate Domain: " + primary_domain + "\r\nCertificate Path: " + certificate_path)
        return False

def delete_certificate(server_certificate_name):
    iam_client = create_aws_client('iam')

    try:
        response = iam_client.delete_server_certificate(
            ServerCertificateName=server_certificate_name
        )
        logger.info('Deleted: ' + server_certificate_name)
        return True
    except botocore.exceptions.ClientError as e:
        logger.error('Unable to delete ' + server_certificate_name)
        return False


def prune_old_certificates(domain_objects):
    for primary_domain, config in domain_objects.iteritems():
        certificates = list_certificates(primary_domain)
        lastest_certificate = get_lastest_certificate(primary_domain)
        active_certificate = get_active_certficate_id(primary_domain)

        if certificates:
            for certificate in certificates:
                if (certificate['ServerCertificateId'] != lastest_certificate['id'] and
                    certificate['ServerCertificateId'] != active_certificate):
                    logger.info('Pruning: ' + certificate['ServerCertificateName'])
                    delete_certificate(certificate['ServerCertificateName'])
                else:
                    logger.info('In use or latest: ' + certificate['ServerCertificateName'])

def update_distribution_certificate(distribution_id, server_certificate_name):
    cloudfront_client = create_aws_client('cloudfront')
    iam_client = create_aws_client('iam')

    try:
        certificate = iam_client.get_server_certificate(ServerCertificateName=server_certificate_name)
        distribution = cloudfront_client.get_distribution(Id=distribution_id)
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        return False

    certificate_id = certificate['ServerCertificate']['ServerCertificateMetadata']['ServerCertificateId']

    if distribution['Distribution']:
        distribution_config = distribution['Distribution']['DistributionConfig']
        if 'IAMCertificateId' in distribution_config['ViewerCertificate']:
            if distribution_config['ViewerCertificate']['IAMCertificateId'] == certificate_id:
                return True
        if 'CloudFrontDefaultCertificate' in distribution_config['ViewerCertificate']:
            del distribution_config['ViewerCertificate']['CloudFrontDefaultCertificate']
        distribution_config['ViewerCertificate']['IAMCertificateId'] = certificate_id
        distribution_config['ViewerCertificate']['Certificate'] = certificate_id
        distribution_config['ViewerCertificate']['CertificateSource'] = 'iam'
        distribution_config['ViewerCertificate']['MinimumProtocolVersion'] = 'TLSv1'
        distribution_config['ViewerCertificate']['SSLSupportMethod'] = 'sni-only'

    try:
        response = cloudfront_client.update_distribution(
            DistributionConfig=distribution_config,
            Id=distribution_id,
            IfMatch=distribution['ETag'],
        )
        return True
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        return False

    #TODO: verify that the domains match before enabling

def get_active_certficate_id(distribution_id):
    cloudfront_client = create_aws_client('cloudfront')

    try:
        distribution = cloudfront_client.get_distribution(Id=distribution_id)
    except botocore.exceptions.ClientError as e:
        return False

    distribution_config = distribution['Distribution']['DistributionConfig']
    if 'IAMCertificateId' in distribution_config['ViewerCertificate']:
        certificate_id = distribution_config['ViewerCertificate']['IAMCertificateId']
        return certificate_id
    else:
        return False

def get_certificate_name(primary_domain, certificate_id):
    certificates = list_certificates(primary_domain)
    certificate_name = False

    if certificates:
        for certificate in certificates:
            if certificate['ServerCertificateId'] == certificate_id:
                certificate_name = certificate['ServerCertificateName']
                break
    return certificate_name

def get_lastest_certificate(primary_domain):
    latest_time = 0
    iam_client = create_aws_client('iam')

    response = iam_client.list_server_certificates(
        PathPrefix='/cloudfront/' + primary_domain + '/'
    )

    if response['ServerCertificateMetadataList']:
        for certificate in response['ServerCertificateMetadataList']:
            certificate_time = certificate['Expiration'].strftime("%s")
            if certificate_time > latest_time:
                latest_time = certificate_time
                latest_id = certificate['ServerCertificateId']
                latest_name = certificate['ServerCertificateName']
        certificate = {}
        certificate['id'] = latest_id
        certificate['name'] = latest_name
        return certificate
    else:
        return False
