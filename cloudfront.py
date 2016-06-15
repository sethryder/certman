import boto3, botocore, datetime, hashlib, json, os, re, time
from helpers import *

def uploadCloudFrontCertificates(domain_objects, certificate_path):
    for primary_domain, config in domain_objects.iteritems():
        is_uploaded = False
        if config['distribution_id']:
            certificate_hash = generateCloudFrontHash(primary_domain, certificate_path)
            uploaded_certificates = listCertificates(primary_domain)

            for uploaded_certificate in uploaded_certificates:
                uploaded = re.search(certificate_hash, uploaded_certificate['ServerCertificateName'])

            if not uploaded:
                upload_result = uploadCertificate(primary_domain, certificate_path)

    return True

def updateCloudFrontDistributions(domain_objects, certificate_path):
    for primary_domain, config in domain_objects.iteritems():
        latest_certificate = getLastestCertificate(primary_domain)
        active_certificate = getActiveCertficateID(config['distribution_id'])

        if latest_certificate['id'] != active_certificate:
            updated = updateDistributionCertificate(config['distribution_id'], latest_certificate['name'])
            if not updated:
                logError("Unable to update certificate for" + primary_domain)
    return True

def listCertificates(primary_domain):
    iam_client = createAWSClient('iam')
    response = iam_client.list_server_certificates(
        PathPrefix='/cloudfront/' + primary_domain + '/'
    )

    if response['ServerCertificateMetadataList']:
        return response['ServerCertificateMetadataList']
    else:
        return False

def uploadCertificate(primary_domain, certificate_path):
    iam_client = createAWSClient('iam')
    primary_path = certificate_path + '/' + primary_domain

    if os.path.isfile(primary_path + '/cert.pem'):
        with open(certificate_path + '/' + primary_domain + '/cert.pem') as cert_file:
            cert = cert_file.read()
            cert_hash = hashlib.md5(cert).hexdigest()
    else:
        logError('Cert file does not exist.')
        return False

    if os.path.isfile(primary_path + '/privkey.pem'):
        with open(certificate_path + '/' + primary_domain + '/privkey.pem') as cert_file:
            privkey = cert_file.read()
    else:
        logError('Private key file does not exist.')
        return False

    if os.path.isfile(primary_path + '/chain.pem'):
        with open(certificate_path + '/' + primary_domain + '/chain.pem') as cert_file:
            chain = cert_file.read()
    else:
        logError('Chain file does not exist.')
        return False

    try:
        response = iam_client.upload_server_certificate(
            Path='/cloudfront/' + primary_domain + '/',
            ServerCertificateName=primary_domain + '-' + cert_hash,
            CertificateBody=cert,
            PrivateKey=privkey,
            CertificateChain=chain
        )
        return response['ServerCertificateId']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            logError("Certificate already exists")
        return False

def deleteCertificate(server_certificate_id):
    iam_client = createAWSClient('iam')

    try:
        response = iam_client.delete_server_certificate(
            ServerCertificateName=server_certificate_id
        )
        return True
    except botocore.exceptions.ClientError as e:
        return False


def updateDistributionCertificate(distribution_id, server_certificate_name):
    cloudfront_client = createAWSClient('cloudfront')
    iam_client = createAWSClient('iam')

    try:
        certificate = iam_client.get_server_certificate(ServerCertificateName=server_certificate_name)
        distribution = cloudfront_client.get_distribution(Id=distribution_id)
    except botocore.exceptions.ClientError as e:
        return False

    certificate_id = certificate['ServerCertificate']['ServerCertificateMetadata']['ServerCertificateId']

    if distribution['Distribution']:
        distribution_config = distribution['Distribution']['DistributionConfig']
        if distribution_config['ViewerCertificate']['IAMCertificateId']:
            if distribution_config['ViewerCertificate']['IAMCertificateId'] == certificate_id:
                return True
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
        return False

    #TODO: verify that the domains match before enabling

def getActiveCertficateID(distribution_id):
    cloudfront_client = createAWSClient('cloudfront')

    try:
        distribution = cloudfront_client.get_distribution(Id=distribution_id)
    except botocore.exceptions.ClientError as e:
        return False

    distribution_config = distribution['Distribution']['DistributionConfig']
    if distribution_config['ViewerCertificate']['IAMCertificateId']:
        certificate_id = distribution_config['ViewerCertificate']['IAMCertificateId']
        return certificate_id
    else:
        return False

def getCertificateName(primary_domain, certificate_id):
    certificates = listCertificates(primary_domain)
    certificate_name = False

    if certificates:
        for certificate in certificates:
            if certificate['ServerCertificateId'] == certificate_id:
                certificate_name = certificate['ServerCertificateName']
                break
    return certificate_name

def getLastestCertificate(primary_domain):
    latest_time = 0
    iam_client = createAWSClient('iam')

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

#def addWellKnownOrigin(distribution_id):
