import json, requests, os, smtplib
from string import Template
from datetime import datetime
from email.mime.text import MIMEText

def checkCertificates(domains, config):
    results = {}

    for k,v in domains.iteritems():
        domain_results = {}
        domain_results[k] = checkDomain(k)
        if 'additional_domains' in v:
            for additional_domain in v['additional_domains']:
                domain_results[additional_domain] = checkDomain(additional_domain)
        results[k] = domain_results

    return results

def checkDomain(domain):
    url = 'https://' + domain
    try:
        r = requests.get(url, timeout=5)
        return True
    except requests.exceptions.SSLError as SSLError:
        return "SSL Error: " + str(SSLError)
    except requests.exceptions.ConnectionError as ConnectionError:
        return "Can't connect to URL: " + url
    except requests.exceptions.RequestException as e:
        return e

    return False #not sure how we would get here, but just in case.

def buildCheckReport(results, template_directory):
    domain_reports = []
    problemed_ssls = []
    total_passed = 0
    total_failed = 0
    current_date = datetime.now()
    report_date = current_date.strftime('%m/%d/%Y %I:%M:%S%p')

    os.chdir(template_directory)
    filein = open('domain_report.tpl')
    src = Template(filein.read())

    for k,v in results.iteritems():
        single_domain_report = []
        primary_domain = k
        for domain,result in v.iteritems():
            if result == True:
                total_passed = total_passed + 1
                single_domain_report.append("- " + domain + " - Passed")
            else:
                total_failed = total_failed + 1
                single_domain_report.append("- " + domain + " - Error: " + result)
                problemed_ssls.append("- " + domain + " - Error: " + result)

        d = { 'primary_domain': k, 'domains':'\n'.join(single_domain_report) }
        result = src.substitute(d)
        domain_reports.append(result)

    os.chdir(template_directory)
    filein = open('full_report.tpl')
    src = Template(filein.read())
    d = {
        'report_date': report_date,
        'total_passed': total_passed,
        'total_failed': total_failed,
        'problemed_ssls': '\n'.join(problemed_ssls),
        'full_report':'\n'.join(domain_reports)
    }

    final_report = src.substitute(d)
    return final_report
