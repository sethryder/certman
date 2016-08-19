# certman

Built to help make managing Lets Encrypt certificates easier on Cloudfront. Though the certificates generated can be used anywhere.

## Todo

* Tests
* Better logging
* Create proper (pip) package

## Setup

#### Requirements
* [Certbot](https://certbot.eff.org/)
* Python 2.6+
* pip

#### Installing
```
git clone https://github.com/sethryder/certman.git
cd certman
pip install -r requirements.txt
mv config/certman-sample.conf /etc/certman.conf
```

## Config

By default certman looks for its config file at **/etc/certman.conf**. A sample config file is included at **certman-sample.conf**.

Depending on your Certbot install you will need to update the configuration accordingly.

#### certman.conf

This is the primary config file for certman.

* **certbot_arguments**: Arguments that are passed to certbot when creating and renewing certificates.
* **certbot_binary_path**: Path to the cerbot binary (**Default**: /usr/local/bin/certbot-auto)
* **certbot_certificate_path**: Path to where Certbot keeps its current certificate symlinks. (**Default**: /etc/letsencrypt/live)
* **domain_config_directory**: Path to config files for the managed domains. (**Default**: /etc/certman.d)
* **hash_file_directory**: Path where certman saves its config hash files (**Default**: /etc/certman.d)
* **certbot_server**: URL to your configured Certbot server for domain verification.
* **report_email**: Where certman will send its certificate check reports.

#### Domain Configs

For each domain you want to manage you include a config file. With the default configuration it looks for these files in **/etc/certman.d**. You can find an example in the config directory in this repo.

* **primary_domain**: The primary domain for the certificate.
* **additional_domains**: Any additional domains that the certificate will cover.
* **distribution_id** (optional): The CloudFront distribution for this domain.

## Usage

```
$ python certman.py -h
Usage: certman.py (option)

-a, --all                                Run/do everything.
-c, --check-certificates                 Check and validate all known SSL certificates.
-g, --generate-certificates              Generate SSL certificates.
-r, --renew-certificates                 Renew SSL certificates.
-u, --upload-certificates                Upload SSL certificates to CloudFront.
-d, --update-cloudfront-distributions    Update CloudFront distributions with the latest SSL certificate.
-w, --add-well-known                     Add ./well-known origin and behavior to CloudFront distribution.
-l, --list                               List certificates.
-q, --quiet                              No output, except for errors.
```
