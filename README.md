# Certbot plugin for authentication using bootDNS

This is a plugin for [Certbot](https://certbot.eff.org/) that uses the [bootDNS](https://github.com/bootDNS/bootDNS-admin) API
automates the process of completing a dns-01 challenge by creating, and subsequently removing, TXT records on a domain name.

## Installation

### Python / pip

Install this package via pip in the same python environment where you installed `certbot`.

```commandline
pip install certbot-dns-bootdns
```

## Command lines

To start using DNS authentication for the bootDNS API, pass the following arguments on certbot's command line:

| Option                                                     | Description                                      |
|------------------------------------------------------------|--------------------------------------------------|
| `--authenticator dns-bootdns`                              | Select the authenticator plugin (Required)       |
| `--dns-bootdns-credentials`                                | bootDNS API credentials INI file. (Required)     |
| `--dns-bootdns-propagation-seconds`                        | Seconds to wait for the TXT record to propagate  |

## Usage

1. Make sure the plugin is installed and connected. You can verify this by running `certbot plugins`. `dns-bootdns` should be in the list.

2. Go to your [bootDNS admin](https://github.com/bootDNS/bootDNS-admin) instance, and go to Settings -> API Tokens to create a new API Token.

3. Create a `credentials.ini` config file with the following content:

   ```ini
   dns_bootdns_host = <host>
   dns_bootdns_token = <token>
   ```

   Replace `<host>` with hostname for your bootDNS instance. - Example: bootdns.example.com
   
   Replace `<token>` with your bootDNS API Tokens.

4. Run `certbot` and direct it to use the plugin for authentication and to use the config file previously created:

	```sh
	certbot certonly \\
	 --authenticator dns-bootdns \\
	 --dns-bootdns-credentials /path/to/credentials.ini \\
	 -d example.com
	```

   Use `*.example.com` if you want to generate it as a wildcard certificate.  

## Development

### Install local files as python package

Run the following command in the repository root (so you are in the folder containing the `setup.py`):

```sh
pip3 install -e ./
```

## Distribution

- PyPI: https://pypi.org/project/certbot-dns-bootdns/