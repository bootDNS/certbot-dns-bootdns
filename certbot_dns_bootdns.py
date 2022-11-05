"""DNS Authenticator for bootDNS"""
import logging
import tldextract
import requests
from certbot.plugins import dns_common
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for bootDNS

    This Authenticator uses the bootDNS REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using bootDNS for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=60
        )
        add("credentials", help="bootDNS credentials INI file.")

    def more_info(self):
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using the bootDNS REST API."
        )

    def _setup_credentials(self):
        self._configure_file('credentials',
                             'Absolute path to bootDNS credentials INI file')
        dns_common.validate_file_permissions(self.conf('credentials'))
        self.credentials = self._configure_credentials(
            "credentials",
            "bootDNS credentials INI file",
            {
                "host": "URL for the bootDNS REST API.",
                "token": "Token for the bootDNS REST API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_bootdns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_bootdns_client().del_txt_record(domain, validation_name, validation)

    def _get_bootdns_client(self):
        return _bootDNS_Client(
            credentials=self.credentials.conf,
            ttl=self.ttl
        )


class _bootDNS_Client():
    """Encapsulates all communication with bootDNS REST API."""

    def __init__(self, credentials, ttl):
        super(_bootDNS_Client, self).__init__()
        self.config = {
            'host': credentials('host'),
            'api_token': credentials('token'),
            'ttl': ttl
        }

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.
        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises RequestException: if an error occurs communicating with the bootDNS REST API
        """

        ex = tldextract.extract(domain)
        try:
            requests.post(
                url=f"http://{self.config['host']}/api/record/{ex.registered_domain}",
                headers={'Authorization': f'Bearer {self.config["api_token"]}'},
                data={"ttl":self.config["ttl"], "type": "TXT", "hostname":f"{record_name}.", "value":record_content}
            )
        except RequestException as e:
            raise('Error creating TXT record: {0}'.format(e))

        try:
            requests.post(
                url=f"http://{self.config['host']}/api/push-zone/{ex.registered_domain}",
                headers={'Authorization': f'Bearer {self.config["api_token"]}'}
            )
        except RequestException as e:
            raise('Error pushing zone changes: {0}'.format(e))

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.
        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises RequestException: if an error occurs communicating with the bootDNS REST API
        """
        ex = tldextract.extract(domain)
        try:
            requests.delete(
                url=f"http://{self.config['host']}/api/record/{ex.registered_domain}",
                headers={'Authorization': f'Bearer {self.config["api_token"]}'},
                data={"type": "TXT", "hostname":f"{record_name}.", "value":record_content}
            )
        except RequestException as e:
            raise('Error deleting TXT record: {0}'.format(e))

        try:
            requests.post(
                url=f"http://{self.config['host']}/api/push-zone/{ex.registered_domain}",
                headers={'Authorization': f'Bearer {self.config["api_token"]}'}
            )
        except RequestException as e:
            raise('Error pushing zone changes: {0}'.format(e))