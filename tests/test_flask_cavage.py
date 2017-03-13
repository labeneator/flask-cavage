import json
import base64
import hashlib
try:
    # Python 3
    from urllib.parse import urlparse
except ImportError:
    # Python 2
    from urlparse import urlparse
import unittest
import datetime
import logging
from time import mktime
from wsgiref.handlers import format_date_time
from flask import Flask
from httpsig_cffi.requests_auth import HTTPSignatureAuth
from flask_cavage import CavageSignature, require_apikey_authentication


class WalletRestTestCase(unittest.TestCase):

    def setUp(self):
        super(WalletRestTestCase, self).setUp()
        self.debug = False
        self.app = Flask(__name__)
        self.init_app(self.app)
        self.test_client = self.app.test_client()
        self.secret_keys = dict(access_key_1="12345", access_key_2="23232")
        self.test_host_url = "http://localhost"

    def init_app(self, app):
        if self.debug:
            self.app.logger.addHandler(logging.StreamHandler())
            self.app.logger.setLevel(logging.DEBUG)

        cavage_signature = CavageSignature(app)

        @cavage_signature.secret_loader
        def load_secret(access_key):
            app.logger.debug("Loading secret for %s" % access_key)
            # You can store your keys in files, databases, hash tables...
            if access_key in self.secret_keys:
                return self.secret_keys.get(access_key)

        @self.app.route('/hello_world')
        def hello_world():
            return 'Hello, World!'

        @self.app.route('/hello_world_private', methods=['GET', 'POST'])
        @require_apikey_authentication
        def hello_world_private():
            return '<Whisper> Hello, world!'

        @self.app.route('/hello_someone', methods=['GET', 'POST'])
        @require_apikey_authentication
        def hello_someone():
            # If we get here, the payload has also been validated
            return 'Hello, Someone!'

    def rfc1123_datetime_format(self, dt_instant):
        stamp = mktime(dt_instant.timetuple())
        return format_date_time(stamp)

    def compute_checksum(self, data_dict):
        # This coerces everything into json.
        # TODO: Figure out how to digest form requests
        return "SHA-256=" + base64.encodestring(
            hashlib.sha256(bytes(json.dumps(data_dict).encode('utf-8'))).digest()
        ).decode('utf-8').strip()

    def mk_headers_and_signer(self, signed_headers, key_id, secret, data):
        url_components = urlparse(self.test_host_url)
        headers = dict(
            Date=self.rfc1123_datetime_format(datetime.datetime.now()),
            Host=url_components.netloc, Digest=self.compute_checksum(data)
        )
        signer = HTTPSignatureAuth(key_id=key_id, secret=secret, headers=signed_headers)
        return headers, signer

    def test_hello_world_should_not_be_accesible(self):
        rv = self.test_client.get('/hello_world')
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_without_a_signature(self):
        rv = self.test_client.get('/hello_world_private')
        self.assertEquals(rv.status_code, 403)
        self.assertTrue(b'Access denied' in rv.data)

    def test_protected_resource_should_be_accesible_with_a_signature_via_get(self):
        path = "/hello_world_private"
        headers_to_sign = ['(request-target)', 'host', 'date']
        self.app.config['CAVAGE_VERIFIED_HEADERS'] = headers_to_sign
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict()
        headers, signer = self.mk_headers_and_signer(headers_to_sign, access_key, secret, data)
        auth_headers=signer.header_signer.sign(headers, method="GET", path=path)
        rv = self.test_client.get(path, headers=auth_headers)
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_post(self):
        path = "/hello_world_private"
        headers_to_sign = ['(request-target)', 'host', 'date']
        self.app.config['CAVAGE_VERIFIED_HEADERS'] = headers_to_sign
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict()
        headers, signer = self.mk_headers_and_signer(headers_to_sign, access_key, secret, data)
        auth_headers=signer.header_signer.sign(headers, method="POST", path=path)
        rv = self.test_client.post(path, headers=auth_headers)
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_get_with_query_string(self):
        path = "/hello_world_private?username=Mike"
        headers_to_sign = ['(request-target)', 'host', 'date']
        self.app.config['CAVAGE_VERIFIED_HEADERS'] = headers_to_sign
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict()
        headers, signer = self.mk_headers_and_signer(headers_to_sign, access_key, secret, data)
        auth_headers=signer.header_signer.sign(headers, method="GET", path=path)
        rv = self.test_client.get(path, headers=auth_headers, data=data)
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_post_with_payload(self):
        path = "/hello_someone"
        headers_to_sign = ['(request-target)', 'host', 'date']
        self.app.config['CAVAGE_VERIFIED_HEADERS'] = headers_to_sign
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict(username='Mikey')
        headers, signer = self.mk_headers_and_signer(headers_to_sign, access_key, secret, data)
        auth_headers=signer.header_signer.sign(headers, method="POST", path=path)
        rv = self.test_client.post(path, headers=auth_headers, data=data)
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_post_with_json_payload(self):
        path = "/hello_someone"
        headers_to_sign = ['(request-target)', 'host', 'date']
        self.app.config['CAVAGE_VERIFIED_HEADERS'] = headers_to_sign
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict(username='Mikey')
        headers, signer = self.mk_headers_and_signer(headers_to_sign, access_key, secret, data)
        auth_headers=signer.header_signer.sign(headers, method="POST", path=path)
        rv = self.test_client.post(path, headers=auth_headers, data=json.dumps(data))
        self.assertEquals(rv.status_code, 200)

    def test_protected_resource_should_be_accesible_with_a_signature_via_a_json_digested_post_payload(self):
        path = "/hello_someone"
        headers_to_sign = ['(request-target)', 'host', 'date', 'digest']
        self.app.config['CAVAGE_VERIFIED_HEADERS'] = headers_to_sign
        access_key = "access_key_1"
        secret = self.secret_keys.get(access_key)
        data = dict(username='Mikey')
        headers, signer = self.mk_headers_and_signer(headers_to_sign, access_key, secret, data)
        auth_headers=signer.header_signer.sign(headers, method="POST", path=path)
        rv = self.test_client.post(path, headers=auth_headers, data=json.dumps(data))
        self.assertEquals(rv.status_code, 200)
