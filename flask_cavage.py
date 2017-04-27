import re
import base64
import hashlib
from functools import wraps
from httpsig.verify import HeaderVerifier
from flask import g, request, current_app, abort


class CavageSignature(object):
    digest_functions = {
        "SHA-512": hashlib.sha512,
        "SHA-384": hashlib.sha384,
        "SHA-256": hashlib.sha256,
        "SHA-224": hashlib.sha224,
        "SHA-1": hashlib.sha1,
        "MD5": hashlib.md5,
    }

    generic_headers = [
        "date",
        "(request-target)",
        "host"
    ]
    body_headers = [
        "content-length",
        "content-type",
        "x-content-sha256",
    ]
    required_headers = {
        "get": generic_headers,
        "head": generic_headers,
        "delete": generic_headers,
        "put": generic_headers + body_headers,
        "post": generic_headers + body_headers
    }

    def __init__(self, app=None):
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.secret_loader_callback = None
        app.config.setdefault(
            'CAVAGE_VERIFIED_HEADERS',
            ['(request-target)', 'host', 'date', 'digest'])
        self.init_signature_handlers(app)
        return self

    def verify_secret_loader(self):
        if self.secret_loader_callback is None:
            raise Exception(
                "No secret loader installed."
                " Add one using the secret_loader decorator")

    def validate_headers(self, required_headers):
        if "authorization" not in request.headers:
            current_app.logger.warn(
                "Missing authorization header")
            return False
        required_headers_set = set(required_headers)
        received_headers = set(
            [header_name.lower() for header_name in request.headers.keys()] +
            ["(request-target)"])
        return received_headers.issuperset(required_headers_set)

    def load_secret_key(self):
        authorization_header = request.headers.get('authorization')
        key_id_match = re.match(
            '.*keyId="(?P<key_id>\w+).*', authorization_header)
        if not key_id_match:
            current_app.logger.warn(
                "Missing keyId in header: %s" % authorization_header)
            return
        key_id = key_id_match.groupdict().get('key_id')
        if not key_id:
            current_app.logger.warn(
                "keyId doesn't look right: '%s'" % key_id)
            return

        current_app.logger.debug(
            "Secrets lookup for access key: %s" % key_id)
        secret_key = self.secret_loader_callback(key_id)
        if not secret_key:
            current_app.logger.warn(
                "keyId doesn't have a secret: '%s'" % key_id)
            return
        return secret_key

    def verify_headers(self, app, secret_key, http_method, required_headers):
        if http_method in ['get', 'head', 'delete']:
            url_path = request.full_path.rstrip("?")
        elif http_method in ['post', 'put']:
            url_path = request.path
        else:
            current_app.logger.warn(
                "Don't know what to do with HTTP Method: %s" % http_method)
        current_app.logger.debug("url path: %s" % url_path)
        verifier = HeaderVerifier(
            request.headers, secret_key,
            required_headers=required_headers,
            path=url_path,
            method=request.method)
        return verifier.verify()

    def verify_payload(self, app, required_headers):
        digest_type = "SHA-256"
        digest_header = "x-content-sha256"
        if digest_header not in required_headers:
            return True
        digest_base64 = request.headers.get(digest_header)
        digest_function = self.digest_functions.get(digest_type)
        computed_digest = digest_function(request.data).digest()
        submitted_digest = base64.b64decode(
            bytes(digest_base64.encode('utf-8'))
        )
        current_app.logger.debug(
                "Comparing content digest (%s) vs received digest (%s)" % (
                    computed_digest, submitted_digest))
        return computed_digest == submitted_digest

    def init_signature_handlers(self, app):
        @app.before_request
        def verify_request():
            g.cavage_verified = False
            self.verify_secret_loader()

            http_method = request.method.lower()
            required_headers = self.required_headers.get(http_method)

            if not self.validate_headers(required_headers):
                current_app.logger.warn("Header validation failed")
                return
            current_app.logger.debug("Headers validated")

            secret_key = self.load_secret_key()
            if not secret_key:
                current_app.logger.warn("Secret key loading failed")
                return
            current_app.logger.debug("Secret key loaded")

            if not self.verify_headers(
                    app, secret_key, http_method, required_headers):
                current_app.logger.warn("Header verification failed")
                return
            current_app.logger.debug("Header verification success")
            g.cavage_verified = self.verify_payload(app, required_headers)

    def secret_loader(self, callback):
        if not callback or not callable(callback):
            raise Exception("Please pass in a callable that loads secret keys")
        self.secret_loader_callback = callback
        return callback


def require_apikey_authentication(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if hasattr(g, 'cavage_verified') and not g.cavage_verified:
            abort(401, "Access denied")
        return func(*args, **kwargs)
    return decorated_function
