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
                " Add one using the secret_loader decorator"
        )

    def validate_headers(self):
        if "authorization" not in request.headers:
            current_app.logger.warn(
                "Missing authorization header")
            return False
        if "digest" in self.app.config.get('CAVAGE_VERIFIED_HEADERS') and "digest" not in request.headers:
            current_app.logger.warn(
                "Missing digest header")
            return False
        return True

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

    def verify_headers(self, app, secret_key):
        url_path = request.full_path.rstrip("?") if request.method == 'GET' else request.url_rule
        verifier = HeaderVerifier(
            request.headers, secret_key,
            required_headers=app.config.get('CAVAGE_VERIFIED_HEADERS'),
            path=url_path,
            method=request.method)
        return verifier.verify()

    def verify_payload(self, app):
        if 'digest' in app.config.get('CAVAGE_VERIFIED_HEADERS'):
            digest_type, digest_base64 = request.headers.get("digest").split("=", 1)
            digest_function = self.digest_functions.get(digest_type)
            computed_digest = digest_function(request.data).digest()
            submitted_digest = base64.decodestring(bytes(digest_base64.encode('utf-8')))
            if computed_digest != submitted_digest:
                current_app.logger.warn("Message body digest verification failed")
                return False
        return True

    def init_signature_handlers(self, app):
        @app.before_request
        def verify_request():
            g.cavage_verified = False

            self.verify_secret_loader()

            if not self.validate_headers():
                return

            secret_key = self.load_secret_key()
            if not secret_key:
                return

            if not self.verify_headers(app, secret_key):
                current_app.logger.warn("Signature verification failed")
                return
            current_app.logger.debug("Signature verification success")
            g.cavage_verified = self.verify_payload(app)

    def secret_loader(self, callback):
        if not callback or not callable(callback):
            raise Exception("Please pass in a callable that loads secret keys")
        self.secret_loader_callback = callback
        return callback


def require_apikey_authentication(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if hasattr(g, 'cavage_verified') and not g.cavage_verified:
            abort(403, "Access denied")
        return func(*args, **kwargs)
    return decorated_function
