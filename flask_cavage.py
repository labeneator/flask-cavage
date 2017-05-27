import re
import base64
import hashlib
import binascii
from functools import wraps
from httpsig.verify import HeaderVerifier
from flask import g, request, current_app, jsonify

# Draft doc: https://tools.ietf.org/html/draft-cavage-http-signatures-06

# As per draft appendix C, section 2
base_headers_set = frozenset(["(request-target)", "host", "date"])
content_headers_set = frozenset(["content-length", "content-type", "digest"])


class HeadersMap:
    head = base_headers_set
    get  = base_headers_set
    delete = base_headers_set
    post = base_headers_set.union(content_headers_set)
    put  = base_headers_set.union(content_headers_set)
    patch = base_headers_set.union(content_headers_set)


class CavageSignature(object):
    digest_functions_hash = {
        "SHA-512": hashlib.sha512,
        "SHA-384": hashlib.sha384,
        "SHA-256": hashlib.sha256,
        "SHA-224": hashlib.sha224,
        "SHA-1": hashlib.sha1,
        "MD5": hashlib.md5,
    }


    def __init__(self, app=None, headers_map=None):
        if app:
            self.init_app(app, headers_map)

    def init_app(self, app, headers_map=None):
        self.app = app
        if not headers_map:
            headers_map = HeadersMap
        self.headers_map = headers_map
        self.key_id_matcher = re.compile('.*keyId="(?P<key_id>\w+).*')
        self.secret_loader_callback = None
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
        # Make a list of headers in the HTTP request and add the
        # implict request-target.
        received_headers = set(map(lambda x: x.lower(), request.headers.keys()))
        received_headers.add("(request-target)")
        return received_headers.issuperset(required_headers)

    def load_secret_key(self):
        authorization_header = request.headers.get('authorization')
        key_id_match = self.key_id_matcher.match(authorization_header)
        if not key_id_match:
            current_app.logger.warn(
                "Missing keyId in header: %s" % authorization_header)
            return
        key_id = key_id_match.groupdict().get('key_id')
        if not key_id:
            current_app.logger.warn(
                "Unable to extract keyId: '%s'" % key_id)
            return
        current_app.logger.debug(
            "Secrets lookup for access key: %s" % key_id)
        secret_key = self.secret_loader_callback(key_id)
        if not secret_key:
            current_app.logger.warn(
                "keyId doesn't have a secret: '%s'" % key_id)
            return
        g.cavage_key_id = key_id
        return secret_key

    def verify_headers(self, app, secret_key, http_method, required_headers):
        if http_method in ['get', 'head', 'delete']:
            url_path = request.full_path.rstrip("?")
        else:
            url_path = request.path
        current_app.logger.debug("url path: %s" % url_path)
        verifier = HeaderVerifier(
            request.headers, secret_key, required_headers=required_headers,
            path=url_path, method=request.method)
        return verifier.verify()

    def verify_payload(self, app, required_headers):
        digest_header = "digest"
        if digest_header not in required_headers:
            return True
        digest_hash_type, digest_base64 = request.headers.get(digest_header).split("=", 1)
        digest_function = self.digest_functions_hash.get(digest_hash_type)
        computed_digest = digest_function(request.data).digest()
        submitted_digest = base64.b64decode(
            bytes(digest_base64.encode('utf-8'))
        )
        current_app.logger.debug(
                "Comparing content digest (%s) vs received digest (%s)" %
                   tuple(map(binascii.hexlify, [computed_digest, submitted_digest])))
        return computed_digest == submitted_digest

    def init_signature_handlers(self, app):
        @app.before_request
        def verify_request():
            g.cavage_verified = False
            self.verify_secret_loader()

            http_method = request.method.lower()
            # Default to minimum header verification set required by the spec
            # for unknown methods
            required_headers = getattr(self.headers_map,
                                       http_method,
                                       self.headers_map.get)

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
            # TODO: Abort with a response header as per draft section: 3.1.1.
            headers = " ".join(list(getattr(HeadersMap, request.method.lower())))
            response = jsonify(message="Access Denied")
            response.status_code = 401
            response.headers['WWW-Authenticate'] = 'Signature realm="Example",headers="%s"' % headers
            return response
        return func(*args, **kwargs)
    return decorated_function
