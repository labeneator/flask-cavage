import six
import base64
import hashlib
import email.utils
import requests
from httpsig_cffi.sign import HeaderSigner


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


class SignedRequestAuth(requests.auth.AuthBase):
    def __init__(self, key_id, secret_key, algorithm="hmac-sha256",
                 headers_map=HeadersMap):
        self.key_id = key_id
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.headers_map = headers_map
        self.cached_signers = {}

    def get_required_headers(self, http_method):
        return getattr(self.headers_map, http_method)

    def mk_signer(self, http_method):
        if not self.cached_signers.get(http_method):
            # build the signer and cache it
            self.cached_signers[http_method] = HeaderSigner(
                key_id=self.key_id,
                secret=self.secret_key,
                algorithm=self.algorithm,
                headers=self.get_required_headers(http_method)
            )
        return self.cached_signers.get(http_method)

    def compute_digest(self, body):
        if not body:
            body = ""
        digest = hashlib.sha256(body).digest()
        b64_digest = base64.b64encode(digest).decode('utf-8')
        return {
            "digest": "SHA-256=%s" % b64_digest,
            "content-length" : len(body)
        }

    def mk_headers_for_signing(self, http_method, request):
        headers = request.headers
        header_names = map(lambda name: name.lower, headers.keys())

        if 'date' not in header_names:
            headers['date'] =  email.utils.formatdate(usegmt=True)

        if 'host' in self.get_required_headers(http_method):
            headers['host'] = six.moves.urllib.parse.urlparse(request.url).netloc

        if 'digest' in self.get_required_headers(http_method):
            headers.update(self.compute_digest(request.body))
        return headers

    def __call__(self, request):
        http_method = request.method.lower()
        signer = self.mk_signer(http_method)
        if not signer:
            raise IOError("Cannot sign method: %s" % http_method)

        headers = self.mk_headers_for_signing(http_method, request)
        signed_headers = signer.sign(
            headers, host=headers.get('host'),
            method=http_method,
            path=request.path_url)
        request.headers.update(signed_headers)
        return request
