import json
import hashlib
import base64
import urllib2
import requests
from httpsig_cffi.requests_auth import HTTPSignatureAuth
import datetime
from wsgiref.handlers import format_date_time
from time import mktime


def rfc1123_datetime_format(dt_instant):
    stamp = mktime(dt_instant.timetuple())
    return format_date_time(stamp)


def main():
    key_id = "access_key_1"
    secret = "123456789"
    url = 'http://localhost:5000/hello_world_private'
    data = dict()
    url_components = urllib2.urlparse.urlparse(url)
    checksum = "SHA-256=" + base64.encodestring(
        hashlib.sha256(json.dumps(data)).digest()
    ).strip()

    headers = dict(
        date=rfc1123_datetime_format(datetime.datetime.now()),
        host=url_components.netloc, digest=checksum)
    signed_headers = ['(request-target)', 'host', 'date']
    auth = HTTPSignatureAuth(key_id=key_id, secret=secret, headers=signed_headers)
    z = requests.get(url, auth=auth, headers=headers, json=data)
    print z.request.headers
    print z.content


if __name__ == "__main__":
    main()
