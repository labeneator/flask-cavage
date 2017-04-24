Flask-Cavage
=======================================

Flask-Cavage adds Cavage signature verification and authentication to the
Flask framework. Cavage is a protocol extension is intended to provide a 
simple and standard way for clients to sign HTTP messages. 

Attribution quote from the [cavage draft](https://tools.ietf.org/html/draft-cavage-http-signatures-03)

Why Sign?
-----------
If you do run an API server, you may want to ensure that requests sent by your a
remote endpoint have not been tampered with. One way to do this is to share a common secret 
(api keys) and sign one or all of the following:

* Request headers
* Request body

You then include the signature in an HTTP header and transmit the result. On the other end,
you compute the signature (using the shared private key) and compare it to the transmitted signature.

Installation
------------
Installing the extension is simple with pip:

```sh
    pip install Flask-Cavage
```


Quickstart
----------

After installing the extension, import it into your flask application, 
configure the extension by defining the headers to sign, define a method
that will return a secret key given an access key and you are good to go::

```python
import logging
from flask import Flask
from flask_cavage import CavageSignature, require_apikey_authentication

keys = {
    'access_key_1': '123456789',
    'access_key_2': '4381326329'}

def init_signature_verification(app):
    cavage_signature = CavageSignature(app)

    @cavage_signature.secret_loader
    def load_secret(access_key):
        app.logger.debug("Loading secret for %s" % access_key)
        # You can store your keys in files, databases, hash tables...
        if access_key in keys:
            return keys.get(access_key)

app = Flask(__name__)

@app.route('/hello_world')
def hello_world():
    # Cavage signatures not verified
    return 'Hello, World!'

@app.route('/hello_world_private', methods=['GET', 'POST'])
@require_apikey_authentication
def hello_world_private():
    # Valid cavage signatures ed
    return '<Whisper> Hello, world!'



if __name__ == "__main__":
    # verify the uri, host and date headers. don't verify the body
    app.config['CAVAGE_VERIFIED_HEADERS'] = ['(request-target)', 'host', 'date']
    init_signature_verification(app)
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.DEBUG)
    app.run()
```


Example client using requests.


```python
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
 ```


Configuration
-------------

The only tunable available is the CAVAGE_VERIFIED_HEADERS parameter. This instructs
the extension on which headers (and optionally include the body) to include in the verification
process

| Parameter                      |  Action                                                                |
| ------------------------------ |----------------------------------------------------------------------:|
`request-target`                 |    Use the URI in the verification process
`date`                           |     Use the the provided date to verify the signature
`*any valid http header*`        |    The request has this http header, use it in signature verification
`digest`                         |   Include the request body in digest verification

