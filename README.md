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


@app.route('/hello_world_private', methods=['GET'])
@require_apikey_authentication
def hello_world_private():
    # Valid cavage signatures ed
    return '<Whisper> Hello, world!'


if __name__ == "__main__":
    # verify the uri, host and date headers. don't verify the body
    init_signature_verification(app)
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.DEBUG)
    app.run()
```


Example client using requests.


```python
import requests
import email.utils
from cavage_signed_request_auth import CavageSignedRequestAuth


def mk_headers():
    return {
        "date": email.utils.formatdate(usegmt=True),
        "content-type": "application/json"
    }


def mk_auth(key_id, secret):
    return CavageSignedRequestAuth(key_id, secret)


def do_simple_get(auth):
    data = dict()
    url = 'http://localhost:5000/hello_world_private'
    response = requests.get(url, auth=auth, headers=mk_headers(), json=data)
    response.raise_for_status()
    print("simple get: %s" % response.content)



def main():
    key_id = "access_key_1"
    secret = "123456789"
    auth = mk_auth(key_id, secret)
    bad_auth = mk_auth(key_id, "badSecret")
    do_simple_get(auth)

    try:
        do_simple_get(bad_auth)
    except requests.exceptions.HTTPError as exc:
        print("Expected failure: %s" % exc)

if __name__ == "__main__":
    main()
 ```
