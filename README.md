.. FlaskCavage documentation master file, created by
   sphinx-quickstart on Wed Mar  8 22:26:52 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Flask-Cavage
=======================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:


Flask-Cavage adds Cavage signature verification and authentication to the
Flask framework. Cavage is a protocol extension is intended to provide a 
simple and standard way for clients to sign HTTP messages (quote from the `cavage draft`_)

.. _cavage draft: https://tools.ietf.org/html/draft-cavage-http-signatures-03

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

    $ pip install Flask-Cavage


Quickstart
----------

After installing the extension, import it into your flask application, 
configure the extension by defining the headers to sign, define a method
that will return a secret key given an access key and you are good to go::

    from flask import Flask
    from flask_cavage import CavageSignature

    keys = {
        'access-key-1': '123456789',
        'access-key-2': '4381326329'}

    def init_signature_verification(app):
        cavage_signature = CavageSignature(app)

        @cavage_signature.secret_loader
        def load_secret(access_key):
            app.logger.debug("Loading secret for %s" % access_key)
            # You can store your keys in files, databases, hash tables...
            if access_key in keys:
                return keys.get(access_key)

    app = Flask(__name__)
    # Verify the URI, host and date headers. Don't verify the body
    app.config['CAVAGE_VERIFIED_HEADERS'] = ['(request-target)', 'host', 'date'])
    init_signature_verification(app)

Configuration
-------------

The only tunable available is the CAVAGE_VERIFIED_HEADERS parameter. This instructs
the extension on which headers (and optionally include the body) to include in the verification
process

=================================== ====================================================
`request-target`                     Use the URI in the verification process

`date`                               Use the the provided date to verify the signature

*any valid http header*              The request has this http header, use it in signature verification

`digest`                             Include the request body in digest verification
=================================== ====================================================



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
