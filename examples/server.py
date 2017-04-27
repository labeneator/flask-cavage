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
    app.config['CAVAGE_VERIFIED_HEADERS'] = ['(request-target)', 'host', 'date']
    init_signature_verification(app)
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.DEBUG)
    app.run()
