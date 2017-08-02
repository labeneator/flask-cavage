import logging
from flask import Flask, g
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


    @cavage_signature.context_loader
    def load_context(access_key):
        app.logger.debug("Fun fact! I would have looked up the user for access_key '%s'" % access_key)
        app.logger.debug("Then whatever i return from this function will be accessible as g.cavage_context")
        # return some nonsense
        return dict(user_id="".join(reversed(access_key)))

app = Flask(__name__)


@app.route('/hello_world')
def hello_world():
    # Unverified requests have no context
    print getattr(g, 'cavage_context', '<no-user-context>')
    # Cavage signatures not verified
    return 'Hello, World!'


@app.route('/hello_world_private', methods=['GET'])
@require_apikey_authentication
def hello_world_private():
    # If context loader is used, we will get a user context
    print getattr(g, 'cavage_context', '<no-user-context>')
    # Valid cavage signatures requests work
    return '<Whisper> Hello, world!'


if __name__ == "__main__":
    # verify the uri, host and date headers. don't verify the body
    init_signature_verification(app)
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.DEBUG)
    app.run()
