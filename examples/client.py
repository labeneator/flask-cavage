import requests
import email.utils
from signed_request_auth import SignedRequestAuth


def mk_headers():
    return {
        "date": email.utils.formatdate(usegmt=True),
        "content-type": "application/json"
    }


def mk_auth(key_id, secret):
    return SignedRequestAuth(key_id, secret)


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
