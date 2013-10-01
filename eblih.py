#!/usr/bin/env python
import getpass
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from urllib.parse import urljoin
from argparse import ArgumentParser

BLIH_BASEURL = 'https://blih.epitech.eu'
BLIH_BASEURL = 'https://kokakiwi.net'
HASH_ALGORITHM = 'sha512'

class Blih(object):
    def __init__(self, baseurl = BLIH_BASEURL, user = None, token = None, async = True, verbose = False):
        self.baseurl = baseurl
        self.token = token
        self.user = user
        self.async = async
        self.verbose = verbose

        if not self.user:
            self.user = getpass.getuser()

        if not self.token:
            self.gen_token()

    def gen_token(self, password = None):
        if not password:
            # password = getpass.getpass('Enter your UNIX password: ')
            password = 'hello'

        m = hashlib.new(HASH_ALGORITHM)
        m.update(password.encode('utf8'))
        self.token = m.hexdigest().encode('utf8')

    def sign(self, data = None):
        m = hmac.new(self.token,
            msg = self.user.encode('utf8'),
            digestmod = lambda: hashlib.new(HASH_ALGORITHM)
        )

        if data is not None:
            data_json = json.dumps(data, sort_keys = True, indent = 4, separators = (',', ': '))
            m.update(data_json.encode('utf8'))

        signed_data = {
            'user': self.user,
            'signature': m.hexdigest()
        }

        if data is not None:
            signed_data['data'] = data

        return signed_data

    def request(self, path = '/', method = 'GET', content_type = 'application/json', data = None, url = None):
        data = self.sign(data)
        data_json = json.dumps(data).encode('utf8')

        if not url:
            url = urljoin(self.baseurl, path)

        req = urllib.request.Request(url = url, method = method, data = data_json)
        req.add_header('Content-Type', content_type)

        try:
            res = urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            return (e.code, e.reason, None, None)
        except Exception as e:
            print(e)

            return (None, None, None, None)

        return (res.status, res.reason, res.info(), res.read())

parser = ArgumentParser()
parser.add_argument('-u', '--user', default = None, help = 'Run as user(default=current Linux user).')
parser.add_argument('-s', '--sync', dest = 'async', action = 'store_false', default = True, help = 'Synchronous mode(default=false).')
parser.add_argument('-v', '--verbose', action = 'store_true', default = False, help = 'Verbose output(default=false).')

if __name__ == '__main__':
    args = parser.parse_args()
    blih = Blih(
        user = args.user,
        async = args.async,
        verbose = args.verbose,
    )

    result = blih.request(path = '/user/repositories')
    print(result)
