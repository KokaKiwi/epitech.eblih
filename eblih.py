#!/usr/bin/env python
import getpass
import hashlib
import hmac
import json
import os
import requests  # DEP
import keyring   # DEP
from argparse import ArgumentParser

try:
    from urllib.parse import quote as _quote
except ImportError:
    from urllib import quote as _quote


def quote(*args, **kwargs):
    return _quote(*args, safe='', **kwargs)

BLIH_VERSION = '1.7'
BLIH_BASEURL = 'https://blih.epitech.eu'
BLIH_USERAGENT = 'blih-%s' % (BLIH_VERSION)
HASH_ALGORITHM = 'sha512'
KEYRING_SERVICE_NAME = 'eblih'
KEYRING_TOKEN_KEY_NAME = 'blih-token'


class Eblih(object):

    def __init__(self, baseurl=BLIH_BASEURL, user=None, token=None, async=True, verbose=False):
        self.baseurl = baseurl
        self.token = token
        self.user = user
        self.async = async
        self.verbose = verbose

        if not self.user:
            self.user = getpass.getuser()

        if not self.token:
            self.gen_token()

    def gen_token(self, password=None):
        if password is None:
            token = keyring.get_password(
                KEYRING_SERVICE_NAME, KEYRING_TOKEN_KEY_NAME)

            if token is not None:
                self.token = token.encode('utf8')
                return self.token

            password = getpass.getpass('Enter your UNIX password: ')

        m = hashlib.new(HASH_ALGORITHM)
        m.update(password.encode('utf8'))

        token = m.hexdigest()
        keyring.set_password(
            KEYRING_SERVICE_NAME, KEYRING_TOKEN_KEY_NAME, token)

        self.token = token.encode('utf8')
        return self.token

    def sign(self, data=None):
        m = hmac.new(self.token,
                     msg=self.user.encode('utf8'),
                     digestmod=lambda: hashlib.new(HASH_ALGORITHM)
                     )

        if data is not None:
            data_json = json.dumps(
                data, sort_keys=True, indent=4, separators=(',', ': '))
            m.update(data_json.encode('utf8'))

        signed_data = {
            'user': self.user,
            'signature': m.hexdigest()
        }

        if data is not None:
            signed_data['data'] = data

        return signed_data

    def request(self, path='/', method='GET', content_type='application/json', data=None, url=None):
        data = self.sign(data)
        data_json = json.dumps(data).encode('utf8')

        if not url:
            url = self.baseurl + path

        headers = {
            'Content-Type': content_type,
            'User-Agent': BLIH_USERAGENT,
        }

        res = requests.request(method, url, data=data_json, headers=headers)
        res.raise_for_status()

        return (res.status_code, None, None, res.json())

    def safe_request(self, **kwargs):
        try:
            (status, reason, info, res) = self.request(**kwargs)
        except requests.exceptions.HTTPError as e:
            print('FAIL', kwargs)
            raise e
        return res

    # Repositories methods
    def repo_create(self, name, ty='git', desc=None):
        data = {'name': name, 'type': ty}
        if desc is not None:
            data['description'] = desc
        return self.safe_request(path='/user/repositories', method='POST', data=data)

    def repo_list(self):
        return self.safe_request(path='/user/repositories')

    def repo_delete(self, name):
        return self.safe_request(path='/user/repositories/{name:s}'.format(name=quote(name)), method='DELETE')

    def repo_info(self, name):
        return self.safe_request(path='/user/repositories/{name:s}'.format(name=quote(name)))

    def repo_setacl(self, name, username, acl):
        data = {'user': username, 'acl': acl}
        return self.safe_request(path='/user/repositories/{name:s}/acl'.format(name=quote(name)), method='POST', data=data)

    def repo_getacl(self, name):
        return self.safe_request(path='/user/repositories/{name:s}/acl'.format(name=quote(name)))

    # SSH keys methods
    def sshkey_get(self, filename):
        with open(filename, 'r') as f:
            data = f.read()

        return data.strip('\n')

    def sshkey_upload(self, filename):
        data = {'sshkey': self.sshkey_get(filename)}
        return self.safe_request(path='/user/sshkey', method='POST', data=data)

    def sshkey_delete(self, name):
        return self.safe_request(path='/user/sshkey/{key:s}'.format(key=quote(name)), method='DELETE')

    def sshkey_list(self):
        return self.safe_request(path='/user/sshkey')


class RepositoryCommand(object):
    name = 'repository'

    def config_create(self, parser):
        parser.add_argument('repo_name', metavar='NAME')
        parser.add_argument('--type', dest='repo_type', default='git')
        parser.add_argument('--desc', dest='repo_desc', default=None)

    def create(self, args, blih):
        '''
            Create a repository.
        '''
        res = blih.repo_create(
            args.repo_name, ty=args.repo_type, desc=args.repo_desc)
        if res is not None:
            print(res['message'])

    def list(self, args, blih):
        '''
            List the repositories.
        '''
        res = blih.repo_list()
        if res is not None:
            for (name, repo) in res['repositories'].items():
                print('{name:s}'.format(name=name, url=repo['url']))

    def config_delete(self, parser):
        parser.add_argument('repo_name', metavar='name')

    def delete(self, args, blih):
        '''
            Delete a repository.
        '''
        res = blih.repo_delete(args.repo_name)
        if res is not None:
            print(res['message'])

    def config_info(self, parser):
        parser.add_argument('repo_name', metavar='name')

    def info(self, args, blih):
        '''
            Get info about a repository.
        '''
        res = blih.repo_info(args.repo_name)
        if res is not None:
            print(res['message'])

    def config_setacl(self, parser):
        parser.add_argument('repo_name', metavar='name')
        parser.add_argument('username')
        parser.add_argument('acl')

    def setacl(self, args, blih):
        '''
            Set ACL for a repository.
        '''
        res = blih.repo_setacl(args.repo_name, args.username, args.acl)
        if res is not None:
            print(res['message'])

    def config_getacl(self, parser):
        parser.add_argument('repo_name', metavar='name')

    def getacl(self, args, blih):
        '''
            Get ACL for a repository.
        '''
        res = blih.repo_getacl(args.repo_name)
        if res is not None:
            for (name, acl) in res.items():
                print('{name:s}: {acl:s}'.format(name=name, acl=acl))


class SSHKeyCommand(object):
    name = 'sshkey'

    def config_upload(self, parser):
        default_filename = os.path.join(
            os.getenv('HOME'), '.ssh', 'id_rsa.pub')
        parser.add_argument('filename', nargs='?', default=default_filename)

    def upload(self, args, blih):
        '''
            Upload SSH key.
        '''
        res = blih.sshkey_upload(args.filename)
        if res is not None:
            print(res['message'])

    def list(self, args, blih):
        '''
            List SSH keys.
        '''
        res = blih.sshkey_list()
        if res is not None:
            for (name, key) in res.items():
                print('{name:s}: {key:s}'.format(name=name, key=key))

    def config_delete(self, parser):
        parser.add_argument('key_name', metavar='name')

    def delete(self, args, blih):
        '''
            Delete SSH key.
        '''
        res = blih.sshkey_delete(args.key_name)
        if res is not None:
            print(res['message'])


class ConfigCommand(object):
    name = 'config'

    def token(self, args, blih):
        '''
            Print used login token.
        '''
        print(blih.token.decode('utf8'))

    def reset_token(self, args, blih):
        '''
            Reset used login token.
        '''
        keyring.delete_password(KEYRING_SERVICE_NAME, KEYRING_TOKEN_KEY_NAME)
        print('Done.')


def get_methods(o):
    methods = dir(o)
    methods = [method for method in methods if not method.startswith('__')]
    methods = [method for method in methods if callable(getattr(o, method))]

    return methods

COMMANDS = [
    RepositoryCommand(),
    SSHKeyCommand(),
    ConfigCommand(),
]

parser = ArgumentParser()
parser.add_argument(
    '-u', '--user', default=None, help='Run as user(default=current Linux user).')
parser.add_argument('-s', '--sync', dest='async', action='store_false',
                    default=True, help='Synchronous mode(default=false).')
parser.add_argument('-v', '--verbose', action='store_true',
                    default=False, help='Verbose output(default=false).')
parser.add_argument('-t', '--token', default=None, help='Specify login token.')

subparsers = parser.add_subparsers(dest='command')

for command in COMMANDS:
    methods = get_methods(command)

    subcommands = []
    configcommands = []
    for method in get_methods(command):
        if method.startswith('config_'):
            configcommands.append(method)
        else:
            subcommands.append(method)

    subparser = subparsers.add_parser(command.name, help=command.__doc__)
    command.parser = subparser

    subsubparsers = subparser.add_subparsers(dest='subcommand')
    for subcommand in subcommands:
        method = getattr(command, subcommand)
        subsubparser = subsubparsers.add_parser(
            subcommand, help=method.__doc__)
        if 'config_{}'.format(subcommand) in configcommands:
            getattr(command, 'config_{}'.format(subcommand))(subsubparser)

if __name__ == '__main__':
    args = parser.parse_args()
    method = None

    if args.command is None:
        parser.print_help()
        exit(1)

    for command in COMMANDS:
        if command.name == args.command:
            if args.subcommand is None:
                command.parser.print_help()
                exit(1)
            method = getattr(command, args.subcommand)

    blih = Eblih(
        user=args.user,
        async=args.async,
        verbose=args.verbose,
        token=args.token,
    )
    if method is not None:
        method(args, blih)
