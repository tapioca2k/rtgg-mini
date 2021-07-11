import requests, json, os, base64, webbrowser, time
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer

def rand_string(dlen):
    return base64.b64encode(os.urandom(dlen)).decode()

def read_secrets():
    with open('secrets.json', 'r') as secrets:
        j = json.loads(secrets.read())
    return j

def write_secret(key, val):
    j = read_secrets()
    j[key] = val
    with open('secrets.json', 'w') as secrets:
        secrets.write(json.dumps(j))

base_url = 'http://localhost:8000' # TODO replace with production url ('https://www.racetime.gg/')
auth_endpoint = '/o/authorize'
token_endpoint = '/o/token'
userinfo_endpoint = '/o/userinfo'
success_endpoint = '/o/done'
failure_endpoint = '/o/done?error=access_denied'

redirect_port = 1223
redirect_ip = '127.0.0.1'
redirect_uri = 'http://%s:%s' % (redirect_ip, redirect_port)

j = read_secrets()
client_id = j['client_id']
client_secret = j['client_secret']
client_code = j['client_code']
refresh_token = j['refresh_token']
auth_token = None

# for handling http redirect
class RedirectHandler(BaseHTTPRequestHandler):
    def __init__(self, request, address, server):
        super().__init__(request, address, server)
        
    def do_GET(self):
        global base_url, success_endpoint, failure_endpoint
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if 'error' in qs:
            self.server.error = True
            self.send_response(301)
            self.send_header('Location', base_url + failure_endpoint)
            self.end_headers()            
        else:
            self.server.error = False
            self.server.code = qs['code'][0]
            self.send_response(301)
            self.send_header('Location', base_url + success_endpoint)
            self.end_headers()

class RedirectServer(ThreadingTCPServer):
    def __init__(self, redirect_ip, redirect_port):
        self.code = None
        self.error = None
        super().__init__((redirect_ip, redirect_port), RedirectHandler)
        self.allow_reuse_address = True

# first time user authorization
def do_auth():
    response_type = 'code'
    scope = 'read chat_message race_action'
    state = rand_string(32)
    
    full_url = base_url + auth_endpoint + '?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s' % (response_type, client_id, redirect_uri, scope, state)
    webbrowser.open(full_url)

    with RedirectServer(redirect_ip, redirect_port) as httpd:
        httpd.handle_request()
        while httpd.error is None:
            time.sleep(1)
        if httpd.error:
            code = None
        else:
            code = httpd.code
            write_secret('client_code', code)

    return code


# get user's info
def get_user_info():
    if auth_token == '':
        return None
    
    url = base_url + userinfo_endpoint
    headers = {'Authorization': 'Bearer %s' % (auth_token,)}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return json.loads(r.text)
    else:
        return None


def token_request(data):
    print('Need client code.. it is ' + str(client_code))
    if client_code == '' or client_code is None:
        return None, None
    
    full_url = base_url + token_endpoint
    r = requests.post(full_url, data=data)
    if r.status_code == 200:
        j = json.loads(r.text)
        token = j['access_token']
        refresh_token = j['refresh_token']
        write_secret('refresh_token', refresh_token)
        print('Success. token %s refresh %s' % (token, refresh_token))
        return token, refresh_token
    else:
        print('Error doing token request')
        print(r.text)
        return None, None


# get a token + refresh token
def get_new_token():
    data = {
        'grant_type': 'authorization_code',
        'code': client_code,
        'client_id': client_id
        }
    return token_request(data)


# refresh token
def try_renew_access():
    if refresh_token == '' or refresh_token is None:
        return None, None
    
    data = {
        'grant_type': 'refresh_token',
        'code': client_code,
        'client_id': client_id,
        'client_secret': client_secret,
        'refresh_token': refresh_token
        }
    return token_request(data)

# select the right method for getting tokens
def get_tokens():
    print('Checking refresh token: ' + str(refresh_token))
    if refresh_token == '' or refresh_token is None:
        print('getting new')
        return get_new_token()
    else:
        print('refreshing')
        return try_renew_access()


def authorize():
    global auth_token, refresh_token, client_code
    # 1. try to get user info
    user_info = get_user_info()
    if user_info is not None:
        print('User info get success :)')
        return True
    
    # 2. if this fails, try to renew access
    auth_token, refresh_token = get_tokens()
    if auth_token is not None:
        print('Token refresh success :)')
        return True
    
    # 3. if that failed, ask user to authenticate
    client_code = do_auth()
    if client_code is None:
        return False

    # 4. user is authorized :)
    print('Auth code get success :)')
    auth_token, refresh_token = get_tokens()
    print('Final auth step complete! token %s renew %s' % (auth_token, refresh_token))
    return True
