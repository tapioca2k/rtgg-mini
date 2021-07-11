import requests, json, websocket, _thread, sys, uuid
from oauth2 import *

# get and return list of races that are open
def get_races_by_status(status='open'):
    r = requests.get(base_url + '/races/data')
    j = json.loads(r.text)
    o = [r for r in j['races'] if r['status']['value'] == status]
    return o

def strip_name(full_name):
    return full_name.split('/')[1]

def make_chat_message(msg):
    j = {
        'action': 'message',
        'data': {
            'message': msg,
            'guid': str(uuid.uuid1())
            }
        }
    d = json.dumps(j)
    print(d)
    return d

def on_message(ws, message):
    j = json.loads(message)
    # print(j)
def on_error(ws, error):
    print('Error: %s' % (error,))
def on_close(ws, close_status_code, close_msg):
    print('Closed ws')
def on_open(ws):
    print('Connected to ws')
    def run(*args):
        msg = input('Say something: ')
        ws.send(make_chat_message(msg))
    _thread.start_new_thread(run, ())


print(rand_string(32))
authorized = authorize()
if not authorized:
    print('Authorization failed')
    sys.exit()

auth_token, refresh_token = get_tokens()
open_races = get_races_by_status()
name = strip_name(open_races[0]['name'])
print('Attempting to join %s' % (name,))
ws = websocket.WebSocketApp('ws://127.0.0.1:8000/ws/o/race/' + name + '?token=' + auth_token,
                            on_open=on_open,
                            on_message=on_message,
                            on_error=on_error,
                            on_close=on_close)
ws.run_forever()


'''
authorized = authorize()
if authorized:
    print('Auth success!')
    user_info = get_user_info()
    print(user_info)
    pass # TODO all the actual rtgg interaction
else:
    print('Auth fail')
    pass # user declined to authorize
'''
