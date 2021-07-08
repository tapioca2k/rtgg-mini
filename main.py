from oauth2 import authorize, get_user_info

authorized = authorize()
if authorize:
    print('Auth success!')
    user_info = get_user_info()
    print(user_info)
    pass # TODO all the actual rtgg interaction
else:
    print('Auth fail')
    pass # user declined to authorize
