from jinja2.runtime import TemplateReference
from jinja2 import Template
import jinja2
import json
import os
import re

def dfs_dump(obj, visited=[], indent=0):
    '''
    Use this in combination with the search method described bellow
    '''
    if obj in visited:
        res = '<visited'
        if hasattr(obj, '__call__') and hasattr(obj, '__globals__'): # function
            res += ':' + str(obj)
        res += '>'
        return res
    visited.append(obj)

    if isinstance(obj, dict) or str(type(obj)) == "<class 'mappingproxy'>":
        res  = '\n'
        res += ' '*indent + '{\n'
        for k,v in obj.items():
            res += ' '*(indent+4) + str(k) + ':'
            if k == '__doc__':
                res += '<skipped-doc>'
            else:
                res += dfs_dump(v, visited, indent+4)
            res += ",\n"
        res += ' '*indent + '}'
    
    elif hasattr(obj, '__call__') and hasattr(obj, '__globals__'): # function
        res  = ' ' + str(obj) + '\n' + ' '*indent + '__globals__:'+ dfs_dump(getattr(obj, '__globals__'), visited, indent)
        # res = str(obj)

    # elif hasattr(obj, "_ast"):
    #     return dfs_dump(obj._ast(), visited, indent)
    elif hasattr(obj, '__dict__'):
        return dfs_dump(obj.__dict__, visited, indent)
    # elif hasattr(obj, "__iter__") and not isinstance(obj, str):
    #     res  = ' '*indent + '[\n'
    #     for i,v in enumerate(obj):
    #         res += ' '*(indent+4) + str(i) + ':' + dfs_dump(v, visited, indent+4) + ",\n"
    #     res += ' '*indent + ']\n'
    else:
        res  = ' '*indent
        # res += '[ANNOTATION: type:' + str(type(obj)) +  ']'
        res += str(obj)
    return res

def dfs_dump_full(obj, visited=[], indent=0, prefix=[]):
    '''
    This will yield usable results in dump. You can copy paste them. (Don't forget to add "self" also)
    To find the best one search for, e.g. ".environ:"
    But you know that one exists in the module "os". So, instead we will search for that.
    So, search for the regex "^.+\.os:" and find the resultwith the minimum length. That result is directly usable.
    '''
    if obj in visited:
        res = '<visited'
        if hasattr(obj, '__call__') and hasattr(obj, '__globals__'): # function
            res += ':' + str(obj)
        res += '>'
        return res
    visited.append(obj)

    if isinstance(obj, dict) or str(type(obj)) == "<class 'mappingproxy'>":
        res  = '\n'
        res += ' '*indent + '{\n'
        for k,v in obj.items():
            res += ' '*(indent+4) + '.'.join(prefix) + '.' + str(k) + ':'
            if k == '__doc__':
                res += '<skipped-doc>'
            else:
                res += dfs_dump_full(v, visited, indent+4, prefix+[str(k)])
            res += ",\n"
        res += ' '*indent + '}'
    
    elif hasattr(obj, '__call__') and hasattr(obj, '__globals__'): # function
        res  = ' ' + str(obj) + '\n'
        res += ' '*indent + '__globals__:'+ dfs_dump_full(getattr(obj, '__globals__'), visited, indent, prefix+['__globals__'])
    elif hasattr(obj, '__dict__'):
        return dfs_dump_full(obj.__dict__, visited, indent, prefix)
    else:
        res  = ' '*indent
        res += str(obj)
    return res

# s = dfs_dump(os)
# print(s)

# s = Template("My name is {{ func(self) }}").render(module=json, func=dfs_dump_full)
s = Template("My name is {{ func(self) }}").render(module=json, func=dfs_dump_full)
print(s)
with open('jinja2.TemplateReference.dump', 'w') as f:
    f.write(s)

with open('jinja2.TemplateReference.dump') as f:
    lines = [l[:-1] for l in f.readlines()] # remove trailing '\n'

def find_best_path(target, used_targets=[]): # This doesn't work!!! But idea is good. Reason for not working is that you can have,
    # e.g. the same function in two namespace. This messes up path finding. Consider making a graph with full node names?
    '''
    Based on dfs_dump()
    Based on the following regex search idea:
    You find your "environ:" which has 48 spaces in front of it. Then you search for the first
    occurrence upwards for 48-4=44 spaces that starts with an identifier. That is your previous node.
    Repeated until you reach the top.
    example regex search:

    environ:
    ^ {44}[\w_\[\{]
    ^ {48}[\w_\[\{]
    ^ {40}[\w_\[\{]
    ...
    ^ {04}[\w_\[\{]
    '''
    if not target:
        return ''

    used_targets.append(target)

    target_regex = r'^( *)(' + target + r'):'
    hits = []
    for i,l in enumerate(lines):
        m = re.match(target_regex, l)
        if m and 'method' not in l:
            hits.append((i,m))
    if len(hits) == 0:
        return target

    # min_hit = hits[0]
    # for hit in hits:
    #     if len(hit[1].group(1)) < len(min_hit[1].group(1)):
    #         min_hit = hit

    min_hits = sorted(hits, key=lambda hit: len(hit[1].group(1)))

    for hit in min_hits:
        new_target = None
        in_globals = False
        for i in range(hit[0]-1, -1, -1):
            l = lines[i]
            spaces = len(hit[1].group(1))-4
            my_pattern = r'^( {' + str(spaces) + r'})([\w_]+):(.*)'
            m = re.match(my_pattern, l)
            if m:
                if m.group(2) != '__globals__':
                    new_target = m.group(2)
                else:
                    new_target = re.match(my_pattern, lines[i-1]).group(2)
                    in_globals = True
                break
        # blacklist of targets, e.g. avoid cycles
        if new_target in (['internal_code'] + used_targets):
            continue
        print("{}\t\t{}\t\t".format(hit[1].group(2), len(hit[1].group(1))), hit[0])
        break
    
    if not in_globals:
        return find_best_path(new_target, used_targets) + '.' + target
    else:
        return find_best_path(new_target, used_targets) + '.__globals__.' + target


path = find_best_path('environ')
# path = find_best_path('os')
print('self' + path)


