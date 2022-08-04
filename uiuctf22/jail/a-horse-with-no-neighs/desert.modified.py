#!/usr/bin/python3
import re
import random
import IPython
import sys
horse = input("Begin your journey: ")
m = re.search(r"[a-zA-Z]{4}", horse)
print(f"match: {m}")

if m:
    print("It has begun raining, so you return home.")
    sys.exit(0)

syms = set(re.findall(r"[\W]", horse))
print(f"symbols: {syms} --- ({len(syms)})")

if len(syms) > 4:
    print("A dead horse cannot bear the weight of all those special characters. You return home.")
    sys.exit(0)


print('Compiling code')
original = compile(horse, "<horse>", "eval")

print(f"co_names: {original.co_names}")
c = original.replace(co_names=())

evaluated = eval(c)
print(f"evaluated: {evaluated}")

discovery = list(evaluated)
random.shuffle(discovery)
print("You make it through the journey, but are severely dehydrated. This is all you can remember:", discovery)
