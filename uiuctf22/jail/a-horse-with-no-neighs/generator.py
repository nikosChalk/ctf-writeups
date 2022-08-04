import sys
import string
import unicodedata
mappings = { }
for i in range(sys.maxunicode+1):
    c = chr(i)
    normalized_c = unicodedata.normalize('NFKC', c)
    if normalized_c != c:
        print(f"input {c} (U+{hex(i)}) is normalized to {normalized_c}")
        if normalized_c in string.printable:
            mappings.setdefault(normalized_c, []).append(c)
for normalized_c in sorted(mappings.keys()):
    unic_list = mappings[normalized_c]
    print(f"literal '{normalized_c}' can be represented by: {unic_list}")

