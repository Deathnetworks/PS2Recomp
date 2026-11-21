import re
s=open('src/lib/Kernel/Syscalls/Dispatcher.cpp').read().splitlines()
cur=None
for l in s:
    m=re.match(r'\s*case (?:static_cast<uint32_t>\()?([^:]+):',l)
    if m: cur=m.group(1).strip()
    m2=re.search(r'\b(\w+)\(rdram, ctx, runtime\)',l)
    if m2 and cur: print(cur,'->',m2.group(1))
