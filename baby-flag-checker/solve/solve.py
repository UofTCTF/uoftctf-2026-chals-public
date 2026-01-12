import builtins, contextlib, io

class _Proxy:
    def __init__(self, parent, idxs):
        self.p = parent
        self.idxs = tuple(idxs)
    def __getitem__(self, k):
        if isinstance(k, slice):
            return _Proxy(self.p, self.idxs[k])
        if isinstance(k, int):
            return _Proxy(self.p, (self.idxs[k],))
        raise TypeError
    def __eq__(self, other):
        print(self.idxs, other)
        self.p.c.append((self.idxs, other))
        return True

class hook_s:
    def __init__(self, n):
        self.n, self.c = n, []
    def __len__(self):
        return self.n
    def __getitem__(self, k):
        if isinstance(k, slice):
            return _Proxy(self, range(*k.indices(self.n)))
        if isinstance(k, int):
            if k < 0:
                k += self.n
            return _Proxy(self, (k,))
        raise TypeError

g, buf, hook = {}, io.StringIO(), hook_s(74)

exec(open("baby.py").read(), g, g)

def fake_input(prompt=""):
    print(prompt, end="", file=buf)
    return hook

with contextlib.redirect_stdout(buf):
    orig = builtins.input
    builtins.input = fake_input
    try: g["gog0sQu1D"]()
    finally: builtins.input = orig

print(buf.getvalue())
