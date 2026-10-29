def mypyc_attr(*a, **k):
    def deco(c): return c
    return deco
def trait(c): return c
