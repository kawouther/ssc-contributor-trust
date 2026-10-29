# Stub out heavy precompile-only dependencies (BN254/BLS12-381 pairing libs),
# which are never invoked by the TrustRegistry contract.
import sys, types, importlib.abc, importlib.machinery
class _Any(types.ModuleType):
    def __getattr__(self, n):
        if n.startswith('__'): raise AttributeError(n)
        class X:  # usable as type, callable, subscriptable
            def __init__(s,*a,**k): pass
            def __class_getitem__(c,i): return c
            def __call__(s,*a,**k): return s
        X.__name__=n; return X
class _F(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    P=('py_ecc','eth_typing','eth_utils')
    def find_spec(self, name, path, target=None):
        if name.split('.')[0] in self.P:
            return importlib.machinery.ModuleSpec(name, self, is_package=True)
    def create_module(self, spec):
        m=_Any(spec.name); m.__path__=[]; return m
    def exec_module(self, m): pass
sys.meta_path.insert(0,_F())
