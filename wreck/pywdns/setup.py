from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    name = 'wdns',
    ext_modules = [
        Extension('wdns', ['wdns.pyx'],
            libraries = ['wdns'],
            library_dirs = ['../wdns/.libs'],
            include_dirs = ['../wdns']
        )
    ],
    py_modules = ['wdns_constants'],
    cmdclass = {'build_ext': build_ext},
)
