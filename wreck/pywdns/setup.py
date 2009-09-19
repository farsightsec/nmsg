from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    name = 'pywdns',
    ext_modules = [
        Extension('pywdns', ['pywdns.pyx'], libraries = ['wdns'])
    ],
    cmdclass = {'build_ext': build_ext},
)
