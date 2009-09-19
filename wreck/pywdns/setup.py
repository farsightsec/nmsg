from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    name = 'pywreck',
    ext_modules = [
        Extension('pywreck', ['pywreck.pyx'], libraries = ['wreck'])
    ],
    cmdclass = {'build_ext': build_ext},
)
