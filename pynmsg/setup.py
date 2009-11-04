from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    name = 'nmsg',
    ext_modules = [
        Extension('nmsg', ['nmsg.pyx'],
            libraries = ['nmsg'],
            library_dirs = ['../nmsg/.libs'],
            include_dirs = ['../nmsg']
        )
    ],
    cmdclass = {'build_ext': build_ext},
)
