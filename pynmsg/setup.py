from distutils.core import setup
from distutils.extension import Extension

try:
    from Cython.Distutils import build_ext
    setup(
        name = '_nmsg',
        ext_modules = [
            Extension('_nmsg', ['_nmsg.pyx'],
                libraries = ['nmsg'],
                library_dirs = ['../nmsg/.libs'],
                include_dirs = ['../nmsg', '../protobuf-c', '..']
            )
        ],
        cmdclass = {'build_ext': build_ext},
    )
except ImportError:
    setup(
        name = '_nmsg',
        ext_modules = [
            Extension('_nmsg', ['_nmsg.c'],
                libraries = ['nmsg'],
                library_dirs = ['../nmsg/.libs'],
                include_dirs = ['../nmsg', '../protobuf-c', '..']
            )
        ],
    )

setup(
    name = 'nmsg',
    py_modules = ['nmsg'],
)
