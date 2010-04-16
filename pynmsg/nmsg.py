import ctypes
import sys

flags = sys.getdlopenflags()
sys.setdlopenflags(flags | ctypes.RTLD_GLOBAL)

from _nmsg import *

sys.setdlopenflags(flags)
