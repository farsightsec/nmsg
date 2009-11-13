import socket

include "nmsg.pxi"

PyEval_InitThreads()

nmsg_set_autoclose(False)
#nmsg_set_debug(5)
nmsg_init()

include "nmsg_output.pyx"
include "nmsg_msgmod.pyx"
include "nmsg_message.pyx"
include "nmsg_msgtype.pyx"
msgtype = _msgtype()
include "nmsg_input.pyx"
include "nmsg_io.pyx"
include "nmsg_util.pyx"
