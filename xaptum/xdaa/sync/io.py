# Copyright 2017 Xaptum, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

from __future__ import absolute_import, print_function

import socket

from xaptum.xdaa.events import *

def recvexactly(sock, size, flags=0):
    """Receive exactly size bytes from the socket.

    The return value is a bytes object representing the data received. See the
    Unix manual page recv(2) for the meaning of the optional argument *flags*;
    it defaults to zero.

    """

    buffer = bytearray(size)
    view = memoryview(buffer)
    pos = 0
    while pos < size:
        read = sock.recv_into(view[pos:], size - pos, flags)
        if read == 0:
            return bytes(b'')
        pos += read
    return bytes(buffer)

class SyncSocket(object):
    """Mixin for `XDAAHandshake` that handles the IO events
    synchronously on the provided socket

    """

    @classmethod
    def mixin_to(cls, obj, sock, *args, **kwargs):
        """Mixin the SyncSocket class to the provided object

        :params socket.socket sock: the socket on which to do the I/O.

        """
        obj_cls = obj.__class__
        obj.__class__ = type(obj_cls.__name__, (cls, obj_cls), {})
        obj._sync_socket_init(sock, *args, **kwargs)
        return obj

    def _sync_socket_init(self, sock, *args, **kwargs):
        self._sync_socket_sock = sock
        self._sync_socket_dispatch = {
            Events.DATA_WRITE : self.data_write,
            Events.DATA_READ  : self.data_read
        }

    def receive(self, event):
        while True:
            event = super(SyncSocket, self).receive(event)
            if event.kind in self._sync_socket_dispatch:
                event = self._sync_socket_dispatch[event.kind](event)
            else:
                return event
            
    def data_write(self, event):
        self._sync_socket_sock.sendall(event.data)
        return DataWriteResult()

    def data_read(self, event):
        data = recvexactly(self._sync_socket_sock, event.size)
        if data == b'':
            raise socket.error("Connection closed by peer")
        return DataReadResult(data)
