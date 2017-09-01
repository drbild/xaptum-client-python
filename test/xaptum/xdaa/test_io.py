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

from xaptum import fsm
from xaptum.xdaa import events
from xaptum.xdaa.sync import SyncSocket

from hypothesis import assume, given
from hypothesis.strategies import binary, integers

import pytest
import socket

class Instance(fsm.FSM):
    """FSM that returns the first command in response to the first event
    and the records the second event seen.

    """

    def __init__(self, command):
        super(Instance, self).__init__()
        self.command = command

    def initial(self, event):
        if event.kind != fsm.EXIT:
            self.become(self.recording)
            return self.command

    def recording(self, event):
        if event.kind != fsm.ENTRY and event.kind != fsm.EXIT:
            self.event = event
            return self.terminate()

class MockSock():
    """A mock socket object. Reads returns the provided data and writes
    store to an internal buffer.

    :param to_read: the data to be returned by a read

    """

    def __init__(self, to_read=b''):
        self.to_read = to_read
        self.written = b''

    def recv_into(self, buf, size, flags):
        take = min(len(self.to_read), size)
        buf[:take] = self.to_read[:take]
        self.to_read = self.to_read[take:]
        return take

    def sendall(self, buf):
        self.written += buf
        
def instance(command, sock):
    return SyncSocket.mixin_to(Instance(command), sock)

def issue(command, sock):
    ins = instance(command, sock)
    ins.receive(fsm.Start())
    return ins.event

class TestSyncSocket(object):

    @given(binary(max_size=32))
    def test_data_write(self, data):
        sock = MockSock()
        command = events.DataWrite(data)
        event = issue(command, sock)
        assert sock.written == data

    @given(binary(min_size=1, max_size=32),
           integers(min_value=1))
    def test_data_read(self, data, size):
        assume(size <= len(data))

        sock = MockSock(data)
        command = events.DataRead(size)
        event = issue(command, sock)
        assert event.data == data[:size]

    @given(integers(min_value=1))
    def test_data_read_raises_when_peer_closes_connection(self, size):
        # The peer closing the connection is observed as a read
        # returning no data.
        sock = MockSock(b'')
        command = events.DataRead(size)
        with pytest.raises(socket.error):
            event = issue(command, sock)
