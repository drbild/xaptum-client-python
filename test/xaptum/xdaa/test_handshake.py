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

from xaptum import fsm
from xaptum import xdaa
from xaptum.crypto import secp256r1, x25519
from xaptum.xdaa import daa
from xaptum.xdaa.events import Events, DataWriteResult, DataReadResult
from xaptum.xdaa.exceptions import *
from xaptum.xdaa.handshake import XDAAHandshake
from xaptum.xdaa.message import *
from xaptum.xdaa.sync import SyncCrypto

from hypothesis import given
from hypothesis.strategies import binary, integers

from enum import Enum
import os

import pytest

def decode_message(message_cls, message_data):
    header_len = message_cls.header_len
    m, length = message_cls.parse_header(message_data[:header_len])
    m.parse_body(memoryview(message_data)[header_len:header_len + length])

    assert header_len + length == len(message_data)
    return m

class MockServer(fsm.FSM):
    """A test server that implements the server side of the handshake and
    validates the client actions.

    To test that the client handles incorrect inputs, subclasses may
    override methods on this class to induce incorrect server behavior

    """

    def __init__(self):
        super(MockServer, self).__init__()
        self.receive(fsm.Start())

    # -------------------------------- Server Parameters --------------------------------
    def get_server_daa_group_id(self):
        return daa_keys.group_id

    def get_server_daa_private_key(self):
        return secp256r1.private_key_from_int_hex(daa_keys.client_private_key)

    def get_client_daa_group_id(self):
        return daa_keys.group_id
    
    def get_client_daa_public_key(self):
        return secp256r1.public_key_from_encoded_point_hex(daa_keys.server_public_key)

    def get_server_version(self):
        return 0

    def get_server_nonce(self):
        return os.urandom(32)

    def get_server_ephemeral(self):
        return x25519.key_pair()

    # -------------------------------- Server Message Construction --------------------------------
    def make_server_params(self):
        self.server_version   = self.get_server_version()
        self.server_nonce     = self.get_server_nonce()
        self.server_ephemeral = self.get_server_ephemeral()

        self.server_daa_group_id    = self.get_server_daa_group_id()
        self.server_daa_private_key = self.get_server_daa_private_key()
        self.client_daa_group_id    = self.get_client_daa_group_id()
        self.client_daa_public_key  = self.get_client_daa_public_key()

    def sign_server_key_exchange(self):
        buf = ServerKeyExchangeMessage.serialize_for_signature(self.server_ephemeral.public.to_bytes_be(),
                                                               self.client_nonce)
        return self.server_daa_private_key.sign_sha256(buf)
    
    def make_server_key_exchange(self):
        sig = self.sign_server_key_exchange()
        msg = ServerKeyExchangeMessage(self.server_daa_group_id,
                                       self.server_nonce,
                                       self.server_ephemeral.public.to_bytes_be(),
                                       sig)
        msg.version = self.get_server_version()
        return msg

    def serialize_server_key_exchange(self, msg):
        return msg.serialize()
    
    # -------------------------------- Client Message Validation --------------------------------
    def parse_client_hello(self, data):
        msg = decode_message(ClientHelloMessage, data)
        self.client_nonce = msg.client_nonce
        return msg
        
    def validate_client_hello(self, msg):
        assert msg.client_group_id == daa_keys.group_id
        assert len(msg.client_nonce) == 32

    def parse_client_key_exchange(self, data):
        msg = decode_message(ClientKeyExchangeMessage, data)
        self.client_ephemeral = x25519.public_key_from_bytes_be(msg.client_ecdhe_public_key)
        return msg
            
    def validate_client_key_exchange(self, msg):
        buf = ClientKeyExchangeMessage.serialize_for_signature(msg.client_ecdhe_public_key,
                                                               self.server_nonce)
            
        assert self.client_daa_public_key.verify_sha256(msg.signature, buf)
        assert len(msg.client_ecdhe_public_key) == 32
        
    # -------------------------------- State Machine --------------------------------
    def initial(self, event):
        if event.kind == fsm.START:
            return self.become(self.client_hello)
        else:
            return self.unhandled(event)

    def client_hello(self, event):
        if event.kind == Events.DATA_WRITE:
            msg = self.parse_client_hello(event.data)
            self.validate_client_hello(msg)
            self.become(self.server_key_exchange)
            return DataWriteResult()
        else:
            return self.unhandled(event)

    def server_key_exchange(self, event):
        if event.kind == fsm.ENTRY:
            self.make_server_params()
            msg      = self.make_server_key_exchange()
            self.ske = self.serialize_server_key_exchange(msg)
        elif event.kind == Events.DATA_READ:
            assert 0 < event.size and event.size <= len(self.ske)

            buff = self.ske[:event.size]
            self.ske = self.ske[event.size:]
            if len(self.ske) == 0:
                self.become(self.client_key_exchange)

            return DataReadResult(buff)
        else:
            return self.unhandled(event)

    def client_key_exchange(self, event):
        if event.kind == Events.DATA_WRITE:
            msg = self.parse_client_key_exchange(event.data)
            self.validate_client_key_exchange(msg)

            self.secret = self.server_ephemeral.compute_shared(self.client_ephemeral)[::-1]

            self.terminate()
            return DataWriteResult()
        else:
            return self.unhandled(event)
        
def negotiate_secret(server, daa_keys):
    handshake = XDAAHandshake(daa_keys).mixin(SyncCrypto)

    event = handshake.start()
    while event.kind != Events.TERMINATED:
        event = handshake.receive(server.receive(event))

    return handshake.shared_secret

daa_keys = daa.Keys.from_csv("123456789,04DDD7D190CA38B9891DFEA3BD542A0E29CCF413B7020D8EF85F5821BFD3C03E5684409AB42C897FB7BE3DF4D6BFDA59F97217144306BC577B9FDF8BEB24158432,3FEA28D30FF2B3C16900B9DC77F0AF631C5CFB9103BC23D35BA10FF333A46C3E")

class TestXDAA(object):

    def test_negotiate_secret(self):
        class Server(MockServer):
            pass

        server = Server()
        secret = negotiate_secret(server, daa_keys)
        assert server.secret == secret

    @given(integers(min_value=1, max_value=255))
    def test_negotiate_secret_rejects_invalid_server_version(self, version):
        class Server(MockServer):
            def get_server_version(self):
                return version

        with pytest.raises(UnsupportedVersionError):
            server = Server()
            secret = negotiate_secret(server, daa_keys)

    @given(binary())
    def test_negotiate_secret_rejects_incorrect_server_group(self, group):
        class Server(MockServer):
            def get_server_daa_group_id(self):
                return group

        with pytest.raises(IncorrectGroupError):
            server = Server()
            secret = negotiate_secret(server, daa_keys)

    @given(binary(min_size=32, max_size=32))
    def test_negotiate_secret_rejects_invalid_server_signature(self, bad_client_nonce):
        class Server(MockServer):
            def sign_server_key_exchange(self):
                buf = ServerKeyExchangeMessage.serialize_for_signature(self.server_ephemeral.public.to_bytes_be(),
                                                                   bad_client_nonce)
                return self.server_daa_private_key.sign_sha256(buf)

        with pytest.raises(InvalidSignatureError):
            server = Server()
            secret = negotiate_secret(server, daa_keys)
