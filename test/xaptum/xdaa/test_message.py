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

from xaptum.xdaa.message import (
    ClientHelloMessage, ServerKeyExchangeMessage, ClientKeyExchangeMessage
)

from xaptum.xdaa.exceptions import (
    InvalidMessageError
)

from hypothesis import given
from hypothesis.strategies import binary, integers

import pytest

def decode_message(message_cls, message_data):
    header_len = message_cls.header_len
    m, length = message_cls.parse_header(message_data[:header_len])
    m.parse_body(memoryview(message_data)[header_len:header_len + length])

    assert header_len + length == len(message_data)
    return m

class TestClientHelloMessage(object):

    @given(binary(min_size = 0),
           binary(min_size = 0))
    def test_client_hello_message_parse_inverts_serialize(self, client_group_id, client_nonce):
        m = ClientHelloMessage(client_group_id, client_nonce)
        d = decode_message(ClientHelloMessage, m.serialize())
        assert d.version         == 0
        assert d.client_group_id == client_group_id
        assert d.client_nonce    == client_nonce

    def test_client_hello_message_with_invalid_version_fails_to_parse(self):
        payload = b'\x01\x00\x01\x00\x01ab'

        with pytest.raises(InvalidMessageError):
            decode_message(ClientHelloMessage, payload)

    def test_client_hello_message_with_partial_header_fails_to_parse(self):
        payload = b'\x00\x00\x01\x01'

        with pytest.raises(InvalidMessageError):
            decode_message(ClientHelloMessage, payload)

    def test_client_hello_message_with_body_shorter_than_specified_in_header_fails_to_parse(self):
        payload = b'\x00\x00\x01\x00\x02ab'

        with pytest.raises(InvalidMessageError):
            decode_message(ClientHelloMessage, payload)

class TestServerKeyExchangeMessage(object):

    @given(binary(min_size = 0),
           binary(min_size = 0),
           binary(min_size = 0),
           binary(min_size = 0))
    def test_server_key_exchange_message_parse_inverts_serialize(self,
                                                                 server_group_id,
                                                                 server_nonce,
                                                                 server_ecdhe_public_key,
                                                                 signature):
        m = ServerKeyExchangeMessage(server_group_id,
                                     server_nonce,
                                     server_ecdhe_public_key,
                                     signature)
        d = decode_message(ServerKeyExchangeMessage, m.serialize())
        assert d.version                 == 0
        assert d.server_group_id         == server_group_id
        assert d.server_nonce            == server_nonce
        assert d.server_ecdhe_public_key == server_ecdhe_public_key
        assert d.signature               == signature

    def test_server_key_exchange_message_with_invalid_version_fails_to_parse(self):
        payload = b'\x01\x00\x01\x00\x01\x00\x01\x00\x01abcd'

        with pytest.raises(InvalidMessageError):
            decode_message(ServerKeyExchangeMessage, payload)

    def test_server_key_exchange_message_with_partial_header_fails_to_parse(self):
        payload = b'\x00\x00\x10\x10'

        with pytest.raises(InvalidMessageError):
            decode_message(ServerKeyExchangeMessage, payload)

    def test_server_key_exchange_message_with_body_shorter_than_specified_in_header_fails_to_parse(self):
        payload = b'\x00\x00\x01\x00\x01\x00\x01\x00\x02abcd'

        with pytest.raises(InvalidMessageError):
            decode_message(ServerKeyExchangeMessage, payload)

    def test_serialize_for_signature_serializes_correctly(self):
        pk = b'abcdef'
        n = b'12345'
        assert ServerKeyExchangeMessage.serialize_for_signature(pk, n) == pk + n

class TestClientKeyExchangeMessage(object):

    @given(binary(min_size = 0),
           binary(min_size = 0))
    def test_client_key_exchange_message_parse_inverts_serialize(self,
                                                                 client_ecdhe_public_key,
                                                                 signature):
        m = ClientKeyExchangeMessage(client_ecdhe_public_key,
                                     signature)
        d = decode_message(ClientKeyExchangeMessage, m.serialize())
        assert d.version                 == 0
        assert d.client_ecdhe_public_key == client_ecdhe_public_key
        assert d.signature               == signature

    def test_client_key_exchange_message_with_invalid_version_fails_to_parse(self):
        payload = b'\x01\x00\x01\x00\x01ab'

        with pytest.raises(InvalidMessageError):
            decode_message(ClientKeyExchangeMessage, payload)

    def test_client_key_exchange_message_with_partial_header_fails_to_parse(self):
        payload = b'\x00\x00\x10\x10'

        with pytest.raises(InvalidMessageError):
            decode_message(ClientKeyExchangeMessage, payload)

    def test_client_key_exchange_message_with_body_shorter_than_specified_in_header_fails_to_parse(self):
        payload = b'\x00\x00\x01\x00\x02ab'

        with pytest.raises(InvalidMessageError):
            decode_message(ClientKeyExchangeMessage, payload)

    def test_serialize_for_signature_serializes_correctly(self):
        pk = b'abcdef'
        n = b'12345'
        assert ClientKeyExchangeMessage.serialize_for_signature(pk, n) == pk + n
