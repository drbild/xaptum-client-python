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
from xaptum.crypto import secp256r1, x25519
from xaptum.xdaa import events
from xaptum.xdaa.sync import SyncCrypto

from hypothesis import assume, example, given
from hypothesis.strategies import binary, integers

import pytest

import sys
import string

def is_hex(s):
    def norm(c):
        return c if sys.version_info < (3,) else chr(c)
    return all(norm(c) in string.hexdigits for c in s)

def is_not_hex(s):
    return not is_hex(s)

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

def instance(command):
    return SyncCrypto.mixin_to(Instance(command))

def issue(command):
    ins = instance(command)
    ins.receive(fsm.Start())
    return ins.event

class TestSyncCrypto(object):

    @given(integers(min_value=0, max_value=64))
    def test_create_nonce(self, size):
        command = events.CreateNonce(size)
        event = issue(command)
        assert isinstance(event.nonce, bytes)
        assert len(event.nonce) == size

    def test_ephemeral_create_key(self):
        command = events.EphemeralCreateKey()
        event = issue(command)
        assert isinstance(event.key, x25519.key_pair)

    def test_ephemeral_compute_shared_secret(self):
        private = x25519.key_pair()
        public  = x25519.key_pair().public

        command = events.EphemeralComputeSharedSecret(private, public)
        event = issue(command)
        assert isinstance(event.secret, bytes)
        assert len(event.secret) == 32

    @given(binary(min_size=32, max_size=32))
    def test_ephemeral_decode_public_key(self, encoded):
        command = events.EphemeralDecodePublicKey(encoded)
        event = issue(command)
        assert isinstance(event.public_key, x25519.public_key)

    @given(binary(min_size=0).filter(lambda x: len(x) != 32))
    def test_ephemeral_decode_public_key_raises_on_invalid_input(self, encoded):
        command = events.EphemeralDecodePublicKey(encoded)
        with pytest.raises(ValueError):
            event = issue(command)

    def test_ephemeral_encode_public_key(self):
        key = x25519.key_pair()

        command = events.EphemeralEncodePublicKey(key)
        event = issue(command)
        assert len(event.public_key_encoded) == 32

    def test_group_decode_public_key(self):
        encoded = "04DDD7D190CA38B9891DFEA3BD542A0E29CCF413B7020D8EF85F5821BFD3C03E5684409AB42C897FB7BE3DF4D6BFDA59F97217144306BC577B9FDF8BEB24158432"
        command = events.GroupDecodePublicKey(encoded)
        event = issue(command)
        assert isinstance(event.public_key, secp256r1.public_key)

    @given(binary(min_size=0).filter(is_not_hex))
    def test_group_decode_public_key_raises_on_invalid_input(self, encoded):
        command = events.GroupDecodePublicKey(encoded)
        with pytest.raises((TypeError, ValueError)):
            event = issue(command)

    def test_group_decode_private_key(self):
        encoded = "3FEA28D30FF2B3C16900B9DC77F0AF631C5CFB9103BC23D35BA10FF333A46C3E"
        command = events.GroupDecodePrivateKey(encoded)
        event = issue(command)
        assert isinstance(event.private_key, secp256r1.private_key)

    @given(binary(min_size=0).filter(is_not_hex))
    def test_group_decode_private_key_raises_on_invalid_input(self, encoded):
        command = events.GroupDecodePrivateKey(encoded)
        with pytest.raises(ValueError):
            event = issue(command)

    @given(binary(min_size=0))
    def test_group_sha256_sign_data(self, data):
        key = secp256r1.private_key_from_int_hex("3FEA28D30FF2B3C16900B9DC77F0AF631C5CFB9103BC23D35BA10FF333A46C3E")
        command = events.GroupSHA256SignData(key, data)
        event = issue(command)
        assert len(event.signature) > 0 # length of DER-encoded signature can very

    @given(binary(min_size=0))
    def test_group_sha256_verify_signature_validates_good_signature(self, data):
        key = secp256r1.private_key_from_int_hex("3FEA28D30FF2B3C16900B9DC77F0AF631C5CFB9103BC23D35BA10FF333A46C3E")
        command = events.GroupSHA256SignData(key, data)
        signature = issue(command).signature

        key = secp256r1.public_key_from_encoded_point_hex("04DDD7D190CA38B9891DFEA3BD542A0E29CCF413B7020D8EF85F5821BFD3C03E5684409AB42C897FB7BE3DF4D6BFDA59F97217144306BC577B9FDF8BEB24158432")
        command = events.GroupSHA256VerifySignature(key, data, signature)
        event = issue(command)
        assert event.verified

    @given(binary(min_size=0))
    def test_group_sha256_verify_signature_rejects_bad_signature(self, data):
        key = secp256r1.private_key_from_int_hex("3FEA28D30FF2B3C16900B9DC77F0AF631C5CFB9103BC23D35BA10FF333A46C3E")
        command = events.GroupSHA256SignData(key, data)
        signature = issue(command).signature

        data = data + b'\x63'

        key = secp256r1.public_key_from_encoded_point_hex("04DDD7D190CA38B9891DFEA3BD542A0E29CCF413B7020D8EF85F5821BFD3C03E5684409AB42C897FB7BE3DF4D6BFDA59F97217144306BC577B9FDF8BEB24158432")
        command = events.GroupSHA256VerifySignature(key, data, signature)
        event = issue(command)
        assert not event.verified
