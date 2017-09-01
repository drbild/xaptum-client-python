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

from xaptum.crypto import x25519

from hypothesis import assume, given
from hypothesis.strategies import binary, integers

import pytest

class TestPublicKeyEncodersAndDecoders(object):

    @given(binary(min_size=32, max_size=32))
    def test_public_key_from_bytes_be_and_to_bytes_be_are_inverses(self, public_key):
        assert public_key == x25519.public_key_from_bytes_be(public_key).to_bytes_be()

    @given(binary(min_size=32, max_size=32))
    def test_public_key_from_bytes_le_and_to_bytes_le_are_inverses(self, public_key):
        assert public_key == x25519.public_key_from_bytes_le(public_key).to_bytes_le()
        
    @given(binary(min_size=32, max_size=32))
    def test_public_key_to_bytes_le_reverses_byte_order(self, public_key):
        assert public_key[::-1] == x25519.public_key_from_bytes_be(public_key).to_bytes_le()

class TestPublicKeyEncoders(object):

    def test_key_pair_compute_shared_is_actually_shared(self):
        kp1 = x25519.key_pair()
        kp2 = x25519.key_pair()
        assert kp1 != kp2
        assert kp1.compute_shared(kp2.public) == kp2.compute_shared(kp1.public)
