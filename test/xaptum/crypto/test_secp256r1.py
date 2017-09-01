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

from xaptum.crypto import secp256r1

from hypothesis import assume, given
from hypothesis.strategies import binary, integers

import pytest

HEX_PUBLIC_KEY = "04246aa2fea1b7b53c2d9ecad8da079126205565b64631510410212240aa08a36241142caa399ac93d74a8f3cc32947b0a1ff9891a13cdb5fa1cbe899e482d2932"

HEX_PRIVATE_KEY = "30c2c7209cf822d7e4ba56aaae1cb442d68b5eb773215e2bccc974d10d03ff90"


class TestPublicKeyDecoders(object):

    def test_public_key_from_encoded_point_hex_decodes_successfully(self):
        secp256r1.public_key_from_encoded_point_hex(HEX_PUBLIC_KEY)

class TestPrivateKeyDecoders(object):

    def test_private_key_from_int_hex_(self):
        secp256r1.private_key_from_int_hex(HEX_PRIVATE_KEY)

class TestSigningAndVerifying(object):

    @given(binary())
    def test_sign_sha256_output_verifies_on_same_message(self, message):
        priv = secp256r1.private_key_from_int_hex(HEX_PRIVATE_KEY)
        pub  = secp256r1.public_key_from_encoded_point_hex(HEX_PUBLIC_KEY)
        assert pub.verify_sha256(priv.sign_sha256(message), message)

    @given(binary(),
           binary())
    def test_sign_sha256_output_does_not_verify_on_different_message(self, m1, m2):
        assume(m1 != m2)

        priv = secp256r1.private_key_from_int_hex(HEX_PRIVATE_KEY)
        pub  = secp256r1.public_key_from_encoded_point_hex(HEX_PUBLIC_KEY)
        assert not pub.verify_sha256(priv.sign_sha256(m1), m2)
