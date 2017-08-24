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

import os

from xaptum.crypto import x25519
from xaptum.crypto import secp256r1

from xaptum.xdaa.events import *

class SyncCrypto(object):
    """Mixin for `XDAAHandshake` that handles the crypto events
    synchronously and on the CPU

    """

    @classmethod
    def mixin_to(cls, obj, *args, **kwargs):
        """Mixin the SyncCrypto class to the provided object

        """
        obj_cls = obj.__class__
        obj.__class__ = type(obj_cls.__name__, (cls, obj_cls), {})
        obj._sync_crypto_init(*args, **kwargs)
        return obj

    def _sync_crypto_init(self, *args, **kwargs):
        self._sync_crypto_dispatch = {
            Events.CREATE_NONCE                    : self.create_nonce,
            Events.EPHEMERAL_CREATE_KEY            : self.ephemeral_create_key,
            Events.EPHEMERAL_COMPUTE_SHARED_SECRET : self.ephemeral_compute_shared_secret,
            Events.EPHEMERAL_DECODE_PUBLIC_KEY     : self.ephemeral_decode_public_key,
            Events.EPHEMERAL_ENCODE_PUBLIC_KEY     : self.ephemeral_encode_public_key,
            Events.GROUP_DECODE_PUBLIC_KEY         : self.group_decode_public_key,
            Events.GROUP_DECODE_PRIVATE_KEY        : self.group_decode_private_key,
            Events.GROUP_SHA256_SIGN_DATA          : self.group_sha256_sign_data,
            Events.GROUP_SHA256_VERIFY_SIGNATURE   : self.group_sha256_verify_signature
        }

    def receive(self, event):
        while True:
            event = super(SyncCrypto, self).receive(event)
            if event.kind in self._sync_crypto_dispatch:
                event = self._sync_crypto_dispatch[event.kind](event)
            else:
                return event
        
    def create_nonce(self, event):
        nonce = os.urandom(event.size)
        return CreateNonceResult(nonce)

    def ephemeral_create_key(self, _):
        key = x25519.key_pair()
        return EphemeralCreateKeyResult(key)

    def ephemeral_compute_shared_secret(self, event):
        secret = event.private_key.compute_shared(event.public_key)[::-1]
        return EphemeralComputeSharedSecretResult(secret)

    def ephemeral_decode_public_key(self, event):
        public_key = x25519.public_key_from_bytes_be(event.encoded_public_key)
        return EphemeralDecodePublicKeyResult(public_key)

    def ephemeral_encode_public_key(self, event):
        encoded_public_key = event.key.public.to_bytes_be()
        return EphemeralEncodePublicKeyResult(encoded_public_key)

    def group_decode_public_key(self, event):
        key = secp256r1.public_key_from_encoded_point_hex(event.encoded_public_key)
        return GroupDecodePublicKeyResult(key)

    def group_decode_private_key(self, event):
        key = secp256r1.private_key_from_int_hex(event.encoded_private_key)
        return GroupDecodePrivateKeyResult(key)

    def group_sha256_sign_data(self, event):
        signature = event.private_key.sign_sha256(event.data)
        return GroupSHA256SignDataResult(signature)
    
    def group_sha256_verify_signature(self, event):
        verified = event.public_key.verify_sha256(event.signature, event.data)
        return GroupSHA256VerifySignatureResult(verified)
