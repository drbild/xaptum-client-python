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

import donna25519

def public_key_from_bytes_le(bytes_le):
    """Decodes a Curve25519 public key from the byte representation in
    little endian order.

    """
    raw = donna25519.keys.PublicKey(bytes_le)
    return public_key(raw)
    
def public_key_from_bytes_be(bytes_be):
    """Decodes a Curve25519 public key from the byte representation in big
    endian order.

    """
    bytes_le = bytes_be[::-1]
    return public_key_from_bytes_le(bytes_le)

class public_key(object):
    """A Curve25519 public key for Diffie-Hellman key agreement.

    """
 
    def __init__(self, public):
        self._public = public

    def to_bytes_le(self):
        """Returns the byte representation of the public key in little endian
        order.

        """
        return self._public.public

    def to_bytes_be(self):
        """Returns the byte representation of the public key in big endian
        order.

        """
        return self.to_bytes_le()[::-1]
        
class key_pair(object):
    """A Curve25519 public and private key pair for Diffie-Hellman key
    agreement.

    """

    def __init__(self):
        """Generates a new random key pair.

        """
        self._private = donna25519.keys.PrivateKey()
        self._public = self._private.get_public()

    @property
    def public(self):
        """Returns the public key.

        """
        return public_key(self._public)

    def compute_shared(self, peer_public):
        """Computes a shared secret using the given public key and the private
        key from this pair.

        :param peer_public: The public key with which to compute a
        shared secret.
        :returns: The shared secret.

        """
        return self._private.do_exchange(peer_public._public)
