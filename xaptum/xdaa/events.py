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

from enum import IntEnum

from xaptum import fsm

class Events(IntEnum):
    # FSM
    START      = fsm.Events.START
    TERMINATED = fsm.Events.TERMINATED
    ENTRY      = fsm.Events.ENTRY
    EXIT       = fsm.Events.EXIT
    
    # IO
    DATA_WRITE        = 20
    DATA_WRITE_RESULT = 21
    DATA_READ         = 22
    DATA_READ_RESULT  = 23

    # Crypto
    CREATE_NONCE        = 30
    CREATE_NONCE_RESULT = 31

    # - x25519
    EPHEMERAL_CREATE_KEY                   = 40
    EPHEMERAL_CREATE_KEY_RESULT            = 41
    EPHEMERAL_COMPUTE_SHARED_SECRET        = 42
    EPHEMERAL_COMPUTE_SHARED_SECRET_RESULT = 43
    EPHEMERAL_DECODE_PUBLIC_KEY            = 44
    EPHEMERAL_DECODE_PUBLIC_KEY_RESULT     = 45
    EPHEMERAL_ENCODE_PUBLIC_KEY            = 46
    EPHEMERAL_ENCODE_PUBLIC_KEY_RESULT     = 47
    
    # - secp256r1
    GROUP_DECODE_PUBLIC_KEY              = 50
    GROUP_DECODE_PUBLIC_KEY_RESULT       = 51
    GROUP_DECODE_PRIVATE_KEY             = 52
    GROUP_DECODE_PRIVATE_KEY_RESULT      = 53
    GROUP_SHA256_SIGN_DATA               = 54
    GROUP_SHA256_SIGN_DATA_RESULT        = 55
    GROUP_SHA256_VERIFY_SIGNATURE        = 56
    GROUP_SHA256_VERIFY_SIGNATURE_RESULT = 57
    
# ====================================== IO ======================================
class DataWrite(fsm.Event):
    kind = Events.DATA_WRITE

    def __init__(self, data):
        super(DataWrite, self).__init__()
        self.data = data

class DataWriteResult(fsm.Event):
    kind = Events.DATA_WRITE_RESULT

class DataRead(fsm.Event):
    kind = Events.DATA_READ

    def __init__(self, size):
        super(DataRead, self).__init__()
        self.size = size
    
class DataReadResult(fsm.Event):
    kind = Events.DATA_READ_RESULT

    def __init__(self, data):
        super(DataReadResult, self).__init__()
        self.data = data
    
# ==================================== Crypto ====================================
class CreateNonce(fsm.Event):
    kind = Events.CREATE_NONCE

    def __init__(self, size):
        super(CreateNonce, self).__init__()
        self.size = size

class CreateNonceResult(fsm.Event):
    kind = Events.CREATE_NONCE_RESULT

    def __init__(self, nonce):
        super(CreateNonceResult, self).__init__()
        self.nonce = nonce

# ------------------------------------ x25519 ------------------------------------
class EphemeralCreateKey(fsm.Event):
    kind = Events.EPHEMERAL_CREATE_KEY 

class EphemeralCreateKeyResult(fsm.Event):
    kind = Events.EPHEMERAL_CREATE_KEY_RESULT

    def __init__(self, key):
        super(EphemeralCreateKeyResult, self).__init__()
        self.key  = key

class EphemeralComputeSharedSecret(fsm.Event):
    kind = Events.EPHEMERAL_COMPUTE_SHARED_SECRET

    def __init__(self, private_key, public_key):
        super(EphemeralComputeSharedSecret, self).__init__()
        self.private_key = private_key
        self.public_key = public_key

class EphemeralComputeSharedSecretResult(fsm.Event):
    kind = Events.EPHEMERAL_COMPUTE_SHARED_SECRET_RESULT

    def  __init__(self, secret):
        super(EphemeralComputeSharedSecretResult, self).__init__()
        self.secret = secret

class EphemeralDecodePublicKey(fsm.Event):
    kind = Events.EPHEMERAL_DECODE_PUBLIC_KEY

    def __init__(self, encoded_public_key):
        super(EphemeralDecodePublicKey, self).__init__()
        self.encoded_public_key = encoded_public_key

class EphemeralDecodePublicKeyResult(fsm.Event):
    kind = Events.EPHEMERAL_DECODE_PUBLIC_KEY_RESULT

    def __init__(self, public_key):
        super(EphemeralDecodePublicKeyResult, self).__init__()
        self.public_key = public_key

class EphemeralEncodePublicKey(fsm.Event):
    kind = Events.EPHEMERAL_ENCODE_PUBLIC_KEY

    def __init__(self, key):
        super(EphemeralEncodePublicKey, self).__init__()
        self.key = key

class EphemeralEncodePublicKeyResult(fsm.Event):
    kind = Events.EPHEMERAL_ENCODE_PUBLIC_KEY_RESULT

    def __init__(self, public_key_encoded):
        super(EphemeralEncodePublicKeyResult, self).__init__()
        self.public_key_encoded = public_key_encoded

# ------------------------------------ secp256r1 ------------------------------------
class GroupDecodePublicKey(fsm.Event):
    kind = Events.GROUP_DECODE_PUBLIC_KEY

    def __init__(self, encoded_public_key):
        super(GroupDecodePublicKey, self).__init__()
        self.encoded_public_key = encoded_public_key

class GroupDecodePublicKeyResult(fsm.Event):
    kind = Events.GROUP_DECODE_PUBLIC_KEY_RESULT

    def __init__(self, public_key):
        super(GroupDecodePublicKeyResult, self).__init__()
        self.public_key = public_key

class GroupDecodePrivateKey(fsm.Event):
    kind = Events.GROUP_DECODE_PRIVATE_KEY

    def __init__(self, encoded_private_key):
        super(GroupDecodePrivateKey, self).__init__()
        self.encoded_private_key = encoded_private_key
        
class GroupDecodePrivateKeyResult(fsm.Event):
    kind = Events.GROUP_DECODE_PRIVATE_KEY_RESULT

    def __init__(self, private_key):
        super(GroupDecodePrivateKeyResult, self).__init__()
        self.private_key = private_key

class GroupSHA256SignData(fsm.Event):
    kind = Events.GROUP_SHA256_SIGN_DATA

    def __init__(self, private_key, data):
        super(GroupSHA256SignData, self).__init__()
        self.private_key = private_key
        self.data = data

class GroupSHA256SignDataResult(fsm.Event):
    kind = Events.GROUP_SHA256_SIGN_DATA_RESULT

    def __init__(self, signature):
        super(GroupSHA256SignDataResult, self).__init__()
        self.signature = signature

class GroupSHA256VerifySignature(fsm.Event):
    kind = Events.GROUP_SHA256_VERIFY_SIGNATURE

    def __init__(self, public_key, data, signature):
        super(GroupSHA256VerifySignature, self).__init__()
        self.public_key = public_key
        self.data = data
        self.signature = signature

class GroupSHA256VerifySignatureResult(fsm.Event):
    kind = Events.GROUP_SHA256_VERIFY_SIGNATURE_RESULT

    def __init__(self, verified):
        super(GroupSHA256VerifySignatureResult, self).__init__()
        self.verified = verified
