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

from enum import Enum

from xaptum import fsm
from xaptum.xdaa.events import *
from xaptum.xdaa.exceptions import *
from xaptum.xdaa.message import *

class DAAGroup(object):

    def __init__(self, group_id, server_public_key, client_private_key):
        self.group_id           = group_id
        self.server_public_key  = server_public_key
        self.client_private_key = client_private_key

class XDAAContext(object):
    """The context developed by the XDAA handshake while negotiating the
    shared secret.

    """

    def __init__(self):
        super(XDAAContext, self).__init__()

        self.protocol_version             = 0
        self.daa_group                    = None
        self.client_nonce                 = None
        self.client_daa_private_key       = None
        self.client_ephemeral_private_key = None
        self.server_nonce                 = None
        self.server_daa_public_key        = None
        self.server_ephemeral_public_key  = None

class XDAAHandshake(fsm.FSM):
    """The main xdaa handshake state machine.

    To begin the handshake call `start()` which will return an event
    representing any IO or crypto action to be completed. After
    completing the action, call `receive(event)` with the event
    representing the result of the action to continue the
    handshake. 

    A `Terminated` event is return once the handshake is complete. The
    shared secret may be retrieved from the `shared_secret` instance
    property.

    """

    def __init__(self, daa_group):
        super(XDAAHandshake, self).__init__(self.init_context)
        self.context = XDAAContext()
        self.context.daa_group = daa_group

    def mixin(self, cls, *args, **kwargs):
        return cls.mixin_to(self, *args, **kwargs)
        
    @property
    def shared_secret(self):
        return self.context.shared_secret

    def start(self):
        return self.receive(fsm.Start())

    def init_context(self, event):
        if event.kind == fsm.ENTRY:
            return self.delegate(InitContext(self.context))
        elif event.kind == fsm.TERMINATED:
            return self.become(self.send_client_hello)
        else:
            return self.unhandled(event)
    
    def send_client_hello(self, event):
        if event.kind == fsm.ENTRY:
            return self.delegate(SendClientHello(self.context))
        elif event.kind == fsm.TERMINATED:
            return self.become(self.receive_server_key_exchange)
        else:
            return self.unhandled(event)

    def receive_server_key_exchange(self, event):
        if event.kind == fsm.ENTRY:
            return self.delegate(ReceiveServerKeyExchange(self.context))
        elif event.kind == fsm.TERMINATED:
            return self.become(self.send_client_key_exchange)

    def send_client_key_exchange(self, event):
        if event.kind == fsm.ENTRY:
            return self.delegate(SendClientKeyExchange(self.context))
        elif event.kind == fsm.TERMINATED:
            return self.become(self.compute_shared_secret)

    def compute_shared_secret(self, event):
        if event.kind == fsm.ENTRY:
            return EphemeralComputeSharedSecret(
                self.context.client_ephemeral_private_key,
                self.context.server_ephemeral_public_key
            )
        elif event.kind == Events.EPHEMERAL_COMPUTE_SHARED_SECRET_RESULT:
            self.context.shared_secret = event.secret
            return self.terminate()
        else:
            return self.unhandled(event)
            
class InitContext(fsm.FSM, fsm.StepMixin):

    def __init__(self, context):
        super(InitContext, self).__init__(self.steps)
        self.context = context

    def steps(self, event):
        if self.init_step(event.kind == fsm.ENTRY):
            return GroupDecodePublicKey(self.context.daa_group.server_public_key)
        elif self.step(1, event.kind == Events.GROUP_DECODE_PUBLIC_KEY_RESULT):
            self.context.server_group_public_key = event.public_key
            return GroupDecodePrivateKey(self.context.daa_group.client_private_key)
        elif self.step(2, event.kind == Events.GROUP_DECODE_PRIVATE_KEY_RESULT):
            self.context.client_group_private_key = event.private_key
            return CreateNonce(size=32)
        elif self.step(3, event.kind == Events.CREATE_NONCE_RESULT):
            self.context.client_nonce = event.nonce
            return EphemeralCreateKey()
        elif self.step(4, event.kind == Events.EPHEMERAL_CREATE_KEY_RESULT):
            self.context.client_ephemeral_private_key = event.key
            return self.terminate()
        else:
            return self.unhandled(event)

class SendClientHello(fsm.FSM, fsm.StepMixin):

    def __init__(self, context):
        super(SendClientHello, self).__init__(self.send)
        self.context = context

    def send(self, event):
        if event.kind == fsm.ENTRY:
            client_hello = ClientHelloMessage(self.context.daa_group.group_id,
                                              self.context.client_nonce)
            return DataWrite(client_hello.serialize())
        elif event.kind == Events.DATA_WRITE_RESULT:
            return self.terminate()
        else:
            return self.unhandled(event)

class ReceiveServerKeyExchange(fsm.FSM, fsm.StepMixin):

    def __init__(self, context):
        super(ReceiveServerKeyExchange, self).__init__(self.receive_message)
        self.context = context

    def receive_message(self, event):
        if self.init_step(event.kind == fsm.ENTRY):
            return DataRead(ServerKeyExchangeMessage.header_len)
        elif self.step(1, event.kind == Events.DATA_READ_RESULT):
            (self.message,
             remaining) = ServerKeyExchangeMessage.parse_header(event.data)
            return DataRead(remaining)
        elif self.step(2, event.kind == Events.DATA_READ_RESULT):
            self.message.parse_body(event.data)
            return self.become(self.validate_message)
        else:
            return self.unhandled(event)

    def validate_message(self, event):
        if self.init_step(event.kind == fsm.ENTRY):
            if self.message.version != self.context.protocol_version:
                raise UnsupportedVersionError()
            if self.message.server_group_id != self.context.daa_group.group_id:
                raise IncorrectGroupError()
            return GroupSHA256VerifySignature(self.context.server_group_public_key,
                                              self.message.serialize_for_signature(
                                                  self.message.server_ecdhe_public_key,
                                                  self.context.client_nonce
                                              ),
                                              self.message.signature)
        elif self.step(1, event.kind == Events.GROUP_SHA256_VERIFY_SIGNATURE_RESULT):
            if event.verified == False:
                raise InvalidSignatureError()
            return self.become(self.process_message)
        else:
            return self.unhandled(event)

    def process_message(self, event):
        if event.kind == fsm.ENTRY:
            self.context.server_nonce = self.message.server_nonce
            return EphemeralDecodePublicKey(self.message.server_ecdhe_public_key)
        elif event.kind == Events.EPHEMERAL_DECODE_PUBLIC_KEY_RESULT:
            self.context.server_ephemeral_public_key = event.public_key
            return self.terminate()
        else:
            return self.unhandled(event)

class SendClientKeyExchange(fsm.FSM, fsm.StepMixin):

    def __init__(self, context):
        super(SendClientKeyExchange, self).__init__(self.prepare_message)
        self.context = context

    def prepare_message(self, event):
        if self.init_step(event.kind == fsm.ENTRY):
            return EphemeralEncodePublicKey(self.context.client_ephemeral_private_key)
        elif self.step(1, event.kind == Events.EPHEMERAL_ENCODE_PUBLIC_KEY_RESULT):
            self.public_key_encoded = event.public_key_encoded
            sig_buffer = ClientKeyExchangeMessage.serialize_for_signature(
                self.public_key_encoded,
                self.context.server_nonce
            )
            return GroupSHA256SignData(self.context.client_group_private_key,
                                       sig_buffer)
        elif self.step(2, event.kind == Events.GROUP_SHA256_SIGN_DATA_RESULT):
            self.signature = event.signature
            self.message = ClientKeyExchangeMessage(self.public_key_encoded,
                                                    self.signature)
            return self.become(self.send_message)
        else:
            return self.unhandled(event)

    def send_message(self, event):
        if event.kind == fsm.ENTRY:
            return DataWrite(self.message.serialize())
        elif event.kind == Events.DATA_WRITE_RESULT:
            return self.terminate()
        else:
            return self.unhandled(event)
