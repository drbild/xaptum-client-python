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

import struct

from xaptum.xdaa.exceptions import (
    InvalidMessageError
)

class Message(object):
    """
    Base class for all XDAA messages
    """

    def __init__(self, **kwargs):
        pass
    
class ClientHelloMessage(Message):

    def  __init__(self, client_group_id=b'', client_nonce=b'', **kwargs):
        super(ClientHelloMessage, self).__init__(**kwargs)
        self.version             = 0
        self.client_group_id_len = len(client_group_id)
        self.client_nonce_len    = len(client_nonce)
        self.client_group_id     = client_group_id
        self.client_nonce        = client_nonce

    header_len = 5
        
    @staticmethod
    def parse_header(header):
        """
        Takes a 5-byte header and returns a tuple of the
        ClientHelloMessage and the body length that needs to be read
        from the socket.

        Once the body is available, the returned message must be 
        updated by calling `parse_body` with the body data.

        :raises xaptum.xdda.exceptions.InvalidMessageError: If a
        message with invalid data is received.
        """
        try:
            fields = struct.unpack('!BHH', header)
        except struct.error:
            raise InvalidMessageError("Invalid ClientHello message header")

        version             = fields[0]
        client_group_id_len = fields[1]
        client_nonce_len    = fields[2]

        if version != 0:
            raise InvalidMessageError("Invalid ClientHello message version: %d"%version)
        
        message                     = ClientHelloMessage()
        message.client_group_id_len = client_group_id_len       
        message.client_nonce_len    = client_nonce_len

        length = client_group_id_len + client_nonce_len

        return (message, length)

    def parse_body(self, data):
        """
        Parses the body of the message into this instance.

        :raises xaptum.xdaa.exceptions.InvalidMessageError: If a body
        with invalid data is received.
        """
        try:
            fields = struct.unpack('!%ds%ds'%(self.client_group_id_len,
                                              self.client_nonce_len),
                                   data)
        except struct.error:
            raise InvalidMessageError("Invalid ClientHello message body received")

        self.client_group_id = fields[0]
        self.client_nonce    = fields[1]
        
    def serialize(self):
        """
        Converts the message into a bytestring, representing the
        serialized form of the message.
        """
        header = struct.pack('!BHH',
                             self.version,
                             self.client_group_id_len,
                             self.client_nonce_len)

        body = struct.pack('!%ds%ds'%(self.client_group_id_len,
                                      self.client_nonce_len),
                           self.client_group_id,
                           self.client_nonce)

        return header + body

class ServerKeyExchangeMessage(Message):

    def __init__(self,
                 server_group_id=b'',
                 server_nonce=b'',
                 server_ecdhe_public_key=b'',
                 signature=b'',
                 **kwargs):
        super(ServerKeyExchangeMessage, self).__init__(**kwargs)
        self.version                     = 0
        self.server_group_id_len         = len(server_group_id)
        self.server_nonce_len            = len(server_nonce)
        self.server_ecdhe_public_key_len = len(server_ecdhe_public_key)
        self.signature_len               = len(signature)
        self.server_group_id             = server_group_id
        self.server_nonce                = server_nonce
        self.server_ecdhe_public_key     = server_ecdhe_public_key
        self.signature                   = signature

    header_len = 9

    @staticmethod
    def serialize_for_signature(server_ecdhe_public_key, client_nonce):
        """
        Serializes the provided parameters into the correct format for creating
        or verifying the signature field.
        """
        sig_format = '!%ds%ds'%(len(server_ecdhe_public_key),
                                len(client_nonce))
        return struct.pack(sig_format,
                           server_ecdhe_public_key,
                           client_nonce)

    @staticmethod
    def parse_header(header):
        """
        Takes a 9-byte header and returns a tuple of the
        ServerKeyExchangeMessage and the body length that needs to be read
        from the socket.

        Once the body is available, the returned message must be
        updated by calling `parse_body` with the body data.

        :raises xaptum.xdaa.exceptions.InvalidMessageError: If a
        message with invalid ata is received.
        """
        try:
            fields = struct.unpack('!BHHHH', header)
        except struct.error:
            raise InvalidMessageError("Invalid ServerKeyExchange message header")

        version                     = fields[0]
        server_group_id_len         = fields[1]
        server_nonce_len            = fields[2]
        server_ecdhe_public_key_len = fields[3]
        signature_len               = fields[4]
        
        if version != 0:
            raise InvalidMessageError("Invalid ServerKeyExchange message version: %d"%version)

        message                             = ServerKeyExchangeMessage()
        message.server_group_id_len         = server_group_id_len
        message.server_nonce_len            = server_nonce_len
        message.server_ecdhe_public_key_len = server_ecdhe_public_key_len
        message.signature_len               = signature_len

        length = (server_group_id_len + server_nonce_len +
                  server_ecdhe_public_key_len + signature_len)

        return (message, length)

    def parse_body(self, data):
        """
        Parses the body of the message into this instance.

        :raises xaptum.xdaa.exceptions.InvalidMessageError: If a body
        with invalid data is received.
        """
        try:
            fields = struct.unpack('!%ds%ds%ds%ds'%(self.server_group_id_len,
                                                    self.server_nonce_len,
                                                    self.server_ecdhe_public_key_len,
                                                    self.signature_len),
                                   data)
        except struct.error:
            raise InvalidMessageError("Invalid ServerKeyExchange mesasge body received")

        self.server_group_id         = fields[0]
        self.server_nonce            = fields[1]
        self.server_ecdhe_public_key = fields[2]
        self.signature               = fields[3]

    def serialize(self):
        """
        Converts the message into a bytestring representing the
        serialized form of the message.
        """
        header = struct.pack('!BHHHH',
                             self.version,
                             self.server_group_id_len,
                             self.server_nonce_len,
                             self.server_ecdhe_public_key_len,
                             self.signature_len)

        body = struct.pack('!%ds%ds%ds%ds'%(self.server_group_id_len,
                                            self.server_nonce_len,
                                            self.server_ecdhe_public_key_len,
                                            self.signature_len),
                           self.server_group_id,
                           self.server_nonce,
                           self.server_ecdhe_public_key,
                           self.signature)

        return header + body

class ClientKeyExchangeMessage(Message):

    def __init__(self,
                 client_ecdhe_public_key=b'',
                 signature=b'',
                 **kwargs):
        super(ClientKeyExchangeMessage, self).__init__(**kwargs)
        self.version                     = 0
        self.client_ecdhe_public_key_len = len(client_ecdhe_public_key)
        self.signature_len               = len(signature)
        self.client_ecdhe_public_key     = client_ecdhe_public_key
        self.signature            = signature

    header_len = 5

    @staticmethod
    def serialize_for_signature(client_ecdhe_public_key, server_nonce):
        """
        Serializes the provided parameters into the correct format for creating
        or verifying the signature field.
        """
        format = '!%ds%ds'%(len(client_ecdhe_public_key),
                                len(server_nonce))
        return struct.pack(sig_format,
                           client_ecdhe_public_key,
                           server_nonce)

    @staticmethod
    def parse_header(header):
        """
        Takes a 5-byte header and returns a tuple of the
        ClientKeyExchangeMessage and the body length that needs to be read
        from the socket.

        Once the body is available, the returned message must be
        updated by calling `parse_body` with the body data.

        :raises xaptum.xdaa.exceptions.InvalidMessageError: If a
        message with invalid data is received.
        """
        try:
            fields = struct.unpack('!BHH', header)
        except struct.error:
            raise InvalidMessageError("Invalid ClientKeyExchange message header")

        version                     = fields[0]
        client_ecdhe_public_key_len = fields[1]
        signature_len        = fields[2]

        if version != 0:
            raise InvalidMessageError("Invalid ClientKeyExchange message version: %d"%version)

        message                             = ClientKeyExchangeMessage()
        message.client_ecdhe_public_key_len = client_ecdhe_public_key_len
        message.signature_len               = signature_len

        length = (client_ecdhe_public_key_len + signature_len)

        return (message, length)

    def parse_body(self, data):
        """
        Parses the body of the message into this instance.

        :raises xaptum.xdaa.exceptions.InvalidMessageError: If a body
        with invalid data is received.
        """
        print(self.client_ecdhe_public_key_len)
        print(self.signature_len)
        print(len(data))
        try:
            fields = struct.unpack('!%ds%ds'%(self.client_ecdhe_public_key_len,
                                              self.signature_len),
                                   data)
        except struct.error:
            raise InvalidMessageError("Invalid ClientKeyExchange message body received")

        self.client_ecdhe_public_key = fields[0]
        self.signature               = fields[1]

    def serialize(self):
        """
        Converts the message into a bytestring representing the
        serialized form of the message.
        """
        header = struct.pack('!BHH',
                             self.version,
                             self.client_ecdhe_public_key_len,
                             self.signature_len)

        body = struct.pack('!%ds%ds'%(self.client_ecdhe_public_key_len,
                                      self.signature_len),
                           self.client_ecdhe_public_key,
                           self.signature)

        return header + body
