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

import codecs

class Keys(object):
    """The DAA keys needed for the XDAA protocol.  Keys for each client
    will be provided by Xaptum.

    :param string group_id: the DAA group identifier
    :param string server_public_key: the public key of the server 
      as a hex string of the encoded point
    :param string client_private_key: the private key of the client
      as a hex string of the integral key value

    """

    @staticmethod
    def from_csv(csv):
        """
        Parses the Keys from a comma-separated string of the form
        <GroupId>,<ServerPublicKey>,<ClientPrivateKey>
        """
        return Keys(*csv.split(','))

    def __init__(self, group_id, server_public_key, client_private_key):
        self.group_id           = codecs.encode(group_id, 'ascii')
        self.server_public_key  = codecs.encode(server_public_key, 'ascii')
        self.client_private_key = codecs.encode(client_private_key, 'ascii')
