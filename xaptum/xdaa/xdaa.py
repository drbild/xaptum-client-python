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

from xaptum.xdaa.handshake import DAAGroup, XDAAHandshake
from xaptum.xdaa.sync import SyncCrypto, SyncSocket

def negotiate_secret(sock, group):
    """Performs the XDAA handshake on the given blocking socket and
    returns the negotiated shared secret.

    Raises *socket.error* on underlying socket errors and *xdaa.XDAAError* on
    handshake errors.

    """

    daa_group = DAAGroup(*group.split(','))

    handshake = XDAAHandshake(daa_group).mixin(SyncCrypto)       \
                                        .mixin(SyncSocket, sock)

    handshake.start()
    return handshake.shared_secret
