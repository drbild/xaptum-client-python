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

import socket
import ssl
import sslpsk

from xaptum import xdaa

default_ciphers     = "PSK-AES256-GCM-SHA384:PSK-AES256-CBC-SHA"
default_ssl_version = ssl.PROTOCOL_TLSv1_2

def secure_socket(sock, shared_secret, ciphers=default_ciphers, ssl_version=default_ssl_version):
    return sslpsk.wrap_socket(sock,
                              psk=(shared_secret, 'x'),
                              ciphers=ciphers,
                              ssl_version=ssl_version)

def connect(host, port, daa_keys, ciphers=default_ciphers, ssl_version=default_ssl_version):
    """Establishes a connection to the Xaptum ENF.

    Raises *socket.error* on underlying socket errors, *ssl.SSLError* on
    underlying SSL socket errors, and *xaptum.xdaa.XDAAError* on errors during
    the XDAA secret negotiation.

    """

    tcpsock = socket.create_connection((host, port))
    secret  = xdaa.negotiate_secret(tcpsock, daa_keys)
    tlssock = secure_socket(tcpsock, secret, ciphers=ciphers, ssl_version=default_ssl_version)
    #TODO perform DDS authentication
    
    return tlssock
