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

class XDAAError(Exception):
    """
    Base class for errors during XDAA secret negotiation.
    """

class InvalidMessageError(XDAAError):
    """
    Parsing a message failed because the data was not laid out properly.
    """

class IncorrectGroupError(XDAAError):
    """
    The DAA group claimed by the peer is not a supported group.
    """

class InvalidSignatureError(XDAAError):
    """
    The signature on an XDAA packet was invalid.
    """

class UnsupportedVersionError(InvalidMessageError):
    """
    The peer is using an unsupported version of the XDAA protocol.
    """
