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

from xaptum.xdaa import daa

from hypothesis import assume, given
from hypothesis.strategies import binary, integers

import pytest

class TestKeys(object):

    def test_from_csv(self):
        keys = daa.Keys.from_csv("123456789,04DDD7D190CA38B9891DFEA3BD542A0E29CCF413B7020D8EF85F5821BFD3C03E5684409AB42C897FB7BE3DF4D6BFDA59F97217144306BC577B9FDF8BEB24158432,3FEA28D30FF2B3C16900B9DC77F0AF631C5CFB9103BC23D35BA10FF333A46C3E")

        assert keys.group_id == b"123456789"
        assert keys.server_public_key == b"04DDD7D190CA38B9891DFEA3BD542A0E29CCF413B7020D8EF85F5821BFD3C03E5684409AB42C897FB7BE3DF4D6BFDA59F97217144306BC577B9FDF8BEB24158432"
        assert keys.client_private_key == b"3FEA28D30FF2B3C16900B9DC77F0AF631C5CFB9103BC23D35BA10FF333A46C3E"
