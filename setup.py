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

from setuptools import setup

setup(
    name    = 'xaptum-client',
    version = '0.1.0',
    description = 'Client libraries for the Xaptum ENF',
    author = 'Xaptum, Inc',
    author_email = 'sales@xaptum.com',
    license = 'Apache 2.0',
    url = 'https://github.com/xaptum/xaptum-client-python',
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Operating System :: MacOS',
        'Operating System :: Microsoft'
        ],
    packages = ['xaptum',
                'xaptum.client',
                'xaptum.dds',
                'xaptum.xdaa'],
    setup_requires = ['pytest-runner'],
    install_requires = ['cryptography>=1.9',
                        'enum34>=1.1.6',
                        'donna25519>=0.1.1',
                        'sslpsk>=1.0'],
    tests_require = ['pytest',
                     'pytest-cov',
                     'hypothesis']
    )
