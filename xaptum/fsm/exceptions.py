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

class FSMError(ValueError):
    """The state machine was improperly configured or used.
    
    """

class TerminatedError(FSMError):
    """The state machine is in a terminal state and cannot process new
    events.

    :param Event event: The event that could not be processed.

    """

    def __init__(self, event):
        message = "Cannot process event <%s> in terminal state"%(event.name)
        super(TerminatedError, self).__init__(message)
        self.event = event

class UnsupportedEventError(FSMError):
    """The current state does not support this event.

    :param Event event: The event that could not processed.
    :param func state: The state that could not process the event

    """

    def __init__(self, event, state):
        message = "Event <%s> not supported in state <%s>"%(event.name,
                                                            state.__name__)
        super(UnsupportedEventError, self).__init__(message)
        self.event = event
        self.state = state
