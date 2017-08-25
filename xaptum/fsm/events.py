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

class Events(IntEnum):
    """Enumeration of the framework FSM events.

    `IntEnum` is not inheritable, so user events must be declared in a
    different `IntEnum`.  The numbers 0 to 19 are reserved for framework
    events.

    """

    START      = 1
    TERMINATED = 2
    ENTRY      = 3
    EXIT       = 4

class Event(object):
    """Base class for FSM events.

    User defined events must extend this class and set the `kind`
    class attribute to a valid `IntEnum`.

    """

    kind = None

    @property
    def name(self):
        return self.__class__.__name__

class Start(Event):
    """The default first event sent to an `FSM`. The `initial`
    pseudo-state should transition to the first true state upon this
    event.

    Users may define a different start event and use it instead.

    """
    kind = Events.START

class Terminated(Event):
    """The event returned when the FSM has entered a terminal state.

    """
    kind = Events.TERMINATED
    
class Entry(Event):
    """The event sent to a state when transitioning into the
    state. States should perform any entry actions in response to this
    event. This will often include returning a command.

    """
    kind = Events.ENTRY

class Exit(Event):
    """The event sent to a state when transitioning out of the
    state. States should perform any exit actions in response to this
    event.  Exit actions will usually not return a command.

    """
    kind = Events.EXIT
