# -*- coding: utf-8 -*-

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

from xaptum.fsm.exceptions import (
    TerminatedError, UnsupportedEventError
)

from xaptum.fsm.events import (
    Events, Start, Terminated, Entry, Exit
)

class FSM(object):
    """A base class for a finite state machine.

    This class models an FSM as a mapping from a current state `s` and
    an input event `e` to a new state `s` and an output event `c`.

    Events are passed to the fsm using the `receive(self, event)`
    method. This will updated the state return the event, if any.

    Each state is defined by a method that takes the event, calls
    `become(self, new_state)` to transition to a new state, and returns the
    appropriate event.

    Alternatively, `delegate(self, child_fsm)` maybe used to enter a
    child fsm.  The child can exit by calling `terminate(self)`.  The
    parent state will receive an `events.Terminated` event to indicate
    that the child has terminated.

    Subclasses must implement the initial pseudo state `initial(self,
    event)`. This method should listen for the `fsm.START` event and
    transition into a new state.

    Each state will be called with the `fsm.ENTRY` event when
    transition into and the `fsm.EXIT` event when transitioned out of.

    The `unhandled(self, event)` should be called if a state method
    cannot handle the given event.

    Events must be subclass the `fsm.Event`.  Each subclass must
    specify a class attribute `kind` as an `IntEnum`.

    Example:
    class PingPongEvents(IntEnum):
        TICK = 20
        PING = 30
        PONG = 31

    class Tick(fsm.Event):
        kind = PingPongEvents.TICK

    class Ping(fsm.Event):
        kind = PingPongEvents.PING

    class Pong(fsm.Event):
        kind = PingPongEvents.PONG

    class PingPong(fsm.FSM):
        import PingPongEvents.TICK

        def initial(self, event):
            if event.kind == fsm.START:
                return self.become(self.ping)
            else:
                return self.unhandled(event):

        def ping(self, event):
            if event.kind == fsm.ENTRY:
                return Ping()
            elif event.kind == TICK:
                return self.become(self.pong)
            else:
                return self.unhandled(event):

        def pong(self, event):
            if event.kind == fsm.ENTRY:
                return Pong()
            elif event.kind == TICK:
                return self.become(self.ping)
            else:
                return self.unhandled(event)

    if __name__ == "__main__":
         example = PingPong()
         while True:
             event = example.receive(Tick())
             if event.kind == PingPongEvents.PING:
                 print "ping"
             elif event.kind == PingPongEvents.PONG:
                 print "pong"
             else:
                 print "invalid event"
                 break

    """

    def __init__(self, on_start=None):
        # current state is a transition function and, optionally,
        # a child fsm.
        self.current     = self.initial
        self.maybeChild  = None
        self.maybeParent = None
        self.on_start    = on_start

    def initial(self, event):
        """Initial pseudo-state.

        By convention, a `Start` event is sent to this pseudo-state to
        start the FSM. If an `on_start` state was specified at
        construction, it responds by transitioning into that state and
        returning a event.

        Instead of specifying an `on_start` state, subclasses may
        override this method instead.  For example, custom events may
        be used instead of `Start` to differentiate multiple starting
        behaviors.

        """
        if not self.on_start:
            raise NotImplementedError("The initial pseudo-state must be implemented by the `FSM` subclass.")

        if event.kind == Events.START:
            return self.become(self.on_start)
        else:
            return self.unhandled(event)

    def final(self, event):
        """Default terminal pseudo-state.

        Returns a `Terminated` event upon entry and the rejects all
        further events by raising `TerminatedError`.

        Subclasses may override for different behavior. For example,
        an FSM could auto-reset by immediately transitioning back to
        the `initial` pseudo-state.

        :returns: `Terminated` event upon entry
        :raises TerminatedError: on all other events

        """

        if event.kind == Events.ENTRY:
            return Terminated()
        else:
            raise TerminatedError(event)

    def receive(self, event):
        """Main input method to the FSM.

        Processes an input event and returns any resulting event.

        :returns: any resulting event from processing the event:
        :raises UnsupportedEventError: if the event could not be handled
        """
        if self.maybeChild:
            return self._receive_child(event)
        else:
            return self._receive_self(event)

    def unhandled(self, event):
        """Callback for state functions to indicate that the given event could
        not be handled.

        If the state machine is executing as a child, the event is
        passed back to the parent.  Otherwise, an
        `UnsupportedEventError` is raised.

        :returns: any resulting event from the parent
        :raises UnsupportedEventError: if the event could not be handled
        """
        if event.kind == Events.ENTRY:
            pass
        elif event.kind == Events.EXIT:
            pass
        elif self.maybeParent:
            return self.maybeParent._receive_self(event)
        else:
            raise UnsupportedEventError(event, self.current)

    def become(self, state):
        """Transitions to a new state, passing an `Entry` event to the new
        state.

        :returns: Any event returned by the new state in response to
        the `Entry` event.

        """

        if self.maybeChild:
            self._abort_child()

        self._exit()
        return self._enter(state)

    def delegate(self, child):
        """Transitions to a child fsm, passing a `Start` event to the child.

        :returns: Any event returned by the child in response to the
        `Start` event.

        """
        return self.delegate_with(child, Start())

    def delegate_with(self, child, event):
        """Transitions to a child fsm, passing the given event to the child.

        :returns: Any event returned by the child in response to the
        given event.

        """
        if self.maybeChild:
            self._abortChild()

        self.maybeChild = child
        self.maybeChild.maybeParent = self
        return self.maybeChild.receive(event)
    
    def terminate(self):
        """Transitions to the final state.

        :returns: Any event returned by the final state.
        """

        return self.become(self.final)
        
    def _receive_child(self, event):
        # Pass this event to the child and, if the child
        # terminates, notify our current state.
        ret = self.maybeChild.receive(event)
        if ret.kind == Events.TERMINATED:
            self.maybeChild = None
            return self._receive_self(ret)
        else:
            return ret

    def _receive_self(self, event):
        # Handle this event ourselves
        return self.current(event)

    def _enter(self, state):
        # Enter the given state
        self.current = state
        return self.current(Entry())

    def _exit(self):
        # Exit the current state
        self.current(Exit())
        self.current = None
    
    def _abort(self):
        # Exit the current state, calling any exit actions. Goto the
        # terminal state, but do not execute entry actions.
        if self.maybeChild:
            self._abort_child
        self.maybeParent = None
        self.current = self.final

    def _abort_child(self):
        self.maybeChild._abort()
        self.maybeChild = None

class StepMixin(object):
    """A mixin to succinctly define an `FSM` consisting of a series of
    sequential steps.

    Example:
    class MessageSender(fsm.FSM):

        def initial(self, event):
            if event.kind == fsm.START:
                return self.become(self.get_and_send_message)
            else:
                return self.unhandled(event)

        def get_and_send_message(self, event):
            if event.kind == fsm.ENTRY:
                self.init_step()
                return events.GetAddress()
            elif self.step(1, event.kind == event.GOT_ADDRESS):
                self.address = event.address
                return events.GetSubject()
            elif self.step(2, event.kind == event.GOT_SUBJECT):
                self.subject = event.subject
                return events.GetMessage()
            elif self.step(3, event.kind == event.GOT_MESSAGE):
                self.message = event.message
                self.service.send_to(self.address, self.subject, self.message)
                return self.terminate()
            else:
                return self.unhandled(event)

    As can be seen from the example, this mixin adds two methods to
    the class: `init_step()` and `step(num, guard)`.  The first
    initializes the step substate counter.  The second checks if both
    the step substate count matches the expected count and the guard
    expression is true.  If so, it also increments the step counter.

    """

    def init_step(self, guard):
        if guard:
            self._step = 0
            return True
        else:
            return False

    def step(self, num, guard):
        if num == self._step + 1 and guard:
            self._step += 1
            return True
        else:
            return False
