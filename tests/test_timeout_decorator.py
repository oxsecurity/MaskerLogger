import threading
import time

import pytest

from maskerlogger.utils import TimeoutException, timeout


def test_timeout_creates_daemon_thread():
    thread_refs = []

    @timeout(1)
    def slow_function():
        thread_refs.append(threading.current_thread())
        time.sleep(0.1)
        return "completed"

    result = slow_function()
    assert result == "completed"
    assert len(thread_refs) == 1
    assert thread_refs[0].daemon is True


def test_timeout_raises_exception_when_exceeded():
    @timeout(1)
    def very_slow_function():
        time.sleep(5)
        return "should not reach here"

    with pytest.raises(TimeoutException) as exc_info:
        very_slow_function()
    assert "exceeded 1 seconds" in str(exc_info.value)


def test_timeout_with_callable_seconds():
    @timeout(lambda: 2)
    def function_with_dynamic_timeout():
        time.sleep(0.1)
        return "completed"

    result = function_with_dynamic_timeout()
    assert result == "completed"


def test_timeout_with_callable_seconds_exceeds():
    @timeout(lambda: 1)
    def slow_function_with_dynamic_timeout():
        time.sleep(5)
        return "should not reach here"

    with pytest.raises(TimeoutException):
        slow_function_with_dynamic_timeout()


def test_timeout_propagates_exceptions():
    @timeout(2)
    def function_that_raises():
        raise ValueError("Test exception")

    with pytest.raises(ValueError) as exc_info:
        function_that_raises()
    assert str(exc_info.value) == "Test exception"


def test_timeout_with_method_timeout():
    class TestClass:
        def __init__(self, timeout_value):
            self.timeout_value = timeout_value

        @timeout(lambda self: self.timeout_value)
        def method_with_timeout(self):
            time.sleep(0.1)
            return "completed"

    obj = TestClass(2)
    result = obj.method_with_timeout()
    assert result == "completed"


def test_timeout_creates_daemon_threads_that_dont_block_exit():
    active_threads_before = set(threading.enumerate())

    @timeout(1)
    def timed_out_function():
        time.sleep(5)

    for _ in range(3):
        try:
            timed_out_function()
        except TimeoutException:
            pass

    active_threads_after = set(threading.enumerate())
    new_threads = active_threads_after - active_threads_before

    for thread in new_threads:
        assert thread.daemon is True
