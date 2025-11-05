import functools
import threading
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


class TimeoutException(Exception):
    pass


def timeout(seconds: int | Callable[..., int]) -> Callable[[F], F]:
    """
    Decorator to enforce a timeout on function execution.

    The function runs in a daemon thread to prevent process exit issues.
    Note: The function will continue executing in the background even after
    timeout, but as a daemon thread it won't prevent process termination.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result: list[Any] = [None]
            exception: list[Exception | None] = [None]
            timeout_value = seconds(*args, **kwargs) if callable(seconds) else seconds

            def target() -> None:
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e

            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            thread.join(timeout_value)
            if thread.is_alive():
                raise TimeoutException(f"Function call exceeded {timeout_value} seconds")
            if exception[0]:
                raise exception[0]
            return result[0]

        return wrapper  # type: ignore[return-value]

    return decorator
