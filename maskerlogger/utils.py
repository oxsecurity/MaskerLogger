import functools
import threading
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


class TimeoutException(Exception):
    pass


def timeout(seconds: int | Callable[..., int]) -> Callable[[F], F]:
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result: list[Any] = [None]
            timeout_value = seconds(*args, **kwargs) if callable(seconds) else seconds

            def target() -> None:
                result[0] = func(*args, **kwargs)

            thread = threading.Thread(target=target)
            thread.start()
            thread.join(timeout_value)
            if thread.is_alive():
                raise TimeoutException(f"Function call exceeded {timeout_value} seconds")
            return result[0]

        return wrapper  # type: ignore[return-value]

    return decorator
