"""Moondancer board operations: LEDs, GPIO, USER button, board info, debug ring.

These operations only work while the Cynthion runs the *facedancer* gateware
with the Moondancer SoC firmware (USB 1d50:615b, interface subclass 0x20).

One dispatch function, :func:`apply_board_op`, is shared by:

* the in-process path (:func:`run_board_op` / :func:`open_board`), used when no
  facedancer emulation is running;
* the facedancer child process (``facedancer_worker`` imports
  :func:`apply_board_op` and applies ops to the board it already owns).

API notes, verified against the installed sources (cynthion 0.2.5, pygreat):

* ``cynthion.Cynthion()`` (cynthion/cynthion.py) caches the board in
  ``cynthion.cynthion.active_connections["TODO"]``; we clear it around each
  in-process use to avoid stale handles after re-enumeration.
* ``CynthionMoondancer`` (cynthion/boards/cynthion_moondancer.py): 6 LEDs in
  ``board.leds`` (dict 0..5 of ``cynthion.interfaces.led.LED`` with
  on/off/toggle), ``GPIO_MAPPINGS`` A1..A4, A7..A10 (port 0) and USER (2, 0).
* ``board.gpio`` exists only if ``board.supports_api("gpio")``
  (SIMPLE_CLASS_MAPPINGS); it is a ``cynthion.interfaces.gpio.GPIO``.
* ``GPIOProvider.release_pin()`` forces the pin back to *input*
  (``gpio_pin.set_direction(PinDirection.Input)``), so a written output pin
  must NOT be released. ``get_pin(name)`` (unique=False) returns the already
  active ``GPIOPin`` if one exists, so output pins simply stay registered in
  ``board.gpio.active_gpio``; we additionally keep them in ``_PINS``.
* ``GreatBoard.read_debug_ring(max_length=4096, clear=False, encoding='latin1')``.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from . import common
from .common import (
    ACTIVITY,
    HINT_FACEDANCER,
    InvalidArgumentError,
    NoDeviceError,
    stdout_to_stderr,
    translate_exception,
)

log = logging.getLogger("cynthion_mcp.board_io")

LED_COUNT = 6
LED_STATES = ("on", "off", "toggle")

# Fallback copy of CynthionMoondancer.GPIO_MAPPINGS (cynthion 0.2.5), used for
# validation/listing only when the board class does not expose it.
DEFAULT_GPIO_MAPPINGS: Dict[str, Tuple[int, int]] = {
    "A1": (0, 0), "A2": (0, 1), "A3": (0, 2), "A4": (0, 3),
    "A7": (0, 4), "A8": (0, 5), "A9": (0, 6), "A10": (0, 7),
    "USER": (2, 0),
}

# Output pins we keep registered (never released, because release_pin()
# would switch them back to input). Keyed by (id(board), pin name).
_PINS: Dict[Tuple[int, str], Any] = {}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

@contextlib.contextmanager
def _hw_lock() -> Iterator[None]:
    """Acquire the process-wide hardware lock from .common.

    Accepts either a ``hw_lock()`` context-manager factory or a bare
    ``HW_LOCK`` (threading.RLock) exported by common.
    """
    factory = getattr(common, "hw_lock", None)
    if callable(factory) and not hasattr(factory, "acquire"):
        with factory():
            yield
        return
    lock = factory if factory is not None else getattr(common, "HW_LOCK")
    with lock:
        yield


def _guard(fn: Callable[[], Any]) -> Any:
    """Call fn(); return None on any error (used for optional info fields)."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        log.debug("board info field failed: %s", exc)
        return None


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


def _gpio_mappings(board) -> Dict[str, Tuple[int, int]]:
    mappings = getattr(board, "GPIO_MAPPINGS", None)
    if isinstance(mappings, dict) and mappings:
        return dict(mappings)
    return dict(DEFAULT_GPIO_MAPPINGS)


def _require_gpio(board):
    gpio = getattr(board, "gpio", None)
    if gpio is None:
        err_cls = getattr(common, "UnsupportedError", InvalidArgumentError)
        err = err_cls("The connected Moondancer firmware does not expose the GPIO API.")
        err.hint = HINT_FACEDANCER
        raise err
    return gpio


def _known_pin_names(board) -> list:
    names = set(_gpio_mappings(board).keys())
    gpio = getattr(board, "gpio", None)
    if gpio is not None:
        names.update(getattr(gpio, "pin_mappings", {}).keys())
    return sorted(names, key=lambda n: (len(n), n))


def _normalize_pin(board, pin: Any) -> str:
    if not isinstance(pin, str) or not pin.strip():
        raise InvalidArgumentError(
            f"Invalid pin name: {pin!r}. Valid pins: "
            + ", ".join(_known_pin_names(board))
        )
    name = pin.strip().upper()
    if name not in _known_pin_names(board):
        raise InvalidArgumentError(
            f"Unknown pin: {pin!r}. Valid pins: "
            + ", ".join(_known_pin_names(board))
        )
    return name


def _get_pin(board, name: str):
    """Return the GPIOPin for name, reusing a cached/active one if present."""
    key = (id(board), name)
    cached = _PINS.get(key)
    if cached is not None:
        return cached
    gpio = _require_gpio(board)
    try:
        return gpio.get_pin(name)  # returns existing active pin if any
    except ValueError as exc:
        raise InvalidArgumentError(
            f"Pin {name} unavailable ({exc}). Valid pins: "
            + ", ".join(_known_pin_names(board))
        ) from exc


def _pin_direction():
    from cynthion.interfaces.gpio import PinDirection  # verified module path
    return PinDirection


def forget_board(board) -> None:
    """Drop cached pins for a board (call when the board is closed)."""
    bid = id(board)
    for key in [k for k in _PINS if k[0] == bid]:
        _PINS.pop(key, None)


# --------------------------------------------------------------------------
# op implementations
# --------------------------------------------------------------------------

def _op_info(board, op: dict) -> dict:
    apis = None
    comms = getattr(board, "comms", None)
    if comms is not None and hasattr(comms, "apis"):
        apis = _guard(lambda: sorted(comms.apis.keys()))
    if apis is None:
        apis = _guard(lambda: list(board.available_interfaces())) or []
    return {
        "board_name": _guard(board.board_name),
        "firmware_version": _guard(board.firmware_version),
        "serial": _to_jsonable(_guard(board.serial_number)),
        "part_id": _to_jsonable(_guard(board.part_id)),
        "board_id": _guard(board.board_id) if hasattr(board, "board_id") else None,
        "apis": apis,
        "interfaces": _guard(lambda: list(board.available_interfaces())) or [],
    }


def _op_led(board, op: dict) -> dict:
    index = op.get("index")
    state = str(op.get("state", "")).lower()
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < LED_COUNT:
        raise InvalidArgumentError(
            f"Invalid LED index: {index!r} (expected 0..{LED_COUNT - 1})."
        )
    if state not in LED_STATES:
        raise InvalidArgumentError(
            f"Invalid LED state: {state!r} (expected: on, off, toggle)."
        )
    leds = getattr(board, "leds", None)
    try:
        led = leds[index]  # type: ignore[index]
    except (KeyError, TypeError, IndexError) as exc:
        raise InvalidArgumentError(
            f"LED {index} not available on this board."
        ) from exc
    getattr(led, state)()
    return {"index": index, "state": state}


def _op_gpio_list(board, op: dict) -> dict:
    mappings = _gpio_mappings(board)
    gpio = getattr(board, "gpio", None)
    if gpio is not None:
        pins = list(gpio.get_available_pins(include_active=True))
        active = sorted(getattr(gpio, "active_gpio", {}).keys())
    else:
        pins, active = [], []
    return {
        "pins": pins,
        "active": active,
        "gpio_api": gpio is not None,
        "mapping": {name: {"port": line[0], "pin": line[1]}
                    for name, line in mappings.items()},
        "notes": "A1..A4, A7..A10 = PMOD A header; USER = user button/IO.",
    }


def _op_gpio_read(board, op: dict) -> dict:
    name = _normalize_pin(board, op.get("pin"))
    pin = _get_pin(board, name)
    try:
        try:
            PinDirection = _pin_direction()
            pin.set_direction(PinDirection.Input)
            value = bool(pin.read())
        except ImportError:
            value = bool(pin.input())
    finally:
        # Reading leaves the pin as input anyway; release_pin() sets it to
        # input too, so releasing is harmless here.
        _PINS.pop((id(board), name), None)
        with contextlib.suppress(Exception):
            board.gpio.release_pin(pin)
    return {"pin": name, "value": value}


def _op_gpio_write(board, op: dict) -> dict:
    name = _normalize_pin(board, op.get("pin"))
    if "value" not in op:
        raise InvalidArgumentError("Missing 'value' parameter for gpio_write.")
    value = bool(op.get("value"))
    pin = _get_pin(board, name)
    try:
        PinDirection = _pin_direction()
        pin.set_direction(PinDirection.Output, initial_value=value)
        pin.write(value)
    except ImportError:
        (pin.high if value else pin.low)()
    # Do NOT release: release_pin() would revert the pin to input.
    _PINS[(id(board), name)] = pin
    return {"pin": name, "value": value}


def _op_debug_ring(board, op: dict) -> dict:
    max_length = op.get("max_length", 4096)
    if isinstance(max_length, bool) or not isinstance(max_length, int) \
            or not 1 <= max_length < 65536:
        raise InvalidArgumentError(
            f"Invalid max_length: {max_length!r} (expected 1..65535)."
        )
    clear = bool(op.get("clear", False))
    text = board.read_debug_ring(max_length=max_length, clear=clear)
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("latin1", errors="replace")
    return {"text": text if text is not None else ""}


_OPS: Dict[str, Callable[[Any, dict], dict]] = {
    "info": _op_info,
    "led": _op_led,
    "gpio_list": _op_gpio_list,
    "gpio_read": _op_gpio_read,
    "gpio_write": _op_gpio_write,
    "debug_ring": _op_debug_ring,
}

SUPPORTED_OPS = tuple(_OPS)


def apply_board_op(board, op: dict) -> dict:
    """Apply one board op to an already-open Moondancer board.

    ``op`` is ``{"op": <name>, ...}`` with name in :data:`SUPPORTED_OPS`.
    Returns ``{"ok": True, **result}``; raises InvalidArgumentError for bad
    input. Hardware exceptions propagate (callers translate them).
    """
    if not isinstance(op, dict):
        raise InvalidArgumentError(f"Invalid operation: {op!r} (expected a dict).")
    name = op.get("op")
    handler = _OPS.get(name) if isinstance(name, str) else None
    if handler is None:
        raise InvalidArgumentError(
            f"Unknown board operation: {name!r}. Valid operations: "
            + ", ".join(SUPPORTED_OPS)
        )
    with stdout_to_stderr():
        result = handler(board, op)
    return {"ok": True, **result}


# --------------------------------------------------------------------------
# in-process path
# --------------------------------------------------------------------------

@contextlib.contextmanager
def open_board() -> Iterator[Any]:
    """Open the Moondancer board in-process under HW lock; always close it."""
    with _hw_lock(), stdout_to_stderr():
        try:
            import cynthion
            import cynthion.cynthion as cc
        except Exception as exc:  # noqa: BLE001
            raise translate_exception(exc) from exc

        cc.active_connections.clear()  # avoid a stale cached board
        try:
            board = cynthion.Cynthion()
            if board is None:
                raise NoDeviceError(
                    "No Moondancer board (facedancer gateware) detected.")
        except Exception as exc:  # noqa: BLE001
            err = translate_exception(exc)
            if isinstance(err, NoDeviceError):
                err.hint = HINT_FACEDANCER
            raise err from exc

        try:
            yield board
        finally:
            forget_board(board)
            with contextlib.suppress(Exception):
                board.close()
            cc.active_connections.clear()


def run_board_op(op: dict,
                 forward: Optional[Callable[[dict], dict]] = None) -> dict:
    """Run a board op, either via the facedancer worker or in-process.

    If ``forward`` is given (the server passes ``RUNNER.board_op`` while the
    facedancer child owns the board), the op is forwarded to it.
    Otherwise the analyzer capture must not be running and the board is
    opened in-process for this single op. Blocking: call from a worker thread.
    """
    if forward is not None:
        return {**forward(op), "via": "worker"}
    ACTIVITY.check_free()
    with open_board() as board:
        return {**apply_board_op(board, op), "via": "inprocess"}


__all__ = [
    "SUPPORTED_OPS",
    "LED_COUNT",
    "DEFAULT_GPIO_MAPPINGS",
    "apply_board_op",
    "open_board",
    "run_board_op",
    "forget_board",
]
