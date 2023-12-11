import ctypes as ct

BLACK = "\033[0;30m"
DARK_GRAY = "\033[1;30m"
RED = "\033[0;31m"
BOLD_RED = "\033[1;31m"
GREEN = "\033[0;32m"
BOLD_GREEN = "\033[1;32m"
YELLOW = "\033[0;33m"
BOLD_YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
BOLD_BLUE = "\033[1;34m"
PURPLE = "\033[0;35m"
BOLD_PURPLE = "\033[1;35m"
CYAN = "\033[0;36m"
BOLD_CYAN = "\033[1;36m"
LIGHT_GRAY = "\033[0;37m"
WHITE = "\033[1;37m"

END = "\033[0m"  # Reset to default


def printx(text: str, type: str):
    """
    Prints text with a color based on type
    Types:
        info,
        warn,
        err,
        ok,
        debug
    Default type is info
    """
    match type:
        case "info":
            print(f"{BLUE}[INFO]{END}: {text}")
        case "warn":
            print(f"{YELLOW}[WARN]{END}: {text}")
        case "err":
            print(f"{RED}[ERR]{END}: {text}")
        case "ok":
            print(f"{GREEN}[OK]{END}: {text}")
        case "debug":
            print(f"{CYAN}[DEBUG]{END}: {text}")
        case _:
            print(f"{BLUE}[INFO]{END}: {text}")


class Addr(ct.Union):
    _fields_ = [
        ("v4", ct.c_uint32),
        ("v6", ct.c_uint32 * 4),
    ]


class Data(ct.Structure):
    _fields_ = [
        ("real_src", Addr),
        ("src", Addr),
        ("dst", Addr),
        ("protocol", ct.c_uint8),
        ("action", ct.c_uint8),
        ("rc", ct.c_uint16),
        ("timestamp", ct.c_uint64),
    ]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print(
        f"real_src: {list(event.real_src.v6)} src: {event.src.v4} dst: {event.dst.v4} rc: {event.rc} protocol: {event.protocol} action: {event.action}"
    )
