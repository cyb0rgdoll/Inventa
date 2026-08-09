"""ANSI color codes for terminal output."""

RED     = '\033[0;31m'
GREEN   = '\033[0;32m'
YELLOW  = '\033[1;33m'
BLUE    = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN    = '\033[0;36m'
WHITE   = '\033[1;37m'
GRAY    = '\033[0;90m'
BOLD    = '\033[1m'
DIM     = '\033[2m'
RESET   = '\033[0m'


def color(text: str, color_code: str, bold: bool = False) -> str:
    """Apply color to text."""
    prefix = f"{BOLD}{color_code}" if bold else color_code
    return f"{prefix}{text}{RESET}"


def success(text: str) -> str:
    return f"{GREEN}[✓]{RESET} {text}"


def error(text: str) -> str:
    return f"{RED}[✗]{RESET} {text}"


def info(text: str) -> str:
    return f"{CYAN}[i]{RESET} {text}"


def warn(text: str) -> str:
    return f"{YELLOW}[!]{RESET} {text}"


def prompt(text: str) -> str:
    return f"{GRAY}[?]{RESET} {text}"
