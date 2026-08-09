"""Progress indicators for long-running operations."""

import sys
import time
import threading
from typing import Optional


class Spinner:
    """Simple spinner for long-running operations."""

    FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def __init__(self, message: str, color_code: str = '\033[36m'):
        """Initialize spinner.

        Args:
            message: Display message
            color_code: ANSI color code (default: cyan)
        """
        self.message = message
        self.color_code = color_code
        self.reset_code = '\033[0m'
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Start the spinner animation."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def _animate(self):
        """Animation loop."""
        frame_idx = 0
        while self.running:
            frame = self.FRAMES[frame_idx % len(self.FRAMES)]
            sys.stdout.write(f"\r{self.color_code}[{frame}]{self.reset_code} {self.message}")
            sys.stdout.flush()
            frame_idx += 1
            time.sleep(0.1)

    def stop(self, success: bool = True, final_message: Optional[str] = None):
        """Stop spinner and print result.

        Args:
            success: Whether operation succeeded (shows ✓ or ✗)
            final_message: Optional custom message to display
        """
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

        symbol = '\033[32m[✓]\033[0m' if success else '\033[31m[✗]\033[0m'
        msg = final_message or self.message
        sys.stdout.write(f"\r{symbol} {msg}\n")
        sys.stdout.flush()


class ProgressBar:
    """Simple progress bar for tracking completion."""

    def __init__(self, total: int, width: int = 30):
        """Initialize progress bar.

        Args:
            total: Total number of items
            width: Bar width in characters
        """
        self.total = total
        self.current = 0
        self.width = width

    def update(self, current: int, label: str = ""):
        """Update progress bar.

        Args:
            current: Current progress (0 to total)
            label: Optional label to display
        """
        self.current = min(current, self.total)
        percent = self.current / self.total if self.total > 0 else 0
        filled = int(self.width * percent)
        bar = '█' * filled + '░' * (self.width - filled)
        pct_str = f"{percent*100:.0f}%"

        msg = f"[{bar}] {pct_str}"
        if label:
            msg = f"{label}: {msg}"

        sys.stdout.write(f"\r{msg}")
        sys.stdout.flush()

    def finish(self):
        """Mark progress bar as complete."""
        sys.stdout.write("\n")
        sys.stdout.flush()
