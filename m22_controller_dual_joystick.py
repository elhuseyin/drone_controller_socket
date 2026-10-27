"""
LYHFPV M22 experimental Windows Wi-Fi controller.

Replays the five UDP message types and their ordering observed in the user's
Android app captures. Both original and new joystick inputs are included.
This is a protocol experiment, NOT verified flight software.

Safety: remove propellers before testing. The DOWN state represents minimum
throttle and may stop motors. Neutral is NOT guaranteed to stabilize a flying
aircraft. Use this only for your own drone in a safe test environment.

Python 3 standard library only.  Usage:
    py m22_controller_dual_joystick.py
    py m22_controller_dual_joystick.py --dry-run
"""

import argparse
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

DRONE_IP = "192.168.0.1"
DRONE_PORT = 50000
SOURCE_PORT = 3000  # Android app's captured UDP source port
SEND_INTERVAL = 0.0412  # approx. 41 ms between packets in captures
MAX_CONTINUOUS_PRESS = 2.0  # safety timeout; release and press again


def packet(hexstr):
    return bytes.fromhex(hexstr)


# These are complete, exact UDP application payloads observed in the captures.
# Each state includes the control values as represented in the three variable
# packet types. The other two formats were identical in all three captures.
STATES = {
    "neutral": {
        "ff": packet("FF FD 0C 01 04 80 80 80 80 10 10 10 00 00 19"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 00 00 00 00 00 00 27 5A"),
        "66": packet("66 14 80 80 80 80 00 02 00 00 00 00 00 00 00 00 00 00 02 99"),
    },
    "up": {
        "ff": packet("FF FD 0C 01 04 FF 80 80 80 10 10 10 00 00 66"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 00 00 64 00 00 00 43 5A"),
        "66": packet("66 14 80 80 FF 80 00 02 00 00 00 00 00 00 00 00 00 00 7D 99"),
    },
    "down": {
        "ff": packet("FF FD 0C 01 04 03 80 80 80 10 10 10 00 00 9A"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 00 00 9F 00 00 00 B8 5A"),
        "66": packet("66 14 80 80 03 80 00 02 00 00 00 00 00 00 00 00 00 00 81 99"),
    },
    "left": {
        "ff": packet("FF FD 0C 01 04 8F 00 80 80 10 10 10 00 00 96"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 00 00 0D 9E 00 00 B4 5A"),
        "66": packet("66 14 80 80 8F 00 00 02 00 00 00 00 00 00 00 00 00 00 8D 99"),
    },
    # New right-hand joystick: forward/backward and sideways left/right.
    # Values are from the Android captures and are not independently flight-tested.
    "forward": {
        "ff": packet("FF FD 0C 01 04 80 80 FF 7C 10 10 10 00 00 9A"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 9C FE 00 00 00 00 45 5A"),
        "66": packet("66 14 7D BF 80 80 00 02 00 00 00 00 00 00 00 00 00 00 C0 99"),
    },
    # Captured backward-control state (mv backward.pcap).
    "backward": {
        "ff": packet("FF FD 0C 01 04 80 80 01 80 10 10 10 00 00 98"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 63 00 00 00 00 00 44 5A"),
        "66": packet("66 14 80 40 80 80 00 02 00 00 00 00 00 00 00 00 00 00 C2 99"),
    },
    "move_left": {
        "ff": packet("FF FD 0C 01 04 80 80 80 00 10 10 10 00 00 99"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 00 9C 00 00 00 00 BB 5A"),
        "66": packet("66 14 3F 80 80 80 00 02 00 00 00 00 00 00 00 00 00 00 BD 99"),
    },
    "move_right": {
        "ff": packet("FF FD 0C 01 04 80 80 80 FD 10 10 10 00 00 64"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 00 63 00 00 00 00 44 5A"),
        "66": packet("66 14 BE 7F 80 80 00 02 00 00 00 00 00 00 00 00 00 00 C3 99"),
    },
    "right": {
        "ff": packet("FF FD 0C 01 04 80 FD 80 80 10 10 10 00 00 64"),
        "a5": packet("A5 07 2B 03 00 28 5A A5 0C 2F 08 00 00 00 62 00 00 45 5A"),
        "66": packet("66 14 80 80 80 FD 00 02 00 00 00 00 00 00 00 00 00 00 7F 99"),
    },
}

BT = packet("42 54 3C 01 88 01 88 42 54 3C 01 89 01 89")
FF_HEARTBEAT = packet("46 46 3C 65 01 00 01 65")

# Exact observed 7-packet cycle, approximately 41 ms between packets:
# FF FD, A5, BT, FF, FF, 66, FF FD (the second FF FD belongs to
# the end of the preceding visual cycle; repeating this sequence matches).
MESSAGE_ORDER = ("ff", "a5", "bt", "heartbeat", "heartbeat", "66", "ff")


def verify_packets():
    """Fail early if any hand-transcribed captured payload is malformed."""
    for name, frames in STATES.items():
        ff, a5, p66 = frames["ff"], frames["a5"], frames["66"]
        assert len(ff) == 15 and len(a5) == 19 and len(p66) == 20, name
        assert ff[0:2] == b"\xff\xfd" and (0 ^ ff[0] ^ ff[1] ^ ff[2] ^ ff[3] ^ ff[4] ^ ff[5] ^ ff[6] ^ ff[7] ^ ff[8] ^ ff[9] ^ ff[10] ^ ff[11] ^ ff[12] ^ ff[13] ^ ff[14]) == 2, name
        assert a5[17] == (0x27 ^ a5[11] ^ a5[12] ^ a5[13] ^ a5[14]), name
        assert p66[18] == (0x02 ^ p66[2] ^ p66[3] ^ p66[4] ^ p66[5]), name


class DroneController:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.sock = None
        self.local_ip = "(dry run)"
        if not dry_run:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.sock.bind(("0.0.0.0", SOURCE_PORT))
            except OSError as e:
                self.sock.close()
                raise RuntimeError(
                    f"Cannot use UDP source port {SOURCE_PORT}: {e}. "
                    "Close the other app using it, then retry."
                ) from e
            # UDP connect sets a default address/route. There is NO network
            # handshake here; it does NOT prove the drone accepted anything.
            self.sock.connect((DRONE_IP, DRONE_PORT))
            self.local_ip = self.sock.getsockname()[0]
            if not self.local_ip.startswith("192.168.0."):
                self.sock.close()
                raise RuntimeError(
                    f"Wrong outgoing network ({self.local_ip}). "
                    "Connect Windows to the DRONE Wi-Fi before running."
                )

        self.lock = threading.Lock()
        self.state = "neutral"
        self.deadline = 0.0
        self.sent = 0
        self.last_error = None
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._send_loop, daemon=True)
        self.thread.start()

    def set_state(self, state):
        assert state in STATES
        with self.lock:
            self.state = state
            self.deadline = (time.monotonic() + MAX_CONTINUOUS_PRESS) if state != "neutral" else 0

    def current_state(self):
        with self.lock:
            if self.state != "neutral" and time.monotonic() >= self.deadline:
                self.state = "neutral"
            return self.state

    def _send_loop(self):
        next_send = time.monotonic()
        index = 0
        while not self.stop_event.is_set():
            state = self.current_state()
            kind = MESSAGE_ORDER[index]
            payload = (BT if kind == "bt" else FF_HEARTBEAT if kind == "heartbeat"
                       else STATES[state][kind])
            try:
                if not self.dry_run:
                    self.sock.send(payload)
                self.sent += 1
            except OSError as e:
                self.last_error = str(e)
                self.stop_event.set()
                break
            index = (index + 1) % len(MESSAGE_ORDER)
            next_send += SEND_INTERVAL
            self.stop_event.wait(max(0, next_send - time.monotonic()))
            if next_send < time.monotonic() - 0.5:
                next_send = time.monotonic()  # avoid a burst after a slow stall

    def close(self):
        self.set_state("neutral")
        if not self.dry_run:
            time.sleep(0.33)  # attempt to transmit multiple neutral frames
        self.stop_event.set()
        self.thread.join(timeout=2)
        if self.sock:
            self.sock.close()


def main():
    ap = argparse.ArgumentParser(description="M22 experimental TCP-free UDP controller")
    ap.add_argument("--dry-run", action="store_true", help="GUI demo, do not send packets")
    args = ap.parse_args()
    verify_packets()

    try:
        controller = DroneController(dry_run=args.dry_run)
    except RuntimeError as exc:
        print("ERROR:", exc)
        return

    window = tk.Tk()
    window.title("LYHFPV M22 - two-joystick UDP controller")
    window.geometry("900x430")
    window.minsize(810, 420)
    frame = ttk.Frame(window, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="M22 Wi-Fi UDP Controller", font=("Segoe UI", 17, "bold")).pack(anchor="w")
    ttk.Label(
        frame,
        text=f"Drone {DRONE_IP}:{DRONE_PORT}  |  Your IP {controller.local_ip}  |  source port {SOURCE_PORT}",
    ).pack(anchor="w", pady=(5, 8))
    

    status = tk.StringVar(value="Sending: NEUTRAL")
    sent_label = tk.StringVar(value="Packets sent: 0")

    def set_state(state):
        controller.set_state(state)
        status.set("Sending: " + state.upper())

    def make_control(parent, label, state, r, c):
        widget = ttk.Button(parent, text=label, width=15)
        widget.grid(row=r, column=c, padx=4, pady=5)
        widget.bind("<ButtonPress-1>", lambda event: set_state(state))
        widget.bind("<ButtonRelease-1>", lambda event: set_state("neutral"))
        return widget

    sticks = ttk.Frame(frame)
    sticks.pack(fill="x", pady=6)

    # Original left joystick: keep existing commands and keys unchanged.
    left_stick = ttk.LabelFrame(sticks, text="Left-hand joystick", padding=10)
    left_stick.pack(side="left", fill="both", expand=True, padx=(0, 5))
    make_control(left_stick, "UP (W / ↑)", "up", 0, 1)
    make_control(left_stick, "LEFT (A / ←)", "left", 1, 0)
    make_control(left_stick, "RIGHT (D / →)", "right", 1, 2)
    make_control(left_stick, "DOWN* (S / ↓)", "down", 2, 1)

    # New right joystick: independent forward/backward and lateral states.
    right_stick = ttk.LabelFrame(sticks, text="Right-hand joystick", padding=10)
    right_stick.pack(side="left", fill="both", expand=True, padx=(5, 0))
    make_control(right_stick, "FORWARD (F)", "forward", 0, 1)
    make_control(right_stick, "MOVE LEFT (Q)", "move_left", 1, 0)
    make_control(right_stick, "MOVE RIGHT (E)", "move_right", 1, 2)
    make_control(right_stick, "BACKWARD (B)", "backward", 2, 1)

    ttk.Button(
        frame,
        text="NEUTRAL (SPACE / ESC)",
        command=lambda: set_state("neutral"),
        width=32,
    ).pack(pady=(2, 8))

    key_to_state = {
        "w": "up", "up": "up", "a": "left", "left": "left",
        "s": "down", "down": "down", "d": "right", "right": "right",
        "f": "forward", "b": "backward", "q": "move_left", "e": "move_right",
    }

    def key_press(event):
        key = event.keysym.lower()
        if key in key_to_state:
            set_state(key_to_state[key])
        elif key in ("space", "escape"):
            set_state("neutral")

    def key_release(event):
        if event.keysym.lower() in key_to_state:
            set_state("neutral")

    window.bind("<KeyPress>", key_press)
    window.bind("<KeyRelease>", key_release)
    window.bind("<FocusOut>", lambda event: set_state("neutral"))
    ttk.Label(frame, textvariable=status, font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(2, 3))
    ttk.Label(frame, textvariable=sent_label).pack(anchor="w")
    

    def refresh():
        state = controller.current_state()
        status.set("Sending: " + state.upper())
        sent_label.set(f"{'Simulated' if args.dry_run else 'Packets sent'}: {controller.sent}")
        if controller.last_error:
            messagebox.showerror("UDP error", controller.last_error)
            close()
            return
        window.after(100, refresh)

    closing = False

    def close():
        nonlocal closing
        if closing:
            return
        closing = True
        controller.close()
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", close)
    window.after(100, refresh)
    window.mainloop()


if __name__ == "__main__":
    main()
