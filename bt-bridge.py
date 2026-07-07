"""
GHOSTTOOTH — local scanner bridge for the ghosttooth webpage.
(Gathering Hidden Objects through Signal Tracking and Telemetry
Observation of Operational Tracker Hardware)

Chromium's Web Bluetooth passive scanning (requestLEScan) does not start
radio discovery on Windows. This bridge performs the native BLE scan
(same Windows WinRT APIs, via bleak) and exposes the results as JSON on
http://127.0.0.1:8437/api/devices so the webpage can display them live.

Usage:
    pip install bleak
    python bt-bridge.py

Then open the BT Scanner webpage and click [ START SCAN ] — it connects
to this bridge automatically.

Security: binds to 127.0.0.1 only (never exposed to the network).
"""

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bleak import BleakScanner

PORT = 8437
STALE_AFTER_S = 900         # drop devices not seen for this long (page owns staleness UX)
PRUNE_INTERVAL_S = 5

devices = {}
lock = threading.Lock()


def on_advertisement(device, adv):
    with lock:
        devices[device.address] = {
            "address": device.address,
            "name": adv.local_name or device.name or None,
            "rssi": adv.rssi,
            "tx_power": adv.tx_power,
            "manufacturer_ids": list(adv.manufacturer_data.keys()),
            "uuids": [u.lower() for u in adv.service_uuids],
            "last_seen": time.time(),
        }


async def scan_loop():
    scanner = BleakScanner(on_advertisement)
    await scanner.start()
    print(f"GHOSTTOOTH BLE scan running. Bridge serving on http://127.0.0.1:{PORT}")
    print("Open the GHOSTTOOTH webpage and click [ START SCAN ]. Ctrl+C to quit.")
    while True:
        await asyncio.sleep(PRUNE_INTERVAL_S)
        cutoff = time.time() - STALE_AFTER_S
        with lock:
            for addr in [a for a, d in devices.items() if d["last_seen"] < cutoff]:
                del devices[addr]


class Handler(BaseHTTPRequestHandler):
    def _send_headers(self, code=200, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # CORS + Chrome Private Network Access, so https pages may call localhost
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_OPTIONS(self):
        self._send_headers(204)

    def do_GET(self):
        if self.path == "/api/devices":
            with lock:
                payload = json.dumps({"devices": list(devices.values())})
            self._send_headers()
            self.wfile.write(payload.encode("utf-8"))
        else:
            self._send_headers(200, "text/plain; charset=utf-8")
            self.wfile.write(b"GHOSTTOOTH bridge running. Endpoint: /api/devices\n")

    def log_message(self, *args):
        pass  # keep the console quiet


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        asyncio.run(scan_loop())
    except KeyboardInterrupt:
        print("\nBridge stopped.")


if __name__ == "__main__":
    main()
