"""
GHOSTTOOTH — local scanner bridge for the ghosttooth webpage.
(Gathering Hidden Objects through Signal Tracking and Telemetry
Observation of Operational Tracker Hardware)

Chromium's Web Bluetooth passive scanning (requestLEScan) does not start
radio discovery on Windows. This bridge performs the native BLE scan
(same Windows WinRT APIs, via bleak) and exposes the results as JSON on
ws://127.0.0.1:8437.

Why WebSocket instead of HTTP?
Chrome 130+ blocks fetch() from public https:// origins to loopback
addresses (Private Network Access policy) before even checking CORS
headers. WebSocket connections are not subject to that restriction yet.

Usage:
    pip install bleak websockets
    python bt-bridge.py

Then open the GHOSTTOOTH webpage and click [ START SCAN ] — it connects
to this bridge automatically.

Security: binds to 127.0.0.1 only (never exposed to the network).
"""

import asyncio
import json
import threading
import time

from bleak import BleakScanner

try:
    from websockets.asyncio.server import serve
    from websockets.http11 import Response
    from websockets.datastructures import Headers
except ImportError:
    raise SystemExit("Install the required library: pip install websockets")

PORT = 8437
STALE_AFTER_S = 900         # drop devices not seen for this long (page owns staleness UX)
PRUNE_INTERVAL_S = 5

devices = {}
lock = threading.Lock()

# CORS + Chrome Private Network Access headers
_CORS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET, OPTIONS"),
    ("Access-Control-Allow-Headers", "*"),
    ("Access-Control-Allow-Private-Network", "true"),
    ("Cache-Control", "no-store"),
]


def _http_response(status, reason, extra=(), body=b""):
    headers = Headers([*_CORS, ("Content-Length", str(len(body))), *extra])
    return Response(status, reason, headers, body)


# ---- BLE scanner -----------------------------------------------------------

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


# ---- WebSocket server ------------------------------------------------------

async def process_request(connection, request):
    """Handle plain HTTP GET requests that arrive on the WebSocket port.

    Note: the websockets handshake parser only accepts the GET method (any
    other method raises a parse error before this callback runs), so no
    method check is needed or possible here — only the Upgrade header
    distinguishes a WebSocket handshake from a plain HTTP GET.
    """
    if not request.headers.get("Upgrade"):
        # Plain HTTP GET — return device list for backward compatibility
        with lock:
            body = json.dumps({"devices": list(devices.values())}).encode()
        return _http_response(200, "OK", [("Content-Type", "application/json")], body)

    return None  # proceed with WebSocket upgrade


async def ws_handler(ws):
    """Push the full device list to a connected client every 2 seconds."""
    print("Bridge: client connected.")
    try:
        while True:
            with lock:
                payload = json.dumps({"devices": list(devices.values())})
            await ws.send(payload)
            await asyncio.sleep(2)
    except Exception as exc:
        print(f"Bridge: client disconnected ({exc!r}).")


# ---- Main ------------------------------------------------------------------

async def run():
    scanner = BleakScanner(on_advertisement)
    await scanner.start()
    print(f"GHOSTTOOTH BLE scan running. Bridge on ws://127.0.0.1:{PORT}")
    print("Open the GHOSTTOOTH webpage and click [ START SCAN ]. Ctrl+C to quit.")

    # Browsers do not enforce CORS/Private Network Access on the WebSocket
    # handshake response the way they do for fetch(), so no extra headers
    # are needed here for the upgrade itself (process_request still adds
    # them for the plain-HTTP fallback path).
    #
    # ping_interval=None disables the library's automatic keepalive pings.
    # The BLE scan callback (on_advertisement) runs on the same event loop
    # as the WebSocket server, and native Windows BLE scanning via bleak can
    # briefly block the loop; if a pong reply is delayed past ping_timeout
    # (default 20s), the server closes the connection with "keepalive ping
    # timeout" even though the bridge is perfectly healthy. The 2-second
    # device-list push already acts as an application-level heartbeat, so
    # ping/pong keepalive is not needed here.
    async with serve(
        ws_handler,
        "127.0.0.1",
        PORT,
        process_request=process_request,
        ping_interval=None,
    ):
        while True:
            await asyncio.sleep(PRUNE_INTERVAL_S)
            cutoff = time.time() - STALE_AFTER_S
            with lock:
                for addr in [a for a, d in devices.items() if d["last_seen"] < cutoff]:
                    del devices[addr]


def main():
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nBridge stopped.")


if __name__ == "__main__":
    main()
