# examples/meshcore_simulator.py
"""
Simple Meshcore Serial Device Simulator.
"""

import json
import random
import threading
import time

import serial

SIMULATOR_PORT = "/dev/ttyS1"
BAUD_RATE = 9600
SEND_PERIODIC_SENSOR_DATA = True
SENSOR_INTERVAL_S = 15

shutdown_event = threading.Event()
serial_port = None


def serial_reader():
    print("[Reader] Serial reader thread started.")
    while not shutdown_event.is_set():
        if serial_port and serial_port.is_open:
            try:
                if serial_port.in_waiting > 0:
                    line = serial_port.readline()
                    if line:
                        try:
                            decoded_line = line.decode("utf-8").strip()
                            print(
                                "[Reader] <<< Received: %s" % decoded_line
                            )
                        except UnicodeDecodeError:
                            print(
                                "[Reader] <<< Received non-UTF8 data: %r"
                                % (line,)
                            )
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(
                    f"\n[Reader] Error: {e}"
                )
                time.sleep(1)
        else:
            time.sleep(1)


def periodic_sender():
    print("[Periodic Sender] Started.")
    while not shutdown_event.is_set():
        if serial_port and serial_port.is_open:
            try:
                sensor_value = round(20 + random.uniform(-2, 2), 2)
                message = {
                    "destination_meshtastic_id": "!aabbccdd",
                    "payload_json": {"type": "temp", "val": sensor_value},
                }
                message_str = json.dumps(message) + "\n"
                print(
                    f"\n[Sender] >>> {message_str.strip()}"
                )
                serial_port.write(message_str.encode("utf-8"))
            except Exception as e:
                print(
                    f"\n[Sender] Error: {e}"
                )
        shutdown_event.wait(SENSOR_INTERVAL_S)


def main():
    global serial_port
    print("--- Meshcore Simulator ---")
    reader = threading.Thread(target=serial_reader, daemon=True)
    reader.start()
    if SEND_PERIODIC_SENSOR_DATA:
        sender = threading.Thread(target=periodic_sender, daemon=True)
        sender.start()

    while not shutdown_event.is_set():
        if not serial_port or not serial_port.is_open:
            try:
                serial_port = serial.Serial(
                    SIMULATOR_PORT, BAUD_RATE, timeout=0.5
                )
                print(f"[Main] Opened {SIMULATOR_PORT}")
            except Exception:
                time.sleep(5)
                continue
        try:
            user_input = input()
            if user_input:
                msg = user_input.encode("utf-8") + b"\n"
                serial_port.write(msg)
        except KeyboardInterrupt:
            break

    shutdown_event.set()
    if serial_port:
        serial_port.close()


if __name__ == "__main__":
    main()
