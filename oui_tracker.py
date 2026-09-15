"""Enrich authorized serial observations with OUI organization names."""

import argparse
import ast
import csv
import json
import re
import time
from pathlib import Path


HEX_PAIR = re.compile(r"[0-9A-Fa-f]{2}")


def parse_record(raw_line):
    """Parse a JSON object, with Python-literal input retained for older firmware."""
    try:
        parsed = json.loads(raw_line)
    except json.JSONDecodeError:
        try:
            parsed = ast.literal_eval(raw_line)
        except (SyntaxError, ValueError):
            return None
    return parsed if isinstance(parsed, dict) else None


def get_oui(address):
    """Return an uppercase three-octet OUI, excluding locally administered IDs."""
    if not isinstance(address, str):
        return None

    octets = HEX_PAIR.findall(address)
    if len(octets) < 3:
        return None

    first_octet = int(octets[0], 16)
    if first_octet & 0x02:
        return None

    return ":".join(octet.upper() for octet in octets[:3])


def redact_address(address):
    """Hide the device-specific half of a MAC address for safer console output."""
    octets = HEX_PAIR.findall(address or "")
    if len(octets) < 6:
        return "<invalid>"
    return ":".join([*(octet.upper() for octet in octets[:3]), "XX", "XX", "XX"])


def load_lookup(csv_path, key_col="Mac Prefix", value_col="Vendor Name"):
    lookup = {}
    with Path(csv_path).open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or key_col not in reader.fieldnames or value_col not in reader.fieldnames:
            raise ValueError(f"Expected CSV columns {key_col!r} and {value_col!r}")
        for row in reader:
            oui = get_oui(row.get(key_col))
            vendor = (row.get(value_col) or "").strip()
            if oui and vendor:
                lookup[oui] = vendor
    return lookup


def enrich_record(record, lookup):
    mac = record.get("mac_address")
    if not isinstance(mac, str):
        return None

    vendor_address = record.get("vendor_oui") or record.get("signal_mac_prefix") or mac
    oui = get_oui(vendor_address)
    return {
        "mac": mac,
        "oui": oui,
        "organization": lookup.get(oui) if oui else None,
    }


def build_parser():
    parser = argparse.ArgumentParser(
        description="Enrich authorized serial MAC observations with OUI organization names."
    )
    parser.add_argument("--port", required=True, help="Serial port, for example COM4 or /dev/ttyACM0.")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--oui-db", type=Path, default=Path("oui.csv"))
    parser.add_argument(
        "--show-full-address",
        action="store_true",
        help="Print full device addresses instead of redacting their final three octets.",
    )
    return parser


def main():
    args = build_parser().parse_args()

    try:
        import serial
    except ImportError as exc:
        raise SystemExit("Install dependencies with: python -m pip install -r requirements.txt") from exc

    try:
        lookup = load_lookup(args.oui_db)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Could not load OUI database: {exc}") from exc

    print(f"Loaded {len(lookup):,} OUI records.")
    known_macs = set()

    try:
        with serial.Serial(args.port, args.baud, timeout=1) as connection:
            print(f"Connected to {args.port} at {args.baud} baud.")
            connection.reset_input_buffer()

            while True:
                if connection.in_waiting:
                    raw_line = connection.readline().decode("utf-8", errors="ignore").strip()
                    record = parse_record(raw_line)
                    detection = enrich_record(record, lookup) if record else None
                    if detection and detection["mac"] not in known_macs:
                        known_macs.add(detection["mac"])
                        address = (
                            detection["mac"]
                            if args.show_full_address
                            else redact_address(detection["mac"])
                        )
                        print(
                            f"New observation: address={address} "
                            f"oui={detection['oui'] or 'locally-administered/unknown'} "
                            f"organization={detection['organization'] or 'unknown'}"
                        )
                time.sleep(0.01)
    except serial.SerialException as exc:
        raise SystemExit(f"Serial connection failed: {exc}") from exc
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
