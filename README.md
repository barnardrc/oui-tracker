# OUI Serial Enricher

A small Python command-line tool that reads authorized device observations from a serial connection and enriches MAC-address prefixes with organization names from a local OUI database.

## Why this exists

Hardware prototypes often emit newline-delimited JSON containing a device address but no human-readable manufacturer. This tool keeps the serial reader, record parser, locally administered address detection, OUI lookup, and privacy-conscious output in one testable script.

## Setup

```bash
python -m venv .venv
python -m pip install -r requirements.txt
```

Provide a CSV obtained from an authorized source. The loader expects `Mac Prefix` and `Vendor Name` columns. IEEE describes OUIs, now part of its MA-L product, and provides a public assignment listing on its [Registration Authority page](https://standards.ieee.org/products-programs/regauth/oui/). Review the data source's current terms before redistributing it.

The database is intentionally excluded from this repository:

```text
Mac Prefix,Vendor Name
00:11:22,Example Organization
```

## Usage

```bash
python oui_tracker.py --port COM4 --oui-db path/to/oui.csv
```

On Linux, the port may look like `/dev/ttyACM0`.

Full device addresses are redacted by default. Show them only when you have a legitimate need and an appropriate data-handling plan:

```bash
python oui_tracker.py --port COM4 --oui-db path/to/oui.csv --show-full-address
```

The tool accepts JSON objects and, for compatibility with older firmware, Python dictionary literals. A record should include `mac_address` and may include `vendor_oui` or `signal_mac_prefix`.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q oui_tracker.py
```

## Privacy and responsible use

MAC addresses and their observation times can become identifying or location-linked data. Use this tool only for equipment and networks you own or are explicitly authorized to assess. Collect the minimum data needed, avoid publishing raw addresses, secure any retained observations, and follow applicable law and policy.

## License

No open-source license has been selected. Until one is added, standard copyright applies.
