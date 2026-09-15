import tempfile
import unittest
from pathlib import Path

from oui_tracker import enrich_record, get_oui, load_lookup, parse_record, redact_address


class OuiTrackerTests(unittest.TestCase):
    def test_parse_json_and_legacy_dictionary(self):
        self.assertEqual(parse_record('{"mac_address": "00:11:22:33:44:55"}')["mac_address"], "00:11:22:33:44:55")
        self.assertEqual(parse_record("{'mac_address': '00:11:22:33:44:55'}")["mac_address"], "00:11:22:33:44:55")
        self.assertIsNone(parse_record("not a record"))

    def test_oui_excludes_locally_administered_addresses(self):
        self.assertEqual(get_oui("00:11:22:33:44:55"), "00:11:22")
        self.assertIsNone(get_oui("02:11:22:33:44:55"))

    def test_addresses_are_redacted_by_default_helper(self):
        self.assertEqual(redact_address("00:11:22:33:44:55"), "00:11:22:XX:XX:XX")

    def test_load_and_enrich(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oui.csv"
            path.write_text("Mac Prefix,Vendor Name\n00:11:22,Example Organization\n", encoding="utf-8")
            lookup = load_lookup(path)

        detection = enrich_record({"mac_address": "00:11:22:33:44:55"}, lookup)
        self.assertEqual(detection["organization"], "Example Organization")


if __name__ == "__main__":
    unittest.main()
