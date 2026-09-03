import unittest

from cerulean_integration.hosts import parse_hosts


class ParseHostsTest(unittest.TestCase):
    def test_preferred_format(self):
        entries = parse_hosts("app 3000\ntv 3001 yes\napi 8001 true\n")
        self.assertEqual(
            [(e.subdomain, e.port, e.websockets) for e in entries],
            [("app", 3000, False), ("tv", 3001, True), ("api", 8001, True)],
        )

    def test_legacy_format_with_target(self):
        entries = parse_hosts("app homarr 7575 yes\nmedia jellyfin 8096\n")
        self.assertEqual(
            [(e.subdomain, e.port, e.websockets, e.target) for e in entries],
            [("app", 7575, True, "homarr"), ("media", 8096, False, "jellyfin")],
        )

    def test_comments_and_blank_lines_ignored(self):
        text = """
# header comment
app 3000

# another comment
tv  3001  yes
"""
        entries = parse_hosts(text)
        self.assertEqual([e.subdomain for e in entries], ["app", "tv"])

    def test_inline_comment_stripped(self):
        entries = parse_hosts("app 3000 # the dashboard")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].subdomain, "app")

    def test_subdomain_lowercased(self):
        entries = parse_hosts("App.Media 3000")
        self.assertEqual(entries[0].subdomain, "app.media")

    def test_invalid_subdomain(self):
        with self.assertRaises(ValueError):
            parse_hosts("bad_sub! 3000")

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_hosts("app notaport")

    def test_port_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_hosts("app 70000")

    def test_legacy_missing_port(self):
        with self.assertRaises(ValueError):
            parse_hosts("app homarr")

    def test_empty_file(self):
        with self.assertRaises(ValueError):
            parse_hosts("# nothing here\n\n")


if __name__ == "__main__":
    unittest.main()