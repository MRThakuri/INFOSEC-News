import unittest
from datetime import datetime, timezone

from infosec_news import NewsItem, make_news_items, render_report


class NewsItemTests(unittest.TestCase):
    def test_only_high_and_critical_scored_cves_are_included(self):
        published = datetime(2026, 11, 6, 10, tzinfo=timezone.utc)
        entries = [
            ({"title": "Critical issue CVE-2026-1234", "link": "https://example.test/a"}, published, "Feed"),
            ({"title": "Medium issue CVE-2026-2345", "link": "https://example.test/b"}, published, "Feed"),
            ({"title": "Unscored issue CVE-2026-3456", "link": "https://example.test/c"}, published, "Feed"),
        ]

        items = make_news_items(entries, {
            "CVE-2026-1234": 9.8,
            "CVE-2026-2345": 6.9,
        })

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].severity, "Critical")

    def test_high_boundary_is_included_and_rendered(self):
        published = datetime(2026, 11, 6, 10, tzinfo=timezone.utc)
        entries = [
            ({"title": "Patch CVE-2026-1234", "link": "https://example.test/a"}, published, "Feed")
        ]

        items = make_news_items(entries, {"CVE-2026-1234": 7.0})
        report = render_report(items, datetime(2026, 11, 6, 12, tzinfo=timezone.utc))

        self.assertEqual(items[0].severity, "High")
        self.assertIn("CVSS 7.0", report)
        self.assertIn("https://example.test/a", report)

    def test_report_period_uses_requested_lookback(self):
        now = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)

        report = render_report([], now, hours=12)

        self.assertIn("2026-11-06 00:00 UTC to 2026-11-06 12:00 UTC", report)


if __name__ == "__main__":
    unittest.main()