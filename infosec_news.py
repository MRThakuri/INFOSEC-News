import argparse
import calendar
import os
import re
import smtplib
import ssl
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Iterable

import feedparser
import requests


DEFAULT_FEEDS = (
    "https://www.securityweek.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.nist.gov/news-events/cybersecurity/rss.xml",
)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(frozen=True)
class NewsItem:
    title: str
    url: str
    source: str
    published: datetime
    cves: tuple[str, ...]
    score: float

    @property
    def severity(self) -> str:
        return "Critical" if self.score >= 9.0 else "High"


def entry_datetime(entry: dict) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        value = entry.get(key)
        if value:
            return datetime.fromtimestamp(calendar.timegm(value), timezone.utc)
    return None


def collect_recent_entries(
    feed_urls: Iterable[str], cutoff: datetime, session: requests.Session
) -> list[tuple[dict, datetime, str]]:
    recent = []
    for feed_url in feed_urls:
        try:
            response = session.get(feed_url, timeout=15)
            response.raise_for_status()
            parsed = feedparser.parse(response.content)
        except requests.RequestException as error:
            print(f"Warning: could not read feed {feed_url}: {error}", file=sys.stderr)
            continue
        if parsed.bozo and not parsed.entries:
            print(f"Warning: could not read feed {feed_url}", file=sys.stderr)
            continue
        for entry in parsed.entries:
            published = entry_datetime(entry)
            if published is None or published < cutoff:
                continue
            recent.append((entry, published, feed_url))
    return recent


def extract_cves(entries: Iterable[tuple[dict, datetime, str]]) -> list[str]:
    return sorted({
        cve.upper()
        for entry, _, _ in entries
        for cve in CVE_PATTERN.findall(
            f"{entry.get('title', '')} {entry.get('summary', '')}"
        )
    })


def nvd_scores(cves: Iterable[str], session: requests.Session) -> dict[str, float]:
    cve_list = list(cves)
    scores = {}
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    for start in range(0, len(cve_list), 10):
        batch = cve_list[start : start + 10]
        try:
            response = session.get(
                NVD_URL,
                params={"cveIds": ",".join(batch)},
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            for vulnerability in response.json().get("vulnerabilities", []):
                cve = vulnerability.get("cve", {})
                cve_id = cve.get("id", "").upper()
                found = []
                for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    for metric in cve.get("metrics", {}).get(version, []):
                        score = metric.get("cvssData", {}).get("baseScore")
                        if isinstance(score, (int, float)):
                            found.append(float(score))
                if found:
                    scores[cve_id] = max(found)
        except requests.RequestException as error:
            print(f"Warning: NVD lookup failed for a batch: {error}", file=sys.stderr)
    return scores


def make_news_items(
    entries: Iterable[tuple[dict, datetime, str]], scores: dict[str, float]
) -> list[NewsItem]:
    items = []
    seen_urls = set()
    for entry, published, feed_url in entries:
        url = entry.get("link", "").strip()
        if not url or url in seen_urls:
            continue
        cves = tuple(sorted({
            cve.upper()
            for cve in CVE_PATTERN.findall(
                f"{entry.get('title', '')} {entry.get('summary', '')}"
            )
        }))
        rated = [scores[cve] for cve in cves if cve in scores and scores[cve] >= 7.0]
        if not rated:
            continue
        seen_urls.add(url)
        items.append(NewsItem(
            title=entry.get("title", "Untitled").strip(),
            url=url,
            source=entry.get("source", {}).get("title", feed_url),
            published=published,
            cves=cves,
            score=max(rated),
        ))
    return sorted(items, key=lambda item: (-item.score, -item.published.timestamp()))


def render_report(items: list[NewsItem], now: datetime, hours: float = 24) -> str:
    period = now - timedelta(hours=hours)
    lines = [f"Cybersecurity news: {period:%Y-%m-%d %H:%M UTC} to {now:%Y-%m-%d %H:%M UTC}"]
    if not items:
        lines.append("No articles with verified High or Critical CVSS scores were found.")
    for item in items:
        cves = ", ".join(item.cves)
        lines.extend([
            "",
            f"[{item.severity} | CVSS {item.score:.1f}] {item.title}",
            f"Source: {item.source} | Published: {item.published:%Y-%m-%d %H:%M UTC}",
            f"CVE: {cves}",
            item.url,
        ])
    return "\n".join(lines)


def send_email(report: str) -> bool:
    host = os.getenv("SMTP_HOST")
    recipients = [value.strip() for value in os.getenv("EMAIL_TO", "").split(",") if value.strip()]
    if not host or not recipients:
        return False
    sender = os.getenv("EMAIL_FROM") or os.getenv("SMTP_USER")
    if not sender:
        raise ValueError("Set EMAIL_FROM or SMTP_USER to send email")

    message = EmailMessage()
    message["Subject"] = "Cybersecurity High/Critical News Digest"
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(report)
    port = int(os.getenv("SMTP_PORT", "587"))
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=30) as smtp:
            _login_if_configured(smtp)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            _login_if_configured(smtp)
            smtp.send_message(message)
    return True


def _login_if_configured(smtp: smtplib.SMTP) -> None:
    username = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    if username and password:
        smtp.login(username, password)


def send_slack(report: str, session: requests.Session) -> bool:
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        return False
    response = session.post(webhook, json={"text": report}, timeout=30)
    response.raise_for_status()
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect recent cybersecurity news with verified CVSS severity.")
    parser.add_argument("--hours", type=float, default=24, help="lookback window in hours (default: 24)")
    parser.add_argument("--send", action="store_true", help="deliver the report to configured channels")
    args = parser.parse_args()
    if args.hours <= 0:
        parser.error("--hours must be greater than zero")

    now = datetime.now(timezone.utc)
    feed_urls = [value.strip() for value in os.getenv("NEWS_FEEDS", ",".join(DEFAULT_FEEDS)).split(",") if value.strip()]
    session = requests.Session()
    entries = collect_recent_entries(feed_urls, now - timedelta(hours=args.hours), session)
    scores = nvd_scores(extract_cves(entries), session)
    items = make_news_items(entries, scores)
    report = render_report(items, now, args.hours)
    print(report)

    if args.send:
        delivered = send_email(report)
        delivered = send_slack(report, session) or delivered
        if not delivered:
            print("No delivery configured; set SMTP_HOST and EMAIL_TO, or SLACK_WEBHOOK_URL.", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())