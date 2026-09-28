"""Corpus mode: many responses in, per-host posture out."""

import json
import pathlib

import pytest

from edgeprint.cli import EXIT_EDGE_ONLY, EXIT_INDETERMINATE, EXIT_OK, EXIT_WAF_LIKELY, main
from edgeprint.corpus import analyze_corpus, host_key
from edgeprint.models import HttpObservation
from edgeprint.parsers import parse_har, parse_har_all

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
MIXED = FIXTURES / "corpus" / "mixed_hosts.har"

CF_CDN = {"Server": "cloudflare", "CF-RAY": "8b2f1e4c9a7d3f21-LHR"}
CF_BLOCK = {**CF_CDN, "cf-mitigated": "challenge"}


def _mixed_sources():
    return [(f"mixed#{n}", ob) for n, ob in enumerate(parse_har_all(MIXED.read_text()))]


def _hosts(corpus):
    return {h.host: h for h in corpus.hosts}


def test_parse_har_all_reads_every_entry():
    obs = parse_har_all(MIXED.read_text(encoding="utf-8"))
    assert len(obs) == 7
    assert obs[3].status_code == 403
    assert obs[3].url == "https://shop.example.com/admin"


def test_parse_har_still_returns_first_entry():
    ob = parse_har(MIXED.read_text(encoding="utf-8"))
    assert ob.url == "https://shop.example.com/"


def test_har_malformed_entries_degrade_instead_of_crashing():
    har = {"log": {"entries": ["junk", {"response": "junk"}, {"response": {"headers": 5}}]}}
    obs = parse_har_all(json.dumps(har))
    assert len(obs) == 3
    assert all(ob.headers == {} for ob in obs)


@pytest.mark.parametrize("doc", ["[]", '{"log": []}', '{"log": {"entries": []}}'])
def test_har_without_entries_is_rejected(doc):
    with pytest.raises(ValueError):
        parse_har_all(doc)


def test_block_page_on_one_response_makes_the_host_waf_likely():
    """Evidence on one response in many is the case corpus mode exists for."""
    corpus = analyze_corpus(
        [(f"r{n}", HttpObservation(url=f"https://a.test/{n}", headers=CF_CDN)) for n in range(5)]
        + [("block", HttpObservation(url="https://a.test/admin", headers=CF_BLOCK))]
    )
    (host,) = corpus.hosts
    assert host.responses == 6
    assert host.likely_waf
    assert host.vendors == {"Cloudflare (edge firewall/CDN)": 6}


def test_repetition_does_not_inflate_confidence():
    """Layer confidence is the max over responses, never a sum."""
    single = analyze_corpus([("r", HttpObservation(url="https://a.test/", headers=CF_CDN))])
    many = analyze_corpus(
        [(f"r{n}", HttpObservation(url="https://a.test/", headers=CF_CDN)) for n in range(50)]
    )
    assert many.hosts[0].layers == single.hosts[0].layers
    assert not many.hosts[0].likely_waf


def test_hosts_are_kept_apart():
    corpus = analyze_corpus(
        [
            ("a", HttpObservation(url="https://a.test/", headers=CF_BLOCK)),
            ("b", HttpObservation(url="https://b.test/", headers={"Server": "nginx"})),
        ]
    )
    hosts = _hosts(corpus)
    assert hosts["a.test"].likely_waf
    assert not hosts["b.test"].likely_edge
    assert hosts["b.test"].layers == {}


def test_hosts_are_ordered_by_severity():
    corpus = analyze_corpus(_mixed_sources())
    assert [h.host for h in corpus.hosts] == [
        "shop.example.com",
        "static.example.net",
        "api.example.org",
    ]


@pytest.mark.parametrize(
    "url, source, expected",
    [
        ("https://Shop.Example.com:8443/x", "f", "shop.example.com"),
        ("", "dump.txt", "[dump.txt]"),
        ("not a url", "dump.txt", "[dump.txt]"),
        ("http://[::1", "dump.txt", "[dump.txt]"),
    ],
)
def test_host_key(url, source, expected):
    assert host_key(url, source) == expected


def test_cli_multi_entry_har_uses_corpus_view(capsys):
    code = main(["analyze", "-i", str(MIXED), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_WAF_LIKELY
    assert len(payload["responses"]) == 7
    hosts = {h["host"]: h for h in payload["hosts"]}
    assert hosts["shop.example.com"]["likely_waf"] is True
    assert hosts["static.example.net"]["likely_waf"] is False
    assert hosts["static.example.net"]["likely_edge"] is True
    assert hosts["api.example.org"]["likely_edge"] is False


def test_cli_corpus_text_output(capsys):
    code = main(["analyze", "-i", str(MIXED)])
    out = capsys.readouterr().out
    assert code == EXIT_WAF_LIKELY
    assert "7 responses across 3 hosts" in out
    assert "Cloudflare (edge firewall/CDN) [4/4]" in out
    assert "(1 response)" in out


def test_cli_directory_of_negatives_exits_ok(capsys):
    code = main(["analyze", "-i", str(FIXTURES / "negative")])
    capsys.readouterr()
    assert code == EXIT_OK


def test_cli_most_severe_host_decides_exit(capsys):
    code = main(
        [
            "analyze",
            "-i",
            str(FIXTURES / "negative" / "nginx_200_plain.txt"),
            str(FIXTURES / "positive" / "fastly_200.txt"),
        ]
    )
    capsys.readouterr()
    assert code == EXIT_EDGE_ONLY


def test_cli_bad_inputs_are_skipped_not_fatal(capsys, tmp_path):
    bad = tmp_path / "broken.har"
    bad.write_text("{not json", encoding="utf-8")
    code = main(
        [
            "analyze",
            "-i",
            str(bad),
            str(tmp_path / "missing.txt"),
            str(FIXTURES / "positive" / "imperva_200.txt"),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_WAF_LIKELY
    assert {s["source"] for s in payload["skipped"]} == {
        str(bad),
        str(tmp_path / "missing.txt"),
    }


def test_cli_nothing_analyzable_is_indeterminate(capsys, tmp_path):
    (tmp_path / "a.txt").write_text("", encoding="utf-8")
    (tmp_path / "b.txt").write_text("", encoding="utf-8")
    code = main(["analyze", "-i", str(tmp_path)])
    capsys.readouterr()
    assert code == EXIT_INDETERMINATE


def test_cli_directory_skips_hidden_files(capsys, tmp_path):
    (tmp_path / ".hidden").mkdir()
    (tmp_path / ".hidden" / "cf.txt").write_text(
        (FIXTURES / "positive" / "cloudflare_200.txt").read_text(), encoding="utf-8"
    )
    (tmp_path / "plain.txt").write_text(
        (FIXTURES / "negative" / "nginx_200_plain.txt").read_text(), encoding="utf-8"
    )
    code = main(["analyze", "-i", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert len(payload["responses"]) == 1


def test_cli_repeated_input_flag(capsys):
    code = main(
        [
            "analyze",
            "-i",
            str(FIXTURES / "negative" / "nginx_200_plain.txt"),
            "-i",
            str(FIXTURES / "positive" / "imperva_200.txt"),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_WAF_LIKELY
    assert len(payload["responses"]) == 2
