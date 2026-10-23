from asm.monitor import diff_snapshots, extract_subdomains, build_snapshot, format_report

CT_SAMPLE = [
    {"name_value": "example.com\nwww.example.com"},
    {"name_value": "*.dev.example.com"},
    {"name_value": "mail.example.com"},
    {"name_value": "evil-example.com"},        # not in scope: different domain
    {"name_value": "example.com.attacker.net"},  # not in scope
]


def test_extract_subdomains_keeps_only_in_scope_names():
    assert extract_subdomains(CT_SAMPLE, "example.com") == {
        "example.com", "www.example.com", "dev.example.com", "mail.example.com",
    }


def test_diff_reports_added_removed_and_changed():
    old = {"hosts": {"www.example.com": ["1.1.1.1"], "old.example.com": ["2.2.2.2"]}}
    new = {"hosts": {"www.example.com": ["9.9.9.9"], "dev.example.com": ["3.3.3.3"], "stage.example.com": []}}
    d = diff_snapshots(old, new)
    assert d["added"] == ["dev.example.com", "stage.example.com"]
    assert d["newly_live"] == ["dev.example.com"]
    assert d["removed"] == ["old.example.com"]
    assert d["ip_changed"] == {"www.example.com": {"before": ["1.1.1.1"], "after": ["9.9.9.9"]}}


def test_first_run_report_mentions_baseline():
    snap = build_snapshot("example.com", {"www.example.com"}, resolver=lambda h: ["1.1.1.1"])
    report = format_report("example.com", snap, diff_snapshots(None, snap), first_run=True)
    assert "baseline saved" in report and "**1**" in report
