"""The agent skill must stay a guide to the tool, not a second catalogue."""

from pathlib import Path

SKILL = (Path(__file__).parent.parent / "skills" / "server-hardening-audit" /
         "SKILL.md").read_text()


def test_skill_has_no_control_catalogue():
    assert "control catalogue" not in SKILL.lower()
    for cmd in ("sshd -T 2>/dev/null | grep", "ss -tlnpH | awk", "apt-get update -qq"):
        assert cmd not in SKILL


def test_skill_keeps_operating_rules_and_protocols():
    for rule in (f"**R{i} " for i in range(1, 11)):
        assert rule in SKILL
    for section in ("Phase 0", "Restore drill protocol", "Remediation protocol",
                    "Failure modes", "Closing deliverable"):
        assert section in SKILL


def test_skill_covers_every_subcommand():
    for sub in ("sha list", "sha audit", "sha report", "--attest", "sha probe", "sha diff",
                "sha scrub", "sha redact-check"):
        assert sub in SKILL
