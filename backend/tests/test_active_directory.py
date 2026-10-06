"""The AD configuration the panel writes must be valid and reversible.

The critical tests here run the real ``freeradius -XC`` against a copy of the
live raddb with the panel's AD block installed. Generating config that parses
is not something to find out about on the running server: a syntax error in
``sites-available/default`` stops FreeRADIUS from starting entirely, taking
authentication down for every user, not just AD ones.

Everything else in this module is pure string transformation and needs no
domain, no LDAP server and no privileges.
"""
from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.services import active_directory as ad

RADDB = Path("/etc/freeradius/3.0")
BIN = "/usr/sbin/freeradius"

pytestmark = pytest.mark.skipif(
    not Path(BIN).exists() or not RADDB.exists(),
    reason="requires a real FreeRADIUS installation",
)

BASE_DN = "dc=corp,dc=example,dc=com"
BIND_DN = "cn=svc-radius,ou=service accounts,dc=corp,dc=example,dc=com"
BIND_PASSWORD = "Placeholder-Not-A-Real-Secret-1"
AD_GROUP = "CN=RADIUS-STAFF,OU=Groups,dc=corp,dc=example,dc=com"
DC1 = "dc1.corp.example.com"


def _ldap_module_present() -> bool:
    """Whether rlm_ldap can actually be loaded on this host.

    The validation tests need the real module: `freeradius -XC` refuses an
    `authorize` reference it cannot resolve, and that failure says nothing
    about whether the block *this panel generated* is valid.
    """
    return (RADDB / "mods-enabled" / "ldap").exists()


def settings(**overrides) -> ad.AdSettings:
    base = dict(
        domain="corp.example.com",
        base_dn=BASE_DN,
        bind_dn=BIND_DN,
        servers=[DC1],
        bind_password=BIND_PASSWORD,
        group_map={AD_GROUP: "staff"},
    )
    base.update(overrides)
    return ad.AdSettings(**base)


def test_connection_uses_sanitized_read_only_probes(monkeypatch):
    calls = []

    async def fake_run(argv, timeout=30):
        calls.append(argv)
        assert "Placeholder-Not-A-Real-Secret-1" not in argv
        return runner.CommandResult(argv, 0, "uid=svc", "")

    from app.freeradius import runner

    monkeypatch.setattr(ad, "_tool", lambda path: path)
    monkeypatch.setattr(runner, "run_command", fake_run)
    result = asyncio.run(ad.test_connection(settings()))
    assert result.ok is True
    assert {check.name for check in result.checks} == {
        "winbind",
        "ldap:dc1.corp.example.com",
    }
    assert any("-y" in call for call in calls)


@pytest.fixture
def shipped_ldap() -> str:
    return (RADDB / "mods-available" / "ldap").read_text("utf-8")


@pytest.fixture
def shipped_site() -> str:
    return (RADDB / "sites-available" / "default").read_text("utf-8")


# -- validation ---------------------------------------------------------
def test_default_settings_are_accepted():
    settings().validate()


def test_rejects_plain_ldap_bind():
    """An unencrypted bind is refused by AD and would leak the bind password."""
    with pytest.raises(ad.AdConfigError, match="StartTLS"):
        settings(start_tls=False, use_ldaps=False).validate()


def test_rejects_ldaps_and_start_tls_together():
    with pytest.raises(ad.AdConfigError, match="inside TLS"):
        settings(use_ldaps=True, start_tls=True).validate()


def test_rejects_empty_server_list():
    with pytest.raises(ad.AdConfigError, match="domain controller"):
        settings(servers=[]).validate()


def test_rejects_server_with_scheme():
    with pytest.raises(ad.AdConfigError, match="bare hostname"):
        settings(servers=["ldaps://dc1.corp.example.com"]).validate()


def test_rejects_base_dn_that_is_not_a_dn():
    with pytest.raises(ad.AdConfigError, match="Base DN"):
        settings(base_dn="corp.example.com").validate()


def test_rejects_single_component_dn():
    """dc=corp alone cannot be a user, group or bind DN."""
    with pytest.raises(ad.AdConfigError, match="Base DN"):
        settings(base_dn="dc=corp").validate()


def test_rejects_bind_dn_that_is_not_a_dn():
    with pytest.raises(ad.AdConfigError, match="Bind DN"):
        settings(bind_dn="svc-radius").validate()


def test_rejects_short_bind_password():
    with pytest.raises(ad.AdConfigError, match="at least 12"):
        settings(bind_password="short").validate()


def test_rejects_gc_port_for_user_bind():
    with pytest.raises(ad.AdConfigError, match="3269"):
        settings(port=3269).validate()


def test_rejects_non_dn_group():
    with pytest.raises(ad.AdConfigError, match="AD group is not a DN"):
        settings(group_map={"STAFF": "staff"}).validate()


def test_rejects_invalid_radius_group_name():
    with pytest.raises(ad.AdConfigError, match="not a valid group name"):
        settings(group_map={AD_GROUP: "bad name!"}).validate()


def test_rejects_invalid_membership_attribute():
    with pytest.raises(ad.AdConfigError, match="attribute name"):
        settings(membership_attribute="member of").validate()


# -- module block -------------------------------------------------------
def test_ldap_block_is_written_and_readable():
    out = ad.install_ldap_block(settings(), "")
    assert ad._LDAP_BEGIN in out and ad._LDAP_END in out
    assert DC1 in out
    assert BASE_DN in out
    assert BIND_DN in out


def test_ldap_block_requires_a_password():
    """Writing an empty bind_password would fail every lookup at runtime."""
    with pytest.raises(ad.AdConfigError, match="bind password"):
        ad.install_ldap_block(settings(bind_password=None), "")


def test_ldap_block_replaces_the_previous_one():
    """A stale domain must not survive a re-save."""
    first = ad.install_ldap_block(settings(), "")
    second = ad.install_ldap_block(
        settings(domain="other.example.com", servers=["dc2.other.example.com"]), first
    )
    assert "dc1.corp.example.com" not in second
    assert "dc2.other.example.com" in second
    assert second.count(ad._LDAP_BEGIN) == 1


def test_strip_ldap_block_restores_the_shipped_module(shipped_ldap: str):
    installed = ad.install_ldap_block(settings(), shipped_ldap)
    assert ad.strip_ldap_block(installed) == shipped_ldap


def test_strip_is_idempotent(shipped_ldap: str):
    installed = ad.install_ldap_block(settings(), shipped_ldap)
    once = ad.strip_ldap_block(installed)
    assert ad.strip_ldap_block(once) == once


def test_child_container_derives_from_the_base_dn():
    assert ad._child_container(BASE_DN, "CN=Users") == f"CN=Users,{BASE_DN}"


# -- brace matching -----------------------------------------------------
def test_section_bounds_ignores_commented_out_braces(shipped_site: str):
    """Debian's post-auth contains a commented 'if (...) {' whose closer is
    also commented. Counting braces naively makes the section look
    unterminated and the block lands after the end of the file."""
    start, end = ad._section_bounds(shipped_site, r"^post-auth\s*\{")
    body = shipped_site[start:end]
    assert "freeradius-web" not in body
    assert body.count("}") < shipped_site.count("}")


def test_section_bounds_matches_the_real_post_auth(shipped_site: str):
    """The matched close must be the one that ends post-auth, not a later
    brace in a subsequent section.

    preacct/accounting precede post-auth in the shipped file; pre-proxy and
    post-proxy follow it, so those are the sections that must appear in the
    tail.
    """
    start, end = ad._section_bounds(shipped_site, r"^post-auth\s*\{")
    assert shipped_site[end : end + 3].strip() == "}"
    tail = shipped_site[end + 1 :]
    for section in ("pre-proxy", "post-proxy"):
        assert re.search(rf"^{re.escape(section)}\s*\{{", tail, re.MULTILINE), (
            f"{section} should start after post-auth, not inside it"
        )


def test_section_bounds_ignores_braces_in_strings():
    """A '}' inside a quoted value must not close the section."""
    text = "post-auth {\n\tset attr = '}'\n\tset other = '{'\n}\n"
    start, end = ad._section_bounds(text, r"^post-auth\s*\{")
    assert text[end] == "}"
    assert text[end :].strip() == "}"


def test_hash_inside_a_value_is_not_a_comment():
    """A '#' inside quotes is part of the value. Braces there must still be
    masked, because a quoted '}' is not a section close."""
    masked = ad._mask_comments("set x = 'a#b{c'\n")
    assert "{" not in masked
    assert "#" not in masked
    assert len(masked) == len("set x = 'a#b{c'\n")


def test_section_bounds_mask_preserves_length():
    """The mask is used with indices taken from the original text, so every
    offset has to line up."""
    text = "post-auth {\n\t# a comment with { brace\n\tset x = 'y'\n}\n"
    masked = ad._mask_comments(text)
    assert len(masked) == len(text)
    assert "comment" not in masked
    assert "{" in masked  # the section's real brace survives


def test_block_lands_inside_post_auth(shipped_site: str):
    out = ad.install_postauth_block(settings(), shipped_site)
    start, end = ad._section_bounds(out, r"^post-auth\s*\{")
    assert ad._POSTAUTH_BEGIN in out[start:end]
    assert "&Group += 'staff'" in out[start:end]


# -- authorize / post-auth ----------------------------------------------
def test_authorize_adds_a_separate_ad_ldap_instance(shipped_site: str):
    """The distro ldap instance remains untouched; AD gets its own instance."""
    assert re.search(r"^[ \t]*-ldap[ \t]*$", shipped_site, re.MULTILINE), (
        "the shipped site no longer contains the expected disabled reference"
    )
    out = ad.install_authorize_block(shipped_site)
    assert re.search(r"^[ \t]*ldap_ad[ \t]*$", out, re.MULTILINE)
    assert re.search(r"^[ \t]*-ldap[ \t]*$", out, re.MULTILINE)


def test_authorize_references_ntlm_auth(shipped_site: str):
    out = ad.install_authenticate_block(ad.install_authorize_block(shipped_site))
    assert "ntlm_auth" in out
    start, end = ad._section_bounds(out, r"^authorize\s*\{")
    assert "ntlm_auth" in out[start:end]


def test_strip_authorize_restores_the_shipped_site(shipped_site: str):
    out = ad.install_authorize_block(shipped_site)
    assert ad.strip_authorize_block(out) == shipped_site


def test_authenticate_handlers_are_reversible(shipped_site: str):
    out = ad.install_authenticate_block(shipped_site)
    assert ad._AUTH_BEGIN in out
    assert ad.strip_authenticate_block(out) == shipped_site


def test_strip_authorize_leaves_a_hand_written_ldap_alone(shipped_site: str):
    """With nothing installed, disabling an ldap someone enabled by hand
    would silently change authentication the panel does not own."""
    manual = shipped_site.replace("-ldap", "ldap", 1)
    assert ad.strip_authorize_block(manual) == manual


def test_postauth_maps_ad_groups_to_radius_groups(shipped_site: str):
    out = ad.install_postauth_block(settings(), shipped_site)
    assert ad._POSTAUTH_BEGIN in out
    assert AD_GROUP in out
    assert "&Group += 'staff'" in out


def test_postauth_uses_the_instance_group_comparison(shipped_site: str):
    """The rlm_ldap instance owns the membership lookup; the post-auth block
    only maps a successful group comparison onto the existing RADIUS group."""
    out = ad.install_postauth_block(settings(), shipped_site)
    assert "ldap_ad:group == '" in out


def test_postauth_quotes_the_group_dn(shipped_site: str):
    tricky = settings(group_map={"CN=Sales.Office,OU=Groups," + BASE_DN: "sales"})
    out = ad.install_postauth_block(tricky, shipped_site)
    assert "ldap_ad:group == 'CN=Sales.Office,OU=Groups," in out


def test_postauth_block_is_not_glued_to_the_section_brace(shipped_site: str):
    """unlang rejects this with 'Invalid location for if', pointing at the
    wrong line, so the newline is load-bearing."""
    out = ad.install_postauth_block(settings(), shipped_site)
    assert f"{ad._POSTAUTH_END}\n" in out


def test_postauth_handles_several_groups(shipped_site: str):
    two = settings(
        group_map={AD_GROUP: "staff", "CN=RADIUS-GUEST,OU=Groups," + BASE_DN: "guest"}
    )
    out = ad.install_postauth_block(two, shipped_site)
    assert "&Group += 'staff'" in out and "&Group += 'guest'" in out


def test_postauth_without_a_map_installs_nothing(shipped_site: str):
    assert ad.install_postauth_block(settings(group_map={}), shipped_site) == shipped_site


def test_strip_postauth_restores_the_shipped_site(shipped_site: str):
    out = ad.install_postauth_block(settings(), shipped_site)
    assert ad.strip_postauth_block(out) == shipped_site


def test_installing_twice_does_not_duplicate_the_block(shipped_site: str):
    once = ad.install_authorize_block(shipped_site)
    once = ad.install_authenticate_block(once)
    once = ad.install_postauth_block(settings(), once)
    twice = ad.install_authorize_block(once)
    twice = ad.install_authenticate_block(twice)
    twice = ad.install_postauth_block(settings(), twice)
    assert twice == once


def test_missing_authorize_section_is_an_error_not_a_corruption():
    with pytest.raises(ad.AdConfigError, match="section"):
        ad.install_authorize_block("authenticate {\n}\n")


def test_unterminated_section_is_refused():
    with pytest.raises(ad.AdConfigError, match="Unterminated"):
        ad.install_authorize_block("authorize {\n\tfiles\n\t-ldap\n")


def test_authorize_insertion_is_confined_to_the_section(shipped_site: str):
    """Only the managed ldap_ad reference is added to authorize."""
    out = ad.install_authorize_block(shipped_site)
    assert len(re.findall(r"^[ \t]*ldap_ad[ \t]*$", out, re.MULTILINE)) == 1
    assert out.count("-ldap") == shipped_site.count("-ldap")


# -- validated against the real binary ----------------------------------
@pytest.fixture
def validated_raddb(shipped_ldap: str, shipped_site: str) -> Iterator[Path]:
    """A throwaway raddb tree with the AD block installed."""
    base = Path(tempfile.mkdtemp(prefix="frw-ad-", dir="/tmp"))
    base.chmod(0o755)
    dest = base / "3.0"
    subprocess.run(["cp", "-a", str(RADDB), str(dest)], check=True)
    try:
        (dest / "mods-available" / "ldap").write_text(
            ad.install_ldap_block(settings(), shipped_ldap), encoding="utf-8"
        )
        site = dest / "sites-available" / "default"
        site_text = ad.install_authorize_block(shipped_site)
        site.write_text(ad.install_postauth_block(settings(), site_text), encoding="utf-8")
        ref = RADDB.stat()
        subprocess.run(["chown", "-R", f"{ref.st_uid}:{ref.st_gid}", str(dest)], check=True)
        yield dest
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _run_freeradius(raddb: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [BIN, "-XC", "-d", str(raddb), "-l", "stdout"],
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.mark.skipif(
    not _ldap_module_present(),
    reason="rlm_ldap is not installed on this host; freeradius -XC cannot resolve it",
)
def test_generated_config_passes_the_real_validation(validated_raddb: Path):
    """The check that matters most: config this panel generates must be
    accepted by the binary that will load it.

    A syntax error in sites-available/default stops FreeRADIUS starting
    entirely, taking authentication down for every user rather than just AD
    ones. Runs against a copy of the live tree, so it exercises the real
    modules-available contents and real ownership.
    """
    result = _run_freeradius(validated_raddb)
    assert result.returncode == 0, f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}"


@pytest.mark.skipif(
    not _ldap_module_present(),
    reason="rlm_ldap is not installed on this host",
)
def test_stripped_config_passes_validation_too(shipped_ldap: str, shipped_site: str):
    """Removal has to be as safe as installation - it is what disconnect runs."""
    base = Path(tempfile.mkdtemp(prefix="frw-ad-strip-", dir="/tmp"))
    base.chmod(0o755)
    dest = base / "3.0"
    subprocess.run(["cp", "-a", str(RADDB), str(dest)], check=True)
    try:
        (dest / "mods-available" / "ldap").write_text(
            ad.strip_ldap_block(ad.install_ldap_block(settings(), shipped_ldap)),
            encoding="utf-8",
        )
        site = dest / "sites-available" / "default"
        text = ad.install_authorize_block(shipped_site)
        text = ad.install_postauth_block(settings(), text)
        site.write_text(
            ad.strip_authorize_block(ad.strip_postauth_block(text)), encoding="utf-8"
        )
        ref = RADDB.stat()
        subprocess.run(["chown", "-R", f"{ref.st_uid}:{ref.st_gid}", str(dest)], check=True)
        result = _run_freeradius(dest)
        assert result.returncode == 0, f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}"
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_bind_password_never_appears_in_an_audit_payload():
    """The redaction list covers `bind_password` because it contains
    'password'; this asserts the guarantee rather than trusting the regex."""
    import json

    from app.services.audit import redact

    payload = {
        "domain": "corp.example.com",
        "bind_dn": BIND_DN,
        "bind_password": BIND_PASSWORD,
        "servers": [DC1],
    }
    rendered = json.dumps(redact(payload))
    assert BIND_PASSWORD not in rendered
    assert BIND_DN in rendered  # the DN itself is not a secret
