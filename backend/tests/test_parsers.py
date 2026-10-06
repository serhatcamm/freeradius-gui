"""Parser tests, run against the real configuration files."""
from __future__ import annotations

from app.freeradius.clients_parser import parse_clients
from app.freeradius.users_parser import (
    DEFAULT_USERNAME,
    Assignment,
    parse_assignments,
    parse_users,
    split_segments,
)


# -- users -------------------------------------------------------------
def test_users_roundtrip_is_lossless(real_authorize):
    """Parsing then rendering must reproduce the original byte for byte."""
    doc = parse_users(real_authorize)
    assert doc.render() == real_authorize


def test_users_parses_cleartext_entry(real_authorize):
    doc = parse_users(real_authorize)
    entry = doc.unique_find("testuser")
    assert entry is not None
    assert entry.auth_method == "Cleartext-Password"
    assert entry.has_password
    assert entry.enabled
    assert entry.cisco_privilege is None


def test_users_detects_duplicate_entries(real_authorize):
    """The lab file contains 'testuser' twice; both must be visible."""
    doc = parse_users(real_authorize)
    matches = doc.find("testuser")
    assert len(matches) == 2
    assert {m.line_number for m in matches} == {1, 209}


def test_default_entries_are_not_users(real_authorize):
    doc = parse_users(real_authorize)
    defaults = [e for e in doc.entries if e.is_default]
    assert defaults, "DEFAULT blocks must be preserved"
    assert all(d.username == DEFAULT_USERNAME for d in defaults)
    assert all(d.conditions for d in defaults)
    # They must not be offered as manageable users. 'testuser' appears twice in
    # the real file, and both entries are returned so callers can see the
    # duplication (the service layer collapses them and reports the count).
    assert {u.username for u in doc.users} == {"testuser"}
    assert len(doc.users) == 2


def test_users_set_cisco_privilege_renders_avpair(real_authorize):
    doc = parse_users(real_authorize)
    entry = doc.unique_find("testuser")
    entry.set_cisco_privilege(15)
    rendered = doc.render()
    assert 'Cisco-AVPair = "shell:priv-lvl=15"' in rendered
    assert doc.unique_find("testuser").cisco_privilege == 15


def test_users_cisco_privilege_is_replaced_not_duplicated(real_authorize):
    doc = parse_users(real_authorize)
    entry = doc.unique_find("testuser")
    entry.set_cisco_privilege(5)
    entry.set_cisco_privilege(15)
    assert doc.render().count("Cisco-AVPair") == 1
    assert doc.unique_find("testuser").cisco_privilege == 15


def test_users_disable_preserves_password_and_reenables(real_authorize):
    doc = parse_users(real_authorize)
    entry = doc.unique_find("testuser")
    entry.enabled = False
    entry.dirty = True
    disabled = doc.render()
    assert disabled.count("#freeradius-web-disabled:") == 1

    reparsed = parse_users(disabled)
    back = reparsed.unique_find("testuser")
    assert back is not None
    assert back.enabled is False
    assert back.has_password, "disabling must not destroy the stored password"

    back.enabled = True
    back.dirty = True
    assert 'Cleartext-Password := "TestRadiusPw123!"' in parse_users(reparsed.render()).render()


def test_users_unknown_entries_are_never_rewritten():
    text = (
        "# comment\n"
        "bob\tCleartext-Password := \"bobpass\"\n"
        "\n"
        "# a vendor specific block the panel does not understand\n"
        "someuser\tAuth-Type := MySQL\n"
        "\t\tcontrol:\n"
        "\t\t\trequest = \"SELECT 1\"\n"
    )
    doc = parse_users(text)
    assert doc.render() == text


def test_users_upsert_appends_new_entry(real_authorize):
    doc = parse_users(real_authorize)
    from app.freeradius.users_parser import UserEntry

    entry = UserEntry(username="newuser")
    entry.set_password("S3cret!pass")
    doc.upsert(entry)
    rendered = doc.render()
    assert 'newuser\tCleartext-Password := "S3cret!pass"' in rendered
    assert parse_users(rendered).unique_find("newuser") is not None


def test_users_delete_removes_all_duplicates(real_authorize):
    doc = parse_users(real_authorize)
    assert doc.delete("testuser") == 2
    assert doc.unique_find("testuser") is None
    # DEFAULT blocks must survive.
    assert any(e.is_default for e in doc.entries)


def test_quote_escaping_roundtrips():
    original = 'pa"ss\\word'
    rendered = Assignment("Cleartext-Password", ":=", original).render()
    assert rendered == 'Cleartext-Password := "pa\\"ss\\\\word"'
    parsed = parse_assignments(rendered)[0]
    assert parsed.unquoted_value == original


def test_parse_assignments_multiple_pairs():
    got = parse_assignments('Cleartext-Password := "x", Session-Timeout = 3600')
    assert [a.key for a in got] == ["Cleartext-Password", "Session-Timeout"]
    assert got[0].unquoted_value == "x"
    assert got[1].unquoted_value == "3600"


# -- clients -----------------------------------------------------------
def test_clients_roundtrip_is_lossless(real_clients_conf):
    doc = parse_clients(real_clients_conf)
    assert doc.render() == real_clients_conf


def test_clients_parses_all_four_entries(real_clients_conf):
    doc = parse_clients(real_clients_conf)
    names = [c.name for c in doc.clients]
    assert names == ["localhost", "localhost_ipv6", "test-nas-a", "test-nas-b"]


def test_clients_distinguishes_host_from_network(real_clients_conf):
    doc = parse_clients(real_clients_conf)
    by_name = {c.name: c for c in doc.clients}
    assert by_name["localhost"].address == "127.0.0.1"
    assert by_name["localhost"].address_kind == "host"
    assert by_name["test-nas-a"].address == "192.0.2.0/24"
    assert by_name["test-nas-a"].address_kind == "network"
    assert by_name["localhost_ipv6"].address == "::1"


def test_clients_secret_is_detected_but_never_returned(real_clients_conf):
    doc = parse_clients(real_clients_conf)
    for client in doc.clients:
        assert client.has_secret is True
        # The parsed value must not be reachable via the API dict.
    from app.services.clients import _to_dict

    for client in doc.clients:
        payload = _to_dict(client)
        assert "secret" not in payload
        assert payload["has_secret"] is True


def test_clients_preserves_nested_limit_block(real_clients_conf):
    """The stock localhost client has a nested 'limit { }' block."""
    doc = parse_clients(real_clients_conf)
    localhost = doc.unique_find("localhost")
    assert localhost is not None
    rendered = localhost.render()
    assert "limit {" in rendered
    assert "max_connections = 16" in rendered
    assert "idle_timeout = 900" in rendered


def test_clients_unmodified_blocks_render_verbatim(real_clients_conf):
    doc = parse_clients(real_clients_conf)
    localhost = doc.unique_find("localhost")
    assert localhost.render() == "\n".join(localhost.raw_lines)


def test_clients_set_directive_updates_in_place(real_clients_conf):
    doc = parse_clients(real_clients_conf)
    client = doc.unique_find("test-nas-a")
    client.set_directive("description", "Lab VLAN 40 switches")
    rendered = doc.render()
    assert "description = Lab VLAN 40 switches" in rendered
    assert "secret = TestNasSecret123!" in rendered, "other directives must survive"
    reparsed = parse_clients(rendered)
    assert reparsed.unique_find("test-nas-a").description == "Lab VLAN 40 switches"


def test_clients_disable_comments_block_and_reenables(real_clients_conf):
    doc = parse_clients(real_clients_conf)
    client = doc.unique_find("test-nas-b")
    client.enabled = False
    client.dirty = True
    disabled = doc.render()

    reparsed = parse_clients(disabled)
    entry = reparsed.unique_find("test-nas-b")
    assert entry is not None
    assert entry.enabled is False
    assert entry.address == "198.51.100.0/24"
    assert entry.has_secret


def test_clients_handles_ipv6(real_clients_conf):
    doc = parse_clients(real_clients_conf)
    v6 = doc.unique_find("localhost_ipv6")
    assert v6.address == "::1"
    net = v6.network
    assert net is not None and net.version == 6


def test_clients_brace_in_comment_does_not_break_blocks():
    text = (
        "client a {\n"
        "	# a stray brace } in a comment\n"
        "	ipaddr = 10.0.0.1\n"
        "	secret = abcdefghijklmnop\n"
        "}\n"
        "client b {\n"
        "	ipaddr = 10.0.0.2\n"
        "	secret = abcdefghijklmnop\n"
        "}\n"
    )
    doc = parse_clients(text)
    assert [c.name for c in doc.clients] == ["a", "b"]
    assert doc.unique_find("a").address == "10.0.0.1"