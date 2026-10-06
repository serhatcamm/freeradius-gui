"""Parser for the FreeRADIUS ``groups`` file."""
from __future__ import annotations

import pytest

from app.freeradius.groups_parser import (
    DEFAULT_GROUP,
    GroupEntry,
    load_groups,
    parse_groups,
)


def test_parses_name_and_attributes():
    doc = parse_groups('staff\tReply-Message = "welcome", Max-Monthly-Session = 36000\n')
    assert [g.name for g in doc.groups] == ["staff"]
    entry = doc.groups[0]
    assert [a.key for a in entry.attributes] == ["Reply-Message", "Max-Monthly-Session"]
    assert entry.attributes[0].unquoted_value == "welcome"
    assert entry.attributes[1].unquoted_value == "36000"


def test_default_group_is_an_ordinary_entry():
    doc = parse_groups(f'{DEFAULT_GROUP}\tReply-Message = "hi"\n')
    assert len(doc.groups) == 1
    assert doc.groups[0].is_default is True
    assert doc.groups[0].name == DEFAULT_GROUP


def test_separates_reply_prefixed_attributes():
    doc = parse_groups('g\tTunnel-Type = VLAN, reply:Reply-Message = "yo"\n')
    entry = doc.groups[0]
    assert [a.key for a in entry.attributes] == ["Tunnel-Type", "Reply-Message"]
    assert entry.reply_indices == {1}
    # The prefix must come back on render.
    assert entry.render() == 'g\tTunnel-Type = VLAN, reply:Reply-Message = "yo"'


def test_commas_inside_quotes_do_not_split():
    doc = parse_groups('g\tReply-Message = "a, b, c", Max-Monthly-Session = 1\n')
    entry = doc.groups[0]
    assert len(entry.attributes) == 2
    assert entry.attributes[0].unquoted_value == "a, b, c"


def test_comments_and_blanks_are_preserved_verbatim():
    text = "# header\n\ng1\tReply-Message = \"x\"\n# footer\n"
    doc = parse_groups(text)
    assert doc.render() == text


def test_round_trip_is_byte_exact():
    text = (
        "# Managed by the panel\n"
        'staff\tReply-Message = "welcome"\n'
        "\n"
        'DEFAULT\tReply-Message = "hi, there"\n'
    )
    assert parse_groups(text).render() == text


def test_unparseable_line_is_kept_not_dropped():
    """A line we do not understand must survive a rewrite."""
    text = "g1\tReply-Message = \"x\"\n!!!garbage!!!\ng2\tReply-Message = \"y\"\n"
    doc = parse_groups(text)
    assert [g.name for g in doc.groups] == ["g1", "g2"]
    assert doc.render() == text


def test_upsert_replaces_in_place_and_keeps_order():
    doc = parse_groups(
        'a\tReply-Message = "1"\nb\tReply-Message = "2"\n# footer\n'
    )
    doc.upsert(GroupEntry(name="a"))
    names = [g.name for g in doc.groups]
    assert names == ["a", "b"]
    # Trailing comment must not drift above the entries.
    assert doc.render().splitlines()[-1] == "# footer"


def test_upsert_appends_new_group_above_trailing_comments():
    doc = parse_groups('a\tReply-Message = "1"\n# footer\n')
    doc.upsert(GroupEntry(name="z"))
    lines = doc.render().splitlines()
    assert lines[-1] == "# footer"
    assert any(line.startswith("z") for line in lines)


def test_delete_removes_only_named_group():
    doc = parse_groups('a\tReply-Message = "1"\nb\tReply-Message = "2"\n')
    assert doc.delete("a") == 1
    assert [g.name for g in doc.groups] == ["b"]
    assert doc.delete("nope") == 0


def test_unique_find_and_find():
    doc = parse_groups('a\tReply-Message = "1"\n')
    assert doc.unique_find("a").name == "a"
    assert doc.unique_find("missing") is None


def test_render_without_attributes_is_bare_name():
    assert GroupEntry(name="empty").render() == "empty"


def test_to_dict_shape():
    doc = parse_groups('g\tReply-Message = "x"\n')
    payload = doc.groups[0].to_dict()
    assert payload["name"] == "g"
    assert payload["is_default"] is False
    assert payload["attributes"] == [
        {"key": "Reply-Message", "op": "=", "value": "x", "reply": False}
    ]


def test_missing_file_is_an_empty_document(tmp_path):
    doc = load_groups(tmp_path / "nope")
    assert doc.groups == []
    assert doc.render() == ""


def test_quoted_escapes_survive_round_trip():
    doc = parse_groups('g\tReply-Message = "say \\"hi\\""\n')
    assert doc.groups[0].attributes[0].unquoted_value == 'say "hi"'
    assert doc.render() == 'g\tReply-Message = "say \\"hi\\""\n'


def test_duplicate_names_are_all_found():
    """The file should not contain duplicates, but do not silently hide them."""
    doc = parse_groups('dup\tReply-Message = "1"\ndup\tReply-Message = "2"\n')
    assert len(doc.find("dup")) == 2
    assert doc.unique_find("dup").attributes[0].unquoted_value == "1"


@pytest.mark.parametrize("name", ["", "   "])
def test_blank_input_yields_no_groups(name):
    assert parse_groups(name).groups == []