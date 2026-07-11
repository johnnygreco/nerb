from __future__ import annotations

import base64
from typing import Any, cast

import pytest

from nerb.enron_cleaning import (
    CLEANING_POLICY_SHA256,
    CLEANING_POLICY_VERSION,
    GROUPING_TEXT_POLICY_SHA256,
    GROUPING_TEXT_POLICY_VERSION,
    EnronCleaningError,
    EnronCleaningReason,
    clean_email_body,
    clean_subject,
    normalize_grouping_text,
    normalize_natural_text,
    normalize_thread_subject,
)


def test_policy_identifiers_are_stable_sha256_values() -> None:
    assert CLEANING_POLICY_VERSION == "nerb.enron-cleaning.v2.2"
    assert GROUPING_TEXT_POLICY_VERSION == "nerb.enron-grouping-text.v2.2"
    assert len(CLEANING_POLICY_SHA256) == 64
    assert len(GROUPING_TEXT_POLICY_SHA256) == 64
    assert int(CLEANING_POLICY_SHA256, 16) >= 0
    assert int(GROUPING_TEXT_POLICY_SHA256, 16) >= 0


def test_normalize_natural_text_is_lf_nfc_and_control_safe() -> None:
    result = normalize_natural_text(
        "  Cafe\u0301\r\n\r\n\r\nx\x00\t y\u202ez\u200b\U0001f469\u200d\U0001f4bb  ",
        "body",
        200,
        1_000,
    )

    assert result.text == "Café\n\nx yz\U0001f469\u200d\U0001f4bb"
    assert result.counters["line_endings_normalized"] == 3
    assert result.counters["unicode_nfc_changed"] == 1
    assert result.counters["control_chars_replaced"] == 1
    assert result.counters["bidi_chars_removed"] == 1
    assert result.counters["zero_width_chars_removed"] == 1
    assert result.audit is result.counters


def test_clean_subject_stays_natural_and_becomes_one_line() -> None:
    result = clean_subject("Re:  Budget\r\n  follow-up < 3", 100, 300)

    assert result.text == "Re: Budget follow-up < 3"
    assert result.counters["subject_line_breaks_collapsed"] == 1


@pytest.mark.parametrize(
    "value, max_chars, max_bytes, reason",
    [
        (None, 10, 10, EnronCleaningReason.INVALID_TYPE),
        ("x", 0, 10, EnronCleaningReason.INVALID_LIMIT),
        ("x", 10, True, EnronCleaningReason.INVALID_LIMIT),
        ("abc", 2, 10, EnronCleaningReason.INPUT_CHAR_LIMIT),
        ("é", 2, 1, EnronCleaningReason.INPUT_BYTE_LIMIT),
        ("\ud800", 10, 10, EnronCleaningReason.INVALID_UNICODE),
    ],
)
def test_natural_text_rejects_non_strings_surrogates_and_limits(
    value: object, max_chars: int, max_bytes: int, reason: EnronCleaningReason
) -> None:
    with pytest.raises(EnronCleaningError, match="^invalid or unsafe Enron text$") as caught:
        normalize_natural_text(cast(str, value), "body", max_chars, max_bytes)
    assert caught.value.reason is reason
    assert caught.value.code == reason.value


def test_cleaning_error_reasons_are_closed_bounded_and_non_echoing() -> None:
    assert {reason.value for reason in EnronCleaningReason} == {
        "grouping_expansion_limit",
        "html_structure_limit",
        "input_byte_limit",
        "input_char_limit",
        "invalid_field",
        "invalid_limit",
        "invalid_type",
        "invalid_unicode",
        "mime_charset_invalid",
        "mime_charset_unsupported",
        "mime_structure",
        "mime_structure_limit",
        "mime_transfer_invalid",
        "mime_transfer_unsupported",
        "output_byte_limit",
        "output_char_limit",
    }
    assert all(len(reason.value) <= 32 and reason.value.replace("_", "").islower() for reason in EnronCleaningReason)
    assert all(str(reason) == reason.value for reason in EnronCleaningReason)

    private_value = "private.person@example.test\ud800"
    with pytest.raises(EnronCleaningError) as caught:
        normalize_natural_text(private_value, "body", 100, 1_000)
    assert caught.value.reason is EnronCleaningReason.INVALID_UNICODE
    assert private_value not in str(caught.value)
    assert private_value not in repr(caught.value)
    assert caught.value.__cause__ is None

    with pytest.raises(EnronCleaningError) as invalid_field:
        normalize_natural_text("safe", "", 10, 10)
    assert invalid_field.value.reason is EnronCleaningReason.INVALID_FIELD


def test_html_visible_text_is_cleaned_without_resource_or_hidden_content() -> None:
    body = (
        "<html><head><title>hidden</title></head><body><p>Hello&nbsp;<b>Alice</b></p>"
        "<script>secret@example.com</script><style>.x{}</style>"
        '<a href="https://example.test/private">Open</a><!-- comment --></body></html>'
    )

    result = clean_email_body(body, 2_000, 5_000)

    assert result.full_visible_body == "Hello Alice\nOpen"
    assert "secret@example.com" not in result.full_visible_body
    assert "https://" not in result.full_visible_body
    assert result.counters["html_detected"] == 1
    assert result.counters["html_hidden_chars_dropped"] > 0
    assert result.counters["html_comments_dropped"] == 1


def test_html_preserves_noscript_and_inline_svg_visible_text_for_recall() -> None:
    body = "<noscript>alice.private@example.test</noscript><p>Hello</p><svg><text>bob.private@example.test</text></svg>"

    result = clean_email_body(body, 2_000, 5_000)

    assert "alice.private@example.test" in result.full_visible_body
    assert "bob.private@example.test" in result.full_visible_body
    assert "Hello" in result.full_visible_body


def test_default_ignorables_do_not_split_identifiers_in_plain_or_html_text() -> None:
    plain = clean_email_body(
        "alice\u00ad@exa\u034fmple.test and bob\u2062@example.test and dan\ufff0@example.test",
        2_000,
        5_000,
    )
    html = clean_email_body("<p>carol&shy;@example.test</p>", 2_000, 5_000)

    assert plain.full_visible_body == ("alice@example.test and bob@example.test and dan@example.test")
    assert html.full_visible_body == "carol@example.test"
    assert plain.counters["default_ignorable_chars_removed"] == 4
    assert html.counters["default_ignorable_chars_removed"] == 1


def test_join_controls_remain_supported_language_exceptions() -> None:
    result = clean_email_body("می\u200cخواهم ن\u200dم", 100, 500)

    assert result.full_visible_body == "می\u200cخواهم ن\u200dم"
    assert result.counters["default_ignorable_chars_removed"] == 0


def test_join_controls_cannot_hide_inside_ascii_identifiers() -> None:
    result = clean_email_body("Ali\u200dce alice\u200c@example.test", 100, 500)

    assert result.full_visible_body == "Alice alice@example.test"
    assert result.counters["default_ignorable_chars_removed"] == 2


def test_default_ignorable_range_boundaries_are_explicit() -> None:
    result = clean_email_body("a\u180fb x\ufff8y z\ufff9w", 100, 500)

    assert result.full_visible_body == "ab xy z\ufff9w"
    assert result.counters["default_ignorable_chars_removed"] == 2


def test_html_retains_safe_accessibility_and_form_attributes_but_not_unsafe_urls() -> None:
    body = (
        '<img alt="private.person@example.test" title="Portrait of Private Person" '
        'src="https://private.person@example.test/image" onerror="event-private@example.test" '
        'style="background:url(style-private@example.test)">'
        '<input value="+1 555 0100" placeholder="backup.person@example.test" '
        'aria-label="Private account owner" src="https://source-private.example.test">'
        '<button aria-label="Submit private request">Submit private request</button>'
        '<a title="Private profile" href="mailto:href-private@example.test">Open profile</a>'
    )

    result = clean_email_body(body, 5_000, 10_000)

    for retained in (
        "private.person@example.test",
        "Portrait of Private Person",
        "+1 555 0100",
        "backup.person@example.test",
        "Private account owner",
        "Submit private request",
        "Private profile",
        "Open profile",
    ):
        assert retained in result.full_visible_body
    for dropped in (
        "https://private.person@example.test/image",
        "event-private@example.test",
        "style-private@example.test",
        "https://source-private.example.test",
        "href-private@example.test",
    ):
        assert dropped not in result.full_visible_body
    assert result.full_visible_body.count("Submit private request") == 1
    assert result.counters["html_attributes_retained"] == 7
    assert result.counters["html_attribute_chars_retained"] > 0
    assert result.counters["html_attributes_dropped"] == 5
    assert result.counters["html_attribute_chars_dropped"] > 0


def test_html_retains_finite_natural_aria_descriptions_for_recall() -> None:
    body = (
        '<div aria-description="alice.private@example.test" '
        'aria-valuetext="bob.private@example.test" '
        'aria-placeholder="carol.private@example.test" '
        'aria-roledescription="Owner dan.private@example.test">Visible</div>'
    )

    result = clean_email_body(body, 2_000, 5_000)

    for name in ("alice", "bob", "carol", "dan"):
        assert f"{name}.private@example.test" in result.full_visible_body


def test_outlook_conditional_comment_visible_text_is_preserved() -> None:
    body = "<body><!--[if mso]><p>alice.private@example.test</p><![endif]--><p>Hello</p></body>"

    result = clean_email_body(body, 2_000, 5_000)

    assert "alice.private@example.test" in result.full_visible_body
    assert "Hello" in result.full_visible_body
    assert result.counters["html_conditional_comments_kept"] == 1


def test_plain_comparison_and_unlabelled_base64_are_not_reparsed() -> None:
    encoded = base64.b64encode(b"alice@example.com").decode("ascii")
    body = f"Budget is 2 < 3. Encoded token: {encoded}"

    result = clean_email_body(body, 1_000, 2_000)

    assert result.full_visible_body == body
    assert result.counters["html_detected"] == 0
    assert result.counters["base64_decoded"] == 0


def test_explicit_quoted_printable_html_is_decoded_conservatively() -> None:
    body = "\n".join(
        [
            'Content-Type: text/html; charset="utf-8"',
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<p>Hello=20Jos=C3=A9</p><p>Second</p>",
        ]
    )

    result = clean_email_body(body, 2_000, 5_000)

    assert result.full_visible_body == "Hello José\n\nSecond"
    assert result.counters["mime_detected"] == 1
    assert result.counters["quoted_printable_decoded"] == 1
    assert result.counters["html_detected"] == 1


def test_explicit_base64_text_is_decoded() -> None:
    encoded = base64.b64encode("Hello José".encode()).decode()
    body = f"Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n{encoded}"

    result = clean_email_body(body, 1_000, 2_000)

    assert result.full_visible_body == "Hello José"
    assert result.counters["base64_decoded"] == 1


def test_nonattachment_text_calendar_is_preserved_for_recall() -> None:
    body = "Content-Type: text/calendar; charset=utf-8\n\nATTENDEE:mailto:alice.private@example.test"

    result = clean_email_body(body, 2_000, 5_000)

    assert result.full_visible_body == "ATTENDEE:mailto:alice.private@example.test"
    assert result.counters["mime_text_parts_kept"] == 1
    assert result.counters["mime_nontext_parts_dropped"] == 0


def test_inline_rfc822_preserves_visible_address_headers_and_body() -> None:
    body = "\n".join(
        [
            "Content-Type: message/rfc822",
            "",
            "From: alice.private@example.test",
            "To: bob.private@example.test",
            "Subject: Private forwarding",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "Call carol.private@example.test",
        ]
    )

    result = clean_email_body(body, 5_000, 10_000)

    for expected in (
        "alice.private@example.test",
        "bob.private@example.test",
        "carol.private@example.test",
    ):
        assert expected in result.full_visible_body
    assert result.counters["mime_message_parts_kept"] == 1


def test_headerless_quoted_printable_requires_multiple_escapes_and_hard_break() -> None:
    result = clean_email_body("EPSILON=20MIME=20MARKER=0Asecond=20line", 1_000, 2_000)

    assert result.full_visible_body == "EPSILON MIME MARKER\nsecond line"
    assert result.counters["headerless_quoted_printable_decoded"] == 1
    assert result.counters["quoted_printable_decoded"] == 1
    assert result.counters["mime_detected"] == 1

    ordinary = clean_email_body("One encoded-looking space=20but no hard break", 1_000, 2_000)
    assert ordinary.full_visible_body == "One encoded-looking space=20but no hard break"
    assert ordinary.counters["quoted_printable_decoded"] == 0


def test_multipart_deduplicates_identical_alternatives_and_drops_attachment() -> None:
    attachment = base64.b64encode(b"not visible").decode()
    body = "\n".join(
        [
            'Content-Type: multipart/mixed; boundary="outer"',
            "",
            "--outer",
            'Content-Type: multipart/alternative; boundary="inner"',
            "",
            "--inner",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "Hello Alice",
            "--inner",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<p>Hello <b>Alice</b></p>",
            "--inner--",
            "--outer",
            "Content-Type: application/octet-stream; name=secret.bin",
            'Content-Disposition: attachment; filename="secret.bin"',
            "Content-Transfer-Encoding: base64",
            "",
            attachment,
            "--outer--",
        ]
    )

    result = clean_email_body(body, 10_000, 20_000)

    assert result.full_visible_body == "Hello Alice"
    assert result.counters["mime_parts_seen"] == 4
    assert result.counters["mime_alternative_parts_dropped"] == 1
    assert result.counters["mime_alternative_duplicates_dropped"] == 1
    assert result.counters["mime_attachments_dropped"] == 1
    assert result.counters["mime_attachment_chars_dropped"] > 0


def test_multipart_alternative_unions_distinct_visible_text_for_recall() -> None:
    body = "\n".join(
        [
            'Content-Type: multipart/alternative; boundary="alt"',
            "",
            "--alt",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "Hello",
            "--alt",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<p>Hello private.person@example.test</p>",
            "--alt--",
        ]
    )

    result = clean_email_body(body, len(body), len(body.encode("utf-8")))

    assert result.full_visible_body == "Hello\n\nHello private.person@example.test"
    assert result.current_body == result.full_visible_body
    assert "private.person@example.test" in result.full_visible_body
    assert result.counters["mime_alternative_parts_dropped"] == 0
    assert result.counters["mime_alternative_duplicates_dropped"] == 0

    with pytest.raises(EnronCleaningError, match="^invalid or unsafe Enron text$"):
        clean_email_body(body, len(body) - 1, len(body.encode("utf-8")))


def test_multipart_preserves_human_readable_preamble_and_epilogue() -> None:
    body = "\n".join(
        [
            'Content-Type: multipart/mixed; boundary="parts"',
            "",
            "Preamble alice.private@example.test",
            "--parts",
            "Content-Type: text/plain",
            "",
            "Visible body",
            "--parts--",
            "Epilogue bob.private@example.test",
        ]
    )

    result = clean_email_body(body, 5_000, 10_000)

    assert "alice.private@example.test" in result.full_visible_body
    assert "bob.private@example.test" in result.full_visible_body
    assert result.counters["mime_preamble_chars_kept"] > 0
    assert result.counters["mime_epilogue_chars_kept"] > 0


def test_headerless_multipart_part_preserves_header_like_recall_text() -> None:
    body = "\n".join(
        [
            'Content-Type: multipart/mixed; boundary="parts"',
            "",
            "--parts",
            "Contact: alice.private@example.test",
            "",
            "Visible body",
            "--parts--",
        ]
    )

    result = clean_email_body(body, 5_000, 10_000)

    assert "Contact: alice.private@example.test" in result.full_visible_body


def test_inline_rfc822_permits_repeated_received_and_preserves_thread_headers() -> None:
    body = "\n".join(
        [
            "Content-Type: message/rfc822",
            "",
            "Received: by relay-one.example.test",
            "Received: by relay-two.example.test",
            "Message-ID: <nested-private@example.test>",
            "In-Reply-To: <parent-private@example.test>",
            "References: <root-private@example.test>",
            "From: alice.private@example.test",
            "Content-Type: text/plain",
            "",
            "Visible body",
        ]
    )

    result = clean_email_body(body, 5_000, 10_000)

    assert "<nested-private@example.test>" in result.full_visible_body
    assert "<parent-private@example.test>" in result.full_visible_body
    assert "<root-private@example.test>" in result.full_visible_body
    assert result.counters["mime_message_header_lines_kept"] == 4
    assert result.counters["mime_headers_removed"] >= 4


def test_inline_rfc822_decodes_visible_rfc2047_headers_with_safe_fallback() -> None:
    encoded = "\n".join(
        [
            "Content-Type: message/rfc822",
            "",
            "Subject: =?utf-8?b?QWxpY2UgUHJpdmF0ZQ==?=",
            "From: =?utf-8?q?Jos=C3=A9_Private?= <jose.private@example.test>",
            "Content-Type: text/plain",
            "",
            "Visible body",
        ]
    )
    malformed = "\n".join(
        [
            "Content-Type: message/rfc822",
            "",
            "Subject: =?utf-8?b?A?=",
            "Content-Type: text/plain",
            "",
            "Visible body",
        ]
    )

    decoded = clean_email_body(encoded, 5_000, 10_000)
    fallback = clean_email_body(malformed, 5_000, 10_000)

    assert "Subject: Alice Private" in decoded.full_visible_body
    assert "From: José Private <jose.private@example.test>" in decoded.full_visible_body
    assert decoded.counters["mime_message_headers_decoded"] == 2
    assert "Subject: =?utf-8?b?A?=" in fallback.full_visible_body
    assert fallback.counters["mime_message_header_decode_errors"] == 1


@pytest.mark.parametrize(
    "body, reason",
    [
        (
            "Content-Type: text/plain\nContent-Transfer-Encoding: base64\n\n%%%%",
            EnronCleaningReason.MIME_TRANSFER_INVALID,
        ),
        (
            "Content-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n\nbad=QZ",
            EnronCleaningReason.MIME_TRANSFER_INVALID,
        ),
        (
            "Content-Type: text/plain\nContent-Transfer-Encoding: x-private\n\nopaque",
            EnronCleaningReason.MIME_TRANSFER_UNSUPPORTED,
        ),
        (
            "Content-Type: text/plain; charset=x-private\nContent-Transfer-Encoding: base64\n\nb3BhcXVl",
            EnronCleaningReason.MIME_CHARSET_UNSUPPORTED,
        ),
        (
            "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n/w==",
            EnronCleaningReason.MIME_CHARSET_INVALID,
        ),
        (
            'Content-Type: multipart/mixed; boundary="missing-close"\n\n--missing-close\n\nbody',
            EnronCleaningReason.MIME_STRUCTURE,
        ),
    ],
)
def test_malformed_explicit_mime_fails_with_generic_error(body: str, reason: EnronCleaningReason) -> None:
    with pytest.raises(EnronCleaningError, match="^invalid or unsafe Enron text$") as caught:
        clean_email_body(body, 5_000, 10_000)
    assert caught.value.reason is reason


def test_reply_forward_and_quotes_have_separate_recall_views() -> None:
    body = "\n".join(
        [
            "My answer",
            "> quoted address alice@example.com",
            "Inline reply remains",
            "On Tue, Bob wrote:",
            "> another quote",
            "Another inline reply remains",
            "-----Original Message-----",
            "From: Old Sender",
            "Sent: Monday",
            "To: Alice",
            "Subject: Old",
            "Old unquoted message",
        ]
    )

    result = clean_email_body(body, 5_000, 10_000)

    assert result.full_visible_body == body
    assert result.current_body == "My answer\nInline reply remains\nAnother inline reply remains"
    assert "alice@example.com" in result.full_visible_body
    assert "alice@example.com" not in result.current_body
    assert result.counters["quoted_lines_removed"] == 2
    assert result.counters["quoted_regions"] == 2
    assert result.counters["quoted_reply_markers"] == 1
    assert result.counters["reply_regions"] == 2


def test_forward_marker_removes_only_current_region() -> None:
    result = clean_email_body("Current\n\nBegin forwarded message:\nPrivate forwarded text", 1_000, 2_000)

    assert result.full_visible_body.endswith("Private forwarded text")
    assert result.current_body == "Current"
    assert result.counters["forward_regions"] == 1


def test_header_like_prose_is_retained_without_a_strong_header_block() -> None:
    body = "From: this is a prose label\nOnly one header-like line\nTo be continued"

    assert clean_email_body(body, 1_000, 2_000).current_body == body


def test_current_contact_form_header_block_is_not_misclassified_as_a_reply() -> None:
    body = "\n".join(
        [
            "Current request",
            "From: alice.private@example.test",
            "Date: today",
            "To: support.private@example.test",
            "Subject: Please call",
            "Phone: +1 555 0100",
        ]
    )

    result = clean_email_body(body, 2_000, 5_000)

    assert result.current_body == body


def test_signature_is_retained_for_recall_and_removed_only_from_grouping_core() -> None:
    body = "Please call me.\n\n-- \nAlice Example\n+1 555 0100"

    result = clean_email_body(body, 1_000, 2_000)

    assert result.full_visible_body == "Please call me.\n\n--\nAlice Example\n+1 555 0100"
    assert result.current_body == result.full_visible_body
    assert result.current_body_core == "Please call me."
    assert "+1 555 0100" in result.current_body
    assert result.counters["signature_regions"] == 1
    assert result.counters["signature_lines_annotated"] == 3


def test_known_client_template_is_retained_but_annotated_for_grouping() -> None:
    result = clean_email_body("Short reply\n\nSent from my iPhone", 1_000, 2_000)

    assert result.current_body == "Short reply\n\nSent from my iPhone"
    assert result.current_body_core == "Short reply"
    assert result.counters["template_regions"] == 1


def test_grouping_and_thread_subject_normalization_is_deterministic() -> None:
    assert normalize_grouping_text("  StraßE\u00a0Ａ\u202e  ") == "strasse a"
    assert normalize_thread_subject(" RE[2]: Fwd:  Quarterly Ｒｅｐｏｒｔ ") == "quarterly report"
    assert normalize_thread_subject(" Re: FW: ") is None
    with pytest.raises(EnronCleaningError) as caught:
        normalize_grouping_text("\ufdfa")
    assert caught.value.reason is EnronCleaningReason.GROUPING_EXPANSION_LIMIT


def test_cleaning_is_deterministic_and_counters_are_immutable() -> None:
    body = "<p>Hello</p>\r\n\r\n-- \r\nAlice"

    first = clean_email_body(body, 1_000, 2_000)
    second = clean_email_body(body, 1_000, 2_000)

    assert first == second
    assert tuple(first.counters) == tuple(sorted(first.counters))
    with pytest.raises(TypeError):
        cast(Any, first.counters)["html_detected"] = 99


def test_body_enforces_input_output_and_parser_budgets() -> None:
    with pytest.raises(EnronCleaningError):
        clean_email_body("abcd", 3, 100)
    with pytest.raises(EnronCleaningError):
        clean_email_body("é", 2, 1)

    too_deep = "<div>" * 257 + "visible" + "</div>" * 257
    with pytest.raises(EnronCleaningError, match="^invalid or unsafe Enron text$") as caught:
        clean_email_body(too_deep, len(too_deep) + 10, len(too_deep.encode()) + 10)
    assert caught.value.reason is EnronCleaningReason.HTML_STRUCTURE_LIMIT


def test_multipart_part_budget_has_a_stable_reason() -> None:
    lines = ['Content-Type: multipart/mixed; boundary="many"', ""]
    for index in range(65):
        lines.extend(("--many", "", f"part {index}"))
    lines.append("--many--")
    body = "\n".join(lines)

    with pytest.raises(EnronCleaningError, match="^invalid or unsafe Enron text$") as caught:
        clean_email_body(body, len(body) + 1, len(body.encode()) + 1)
    assert caught.value.reason is EnronCleaningReason.MIME_STRUCTURE_LIMIT
