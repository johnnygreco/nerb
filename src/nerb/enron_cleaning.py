"""Bounded, recall-first text cleaning for the private Enron preparation pipeline.

The functions in this module are deliberately pure.  They do not read files, use
the network, inspect process state, or learn corpus-dependent rules.  In
particular, signatures and known mail-client templates remain in recall-bearing
views; only the explicitly grouping-only view may omit a strongly identified
tail.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import quopri
import re
import unicodedata
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from email.errors import HeaderParseError
from email.header import decode_header
from enum import Enum
from html.parser import HTMLParser
from types import MappingProxyType

_GENERIC_ERROR = "invalid or unsafe Enron text"


class EnronCleaningReason(str, Enum):
    """Closed, privacy-safe reason codes for aggregate cleaning diagnostics."""

    INVALID_TYPE = "invalid_type"
    INVALID_FIELD = "invalid_field"
    INVALID_LIMIT = "invalid_limit"
    INVALID_UNICODE = "invalid_unicode"
    INPUT_CHAR_LIMIT = "input_char_limit"
    INPUT_BYTE_LIMIT = "input_byte_limit"
    OUTPUT_CHAR_LIMIT = "output_char_limit"
    OUTPUT_BYTE_LIMIT = "output_byte_limit"
    MIME_STRUCTURE = "mime_structure"
    MIME_STRUCTURE_LIMIT = "mime_structure_limit"
    MIME_TRANSFER_UNSUPPORTED = "mime_transfer_unsupported"
    MIME_TRANSFER_INVALID = "mime_transfer_invalid"
    MIME_CHARSET_UNSUPPORTED = "mime_charset_unsupported"
    MIME_CHARSET_INVALID = "mime_charset_invalid"
    HTML_STRUCTURE_LIMIT = "html_structure_limit"
    GROUPING_EXPANSION_LIMIT = "grouping_expansion_limit"

    def __str__(self) -> str:
        return self.value


class EnronCleaningError(ValueError):
    """A generic, non-echoing error for invalid or unsafe cleaning input."""

    def __init__(self, reason: EnronCleaningReason) -> None:
        self.reason = reason if isinstance(reason, EnronCleaningReason) else EnronCleaningReason.INVALID_TYPE
        super().__init__(_GENERIC_ERROR)

    @property
    def code(self) -> str:
        """Return the stable string form used in aggregate counters."""

        return self.reason.value


CLEANING_POLICY_VERSION = "nerb.enron-cleaning.v2.2"
_CLEANING_POLICY_SPEC = """\
strict-str;utf8-strict;input-and-output-char-and-byte-bounds;lf;nfc;
c0-c1-to-space-except-tab-lf;unicode-line-separators-to-lf;
remove-bidi-controls-and-default-ignorables;remove-zwnj-zwj-inside-ascii-identifiers;
collapse-horizontal-space-and-blank-runs;explicit-anchored-mime-only;
strict-qp-base64-finite-charsets;bounded-multipart;visible-html-no-resources;
headerless-qp-requires-multiple-valid-escapes-and-encoded-hard-line-break;
multipart-alternative-union-of-distinct-normalized-visible-text;
safe-html-attribute-values-alt-title-aria-label-placeholder-value;
never-retain-href-src-style-or-event-attributes;
retain-bounded-nonattachment-text-subtypes-and-inline-rfc822-visible-text;
closed-non-echoing-cleaning-error-reason-codes;
strong-original-forward-tail-segmentation;on-wrote-marker-and-angle-quotes;
signatures-and-known-templates-retained-in-full-and-current;
strong-tail-removal-only-in-current-body-core
"""
CLEANING_POLICY_SHA256 = hashlib.sha256(_CLEANING_POLICY_SPEC.encode("utf-8")).hexdigest()

GROUPING_TEXT_POLICY_VERSION = "nerb.enron-grouping-text.v2.2"
_GROUPING_TEXT_POLICY_SPEC = """\
cleaning-policy-v2.2;nfkc;casefold;all-whitespace-to-ascii-space;
remove-bidi-controls-and-default-ignorables;remove-zwnj-zwj-inside-ascii-identifiers;
bounded-fourfold-expansion;thread-prefixes-re-fw-fwd-with-optional-counter
"""
GROUPING_TEXT_POLICY_SHA256 = hashlib.sha256(_GROUPING_TEXT_POLICY_SPEC.encode("utf-8")).hexdigest()


_MAX_MIME_HEADER_LINES = 64
_MAX_MIME_HEADER_CHARS = 16_384
_MAX_MIME_PARTS = 64
_MAX_MIME_DEPTH = 4
_MAX_HTML_TAGS = 20_000
_MAX_HTML_DEPTH = 256
_MAX_GROUPING_CHARS = 4_000_000
_MAX_GROUPING_UTF8_BYTES = 16_000_000
_MAX_GROUPING_EXPANSION = 4

_BIDI_CONTROLS = frozenset(
    {
        "\u061c",  # Arabic letter mark
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u202a",  # embedding/override controls
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",  # isolate controls
        "\u2067",
        "\u2068",
        "\u2069",
    }
)
_REMOVED_ZERO_WIDTH = frozenset({"\u200b", "\u2060", "\ufeff"})
_PRESERVED_JOIN_CONTROLS = frozenset({"\u200c", "\u200d"})
_UNICODE_LINE_SEPARATORS = frozenset({"\u0085", "\u2028", "\u2029"})

_COUNTER_NAMES = (
    "base64_decoded",
    "bidi_chars_removed",
    "blank_lines_removed",
    "control_chars_replaced",
    "current_body_chars",
    "current_body_lines",
    "current_body_utf8_bytes",
    "current_core_chars",
    "current_core_lines",
    "current_core_utf8_bytes",
    "default_ignorable_chars_removed",
    "forward_chars_removed",
    "forward_lines_removed",
    "forward_regions",
    "full_visible_chars",
    "full_visible_lines",
    "full_visible_utf8_bytes",
    "horizontal_whitespace_chars_removed",
    "headerless_quoted_printable_decoded",
    "html_comments_dropped",
    "html_conditional_comment_chars_kept",
    "html_conditional_comments_kept",
    "html_detected",
    "html_attribute_chars_dropped",
    "html_attribute_chars_retained",
    "html_attributes_dropped",
    "html_attributes_retained",
    "html_hidden_chars_dropped",
    "html_tags_seen",
    "input_chars",
    "input_utf8_bytes",
    "line_endings_normalized",
    "mime_alternative_parts_dropped",
    "mime_alternative_duplicates_dropped",
    "mime_attachment_chars_dropped",
    "mime_attachments_dropped",
    "mime_detected",
    "mime_headers_removed",
    "mime_message_header_decode_errors",
    "mime_message_header_lines_kept",
    "mime_message_headers_decoded",
    "mime_message_parts_kept",
    "mime_nontext_parts_dropped",
    "mime_nontext_chars_dropped",
    "mime_parts_seen",
    "mime_epilogue_chars_kept",
    "mime_preamble_chars_kept",
    "mime_text_parts_kept",
    "output_chars",
    "output_utf8_bytes",
    "quoted_chars_removed",
    "quoted_lines_removed",
    "quoted_printable_decoded",
    "quoted_regions",
    "quoted_reply_markers",
    "reply_chars_removed",
    "reply_lines_removed",
    "reply_regions",
    "signature_chars_annotated",
    "signature_lines_annotated",
    "signature_regions",
    "subject_line_breaks_collapsed",
    "template_chars_annotated",
    "template_lines_annotated",
    "template_regions",
    "unicode_nfc_changed",
    "unicode_nfkc_changed",
    "unicode_separator_lines_normalized",
    "zero_width_chars_removed",
)
CLEANING_COUNTER_NAMES = frozenset(_COUNTER_NAMES)


@dataclass(frozen=True, slots=True)
class CleanedText:
    """A cleaned text value and immutable integer-only audit counters."""

    text: str
    counters: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class CleanedBody:
    """Recall-bearing and grouping-only views of one email body."""

    full_visible_body: str
    current_body: str
    current_body_core: str
    counters: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class _HeaderBlock:
    headers: Mapping[str, str]
    payload: str
    line_count: int


@dataclass(frozen=True, slots=True)
class _DecodedMime:
    text: str
    rank: int


@dataclass(frozen=True, slots=True)
class _MultipartBody:
    parts: tuple[str, ...]
    preamble: str
    epilogue: str


@dataclass(frozen=True, slots=True)
class _MessageHeaderBlock:
    headers: Mapping[str, str]
    visible_headers: str
    payload: str
    removed_line_count: int
    retained_line_count: int
    decoded_header_count: int
    decode_error_count: int


def _error(reason: EnronCleaningReason) -> EnronCleaningError:
    return EnronCleaningError(reason)


def _validate_limits(max_chars: int, max_utf8_bytes: int) -> None:
    if type(max_chars) is not int or type(max_utf8_bytes) is not int or max_chars <= 0 or max_utf8_bytes <= 0:
        raise _error(EnronCleaningReason.INVALID_LIMIT)


def _validate_text(value: str, max_chars: int, max_utf8_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise _error(EnronCleaningReason.INVALID_TYPE)
    _validate_limits(max_chars, max_utf8_bytes)
    if len(value) > max_chars:
        raise _error(EnronCleaningReason.INPUT_CHAR_LIMIT)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _error(EnronCleaningReason.INVALID_UNICODE) from None
    if len(encoded) > max_utf8_bytes:
        raise _error(EnronCleaningReason.INPUT_BYTE_LIMIT)
    return encoded


def _check_output(value: str, max_chars: int, max_utf8_bytes: int) -> bytes:
    if len(value) > max_chars:
        raise _error(EnronCleaningReason.OUTPUT_CHAR_LIMIT)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _error(EnronCleaningReason.INVALID_UNICODE) from None
    if len(encoded) > max_utf8_bytes:
        raise _error(EnronCleaningReason.OUTPUT_BYTE_LIMIT)
    return encoded


def _freeze_counters(counters: Counter[str]) -> Mapping[str, int]:
    values = {name: int(counters.get(name, 0)) for name in _COUNTER_NAMES}
    for name, value in counters.items():
        if name not in values:
            values[name] = int(value)
    return MappingProxyType(dict(sorted(values.items())))


def _normalize_line_endings(value: str, counters: Counter[str]) -> str:
    crlf_count = value.count("\r\n")
    value = value.replace("\r\n", "\n")
    cr_count = value.count("\r")
    value = value.replace("\r", "\n")
    counters["line_endings_normalized"] += crlf_count + cr_count

    if any(separator in value for separator in _UNICODE_LINE_SEPARATORS):
        pieces: list[str] = []
        separator_count = 0
        for character in value:
            if character in _UNICODE_LINE_SEPARATORS:
                pieces.append("\n")
                separator_count += 1
            else:
                pieces.append(character)
        value = "".join(pieces)
        counters["line_endings_normalized"] += separator_count
        counters["unicode_separator_lines_normalized"] += separator_count
    return value


def _collapse_layout(value: str, counters: Counter[str]) -> str:
    normalized_lines: list[str] = []
    for line in value.split("\n"):
        output: list[str] = []
        pending_space = False
        removed = 0
        for character in line:
            if character == " " or character == "\t" or character.isspace():
                if output:
                    if pending_space:
                        removed += 1
                    pending_space = True
                else:
                    removed += 1
                continue
            if pending_space:
                output.append(" ")
                pending_space = False
            output.append(character)
        if pending_space:
            removed += 1
        counters["horizontal_whitespace_chars_removed"] += removed
        normalized_lines.append("".join(output))

    collapsed: list[str] = []
    blank_pending = False
    started = False
    for line in normalized_lines:
        if not line:
            if not started:
                counters["blank_lines_removed"] += 1
                continue
            if blank_pending:
                counters["blank_lines_removed"] += 1
            else:
                blank_pending = True
            continue
        if blank_pending:
            collapsed.append("")
            blank_pending = False
        collapsed.append(line)
        started = True
    if blank_pending:
        counters["blank_lines_removed"] += 1
    return "\n".join(collapsed)


def _normalize_unicode_layout(value: str, counters: Counter[str]) -> str:
    nfc = unicodedata.normalize("NFC", value)
    if nfc != value:
        counters["unicode_nfc_changed"] += 1

    output: list[str] = []
    for index, character in enumerate(nfc):
        if character in _BIDI_CONTROLS:
            counters["bidi_chars_removed"] += 1
            continue
        if character in _REMOVED_ZERO_WIDTH:
            counters["zero_width_chars_removed"] += 1
            continue
        if _is_identifier_join_control(nfc, index):
            counters["default_ignorable_chars_removed"] += 1
            continue
        if _is_default_ignorable(character):
            counters["default_ignorable_chars_removed"] += 1
            continue
        if character in {"\n", "\t"}:
            output.append(character)
            continue
        if unicodedata.category(character) == "Cc":
            output.append(" ")
            counters["control_chars_replaced"] += 1
            continue
        output.append(character)
    return _collapse_layout("".join(output), counters)


def _is_default_ignorable(character: str) -> bool:
    """Return whether a Unicode default-ignorable should be removed from detector text."""

    if character in _PRESERVED_JOIN_CONTROLS:
        return False
    codepoint = ord(character)
    return (
        codepoint in {0x00AD, 0x034F, 0x061C, 0x180E, 0x3164, 0xFFA0}
        or 0x115F <= codepoint <= 0x1160
        or 0x17B4 <= codepoint <= 0x17B5
        or 0x180B <= codepoint <= 0x180F
        or 0x200B <= codepoint <= 0x200F
        or 0x202A <= codepoint <= 0x202E
        or 0x2060 <= codepoint <= 0x206F
        or 0xFE00 <= codepoint <= 0xFE0F
        or codepoint == 0xFEFF
        or 0xFFF0 <= codepoint <= 0xFFF8
        or 0x1BCA0 <= codepoint <= 0x1BCA3
        or 0x1D173 <= codepoint <= 0x1D17A
        or 0xE0000 <= codepoint <= 0xE0FFF
    )


def _is_identifier_join_control(value: str, index: int) -> bool:
    if value[index] not in _PRESERVED_JOIN_CONTROLS or index == 0 or index + 1 >= len(value):
        return False
    identifier_chars = "@._+-'"
    return (
        value[index - 1].isascii()
        and (value[index - 1].isalnum() or value[index - 1] in identifier_chars)
        and value[index + 1].isascii()
        and (value[index + 1].isalnum() or value[index + 1] in identifier_chars)
    )


def normalize_natural_text(value: str, field: str, max_chars: int, max_utf8_bytes: int) -> CleanedText:
    """Normalize natural text without interpreting it as an email or HTML document.

    ``max_chars`` and ``max_utf8_bytes`` bound both the input and output.  The
    ``field`` label is validated but never included in errors or output, keeping
    failures non-echoing.
    """

    if not isinstance(field, str) or not field or len(field) > 64:
        raise _error(EnronCleaningReason.INVALID_FIELD)
    encoded = _validate_text(value, max_chars, max_utf8_bytes)
    counters: Counter[str] = Counter(input_chars=len(value), input_utf8_bytes=len(encoded))
    normalized = _normalize_line_endings(value, counters)
    normalized = _normalize_unicode_layout(normalized, counters)
    output_bytes = _check_output(normalized, max_chars, max_utf8_bytes)
    counters["output_chars"] = len(normalized)
    counters["output_utf8_bytes"] = len(output_bytes)
    return CleanedText(normalized, _freeze_counters(counters))


def clean_subject(value: str, max_chars: int, max_utf8_bytes: int) -> CleanedText:
    """Clean a subject as one natural-text line without MIME or HTML parsing."""

    result = normalize_natural_text(value, "subject", max_chars, max_utf8_bytes)
    counters: Counter[str] = Counter(result.counters)
    line_breaks = result.text.count("\n")
    subject = " ".join(part for part in result.text.split("\n") if part)
    subject = re.sub(r" +", " ", subject).strip()
    output_bytes = _check_output(subject, max_chars, max_utf8_bytes)
    counters["subject_line_breaks_collapsed"] += line_breaks
    counters["output_chars"] = len(subject)
    counters["output_utf8_bytes"] = len(output_bytes)
    return CleanedText(subject, _freeze_counters(counters))


_MIME_START_RE = re.compile(r"\A(?:content-type|mime-version|content-transfer-encoding)\s*:", re.IGNORECASE)
_HEADER_RE = re.compile(r"\A([A-Za-z][A-Za-z0-9-]{0,63}):[ \t]*(.*)\Z")
_TOKEN_RE = re.compile(r"\A[a-z0-9!#$&^_.+\-]+\Z", re.IGNORECASE)


def _parse_header_block(value: str, *, require_content_type: bool, strict: bool) -> _HeaderBlock | None:
    lines = value.split("\n")
    try:
        separator = lines.index("")
    except ValueError:
        if strict:
            raise _error(EnronCleaningReason.MIME_STRUCTURE)
        return None

    header_lines = lines[:separator]
    if not header_lines and require_content_type:
        return None
    header_chars = sum(len(line) + 1 for line in header_lines)
    if len(header_lines) > _MAX_MIME_HEADER_LINES or header_chars > _MAX_MIME_HEADER_CHARS:
        raise _error(EnronCleaningReason.MIME_STRUCTURE_LIMIT)

    unfolded: list[str] = []
    for line in header_lines:
        if line.startswith((" ", "\t")):
            if not unfolded:
                raise _error(EnronCleaningReason.MIME_STRUCTURE)
            unfolded[-1] = f"{unfolded[-1]} {line.strip()}"
        else:
            unfolded.append(line)

    headers: dict[str, str] = {}
    for line in unfolded:
        match = _HEADER_RE.fullmatch(line)
        if match is None:
            if strict:
                raise _error(EnronCleaningReason.MIME_STRUCTURE)
            return None
        name = match.group(1).lower()
        if name in headers:
            raise _error(EnronCleaningReason.MIME_STRUCTURE)
        headers[name] = match.group(2).strip()

    if require_content_type and "content-type" not in headers:
        return None
    payload = "\n".join(lines[separator + 1 :])
    return _HeaderBlock(MappingProxyType(headers), payload, len(header_lines) + 1)


def _parse_message_header_block(value: str) -> _MessageHeaderBlock | None:
    """Parse bounded RFC-822 headers while permitting ordinary repeated fields."""

    lines = value.split("\n")
    try:
        separator = lines.index("")
    except ValueError:
        return None
    header_lines = lines[:separator]
    header_chars = sum(len(line) + 1 for line in header_lines)
    if len(header_lines) > _MAX_MIME_HEADER_LINES or header_chars > _MAX_MIME_HEADER_CHARS:
        raise _error(EnronCleaningReason.MIME_STRUCTURE_LIMIT)

    unfolded: list[tuple[str, int]] = []
    for line in header_lines:
        if line.startswith((" ", "\t")):
            if not unfolded:
                return None
            previous, physical_lines = unfolded[-1]
            unfolded[-1] = (f"{previous} {line.strip()}", physical_lines + 1)
        else:
            unfolded.append((line, 1))

    control_names = {"content-disposition", "content-transfer-encoding", "content-type", "mime-version"}
    visible_names = {
        "bcc",
        "cc",
        "from",
        "in-reply-to",
        "message-id",
        "references",
        "reply-to",
        "resent-from",
        "resent-to",
        "sender",
        "subject",
        "to",
    }
    identifier_names = {"in-reply-to", "message-id", "references"}
    controls: dict[str, str] = {}
    visible: list[str] = []
    retained_line_count = 0
    decoded_header_count = 0
    decode_error_count = 0
    for line, physical_lines in unfolded:
        match = _HEADER_RE.fullmatch(line)
        if match is None:
            return None
        name = match.group(1).lower()
        raw_value = match.group(2).strip()
        if name in control_names:
            if name in controls:
                return None
            controls[name] = raw_value
        if name in visible_names:
            rendered_value = raw_value
            if name not in identifier_names:
                rendered_value, decoded_count, error_count = _decode_visible_message_header(raw_value)
                decoded_header_count += decoded_count
                decode_error_count += error_count
            visible.append(f"{match.group(1)}: {rendered_value}")
            retained_line_count += physical_lines
    return _MessageHeaderBlock(
        headers=MappingProxyType(controls),
        visible_headers="\n".join(visible),
        payload="\n".join(lines[separator + 1 :]),
        removed_line_count=len(header_lines) - retained_line_count + 1,
        retained_line_count=retained_line_count,
        decoded_header_count=decoded_header_count,
        decode_error_count=decode_error_count,
    )


def _decode_visible_message_header(value: str) -> tuple[str, int, int]:
    try:
        decoded = decode_header(value)
    except (HeaderParseError, LookupError, ValueError):
        return value, 0, 1
    pieces: list[str] = []
    decoded_any = False
    for item, charset in decoded:
        if not isinstance(item, bytes):
            pieces.append(item)
            continue
        try:
            piece = item.decode(charset or "ascii", errors="strict")
        except (LookupError, UnicodeError):
            return value, 0, 1
        pieces.append(piece)
        decoded_any = True
    return "".join(pieces), int(decoded_any), 0


def _split_semicolon_parameters(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\" and quoted:
            escaped = True
            current.append(character)
            continue
        if character == '"':
            quoted = not quoted
            current.append(character)
            continue
        if character == ";" and not quoted:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    if quoted or escaped:
        raise _error(EnronCleaningReason.MIME_STRUCTURE)
    parts.append("".join(current).strip())
    return parts


def _parse_content_type(value: str) -> tuple[str, Mapping[str, str]]:
    pieces = _split_semicolon_parameters(value)
    media_type = pieces[0].lower()
    if media_type.count("/") != 1 or any(not _TOKEN_RE.fullmatch(token) for token in media_type.split("/")):
        raise _error(EnronCleaningReason.MIME_STRUCTURE)
    parameters: dict[str, str] = {}
    for piece in pieces[1:]:
        if not piece or "=" not in piece:
            raise _error(EnronCleaningReason.MIME_STRUCTURE)
        name, raw_value = piece.split("=", 1)
        name = name.strip().lower()
        if not _TOKEN_RE.fullmatch(name) or name in parameters:
            raise _error(EnronCleaningReason.MIME_STRUCTURE)
        raw_value = raw_value.strip()
        if raw_value.startswith('"'):
            if len(raw_value) < 2 or not raw_value.endswith('"'):
                raise _error(EnronCleaningReason.MIME_STRUCTURE)
            raw_value = raw_value[1:-1]
            raw_value = raw_value.replace('\\"', '"').replace("\\\\", "\\")
        elif not raw_value or not _TOKEN_RE.fullmatch(raw_value):
            raise _error(EnronCleaningReason.MIME_STRUCTURE)
        parameters[name] = raw_value
    return media_type, MappingProxyType(parameters)


def _decode_transfer(
    payload: str,
    transfer_encoding: str,
    charset: str | None,
    max_chars: int,
    max_utf8_bytes: int,
    counters: Counter[str],
) -> str:
    encoding = transfer_encoding.strip().lower()
    if encoding in {"", "7bit", "8bit", "binary"}:
        _check_output(payload, max_chars, max_utf8_bytes)
        return payload
    if encoding not in {"quoted-printable", "base64"}:
        raise _error(EnronCleaningReason.MIME_TRANSFER_UNSUPPORTED)
    try:
        ascii_payload = payload.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise _error(EnronCleaningReason.MIME_TRANSFER_INVALID) from None

    if encoding == "quoted-printable":
        if _scan_quoted_printable(payload) is None:
            raise _error(EnronCleaningReason.MIME_TRANSFER_INVALID)
        decoded = quopri.decodestring(ascii_payload)
        counters["quoted_printable_decoded"] += 1
    else:
        compact = b"".join(ascii_payload.split())
        try:
            decoded = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            raise _error(EnronCleaningReason.MIME_TRANSFER_INVALID) from None
        counters["base64_decoded"] += 1
    if len(decoded) > max_utf8_bytes:
        raise _error(EnronCleaningReason.OUTPUT_BYTE_LIMIT)

    normalized_charset = (charset or "utf-8").strip().lower().replace("_", "-")
    aliases = {
        "ascii": "ascii",
        "cp1252": "cp1252",
        "iso-8859-1": "latin-1",
        "latin-1": "latin-1",
        "latin1": "latin-1",
        "us-ascii": "ascii",
        "utf-8": "utf-8",
        "utf8": "utf-8",
        "windows-1252": "cp1252",
    }
    codec = aliases.get(normalized_charset)
    if codec is None:
        raise _error(EnronCleaningReason.MIME_CHARSET_UNSUPPORTED)
    try:
        text = decoded.decode(codec, errors="strict")
    except UnicodeDecodeError:
        raise _error(EnronCleaningReason.MIME_CHARSET_INVALID) from None
    _check_output(text, max_chars, max_utf8_bytes)
    return text


def _scan_quoted_printable(value: str) -> tuple[int, bool] | None:
    escape_count = 0
    has_hard_line_break = False
    index = 0
    while index < len(value):
        if value[index] != "=":
            index += 1
            continue
        if index + 1 < len(value) and value[index + 1] == "\n":
            index += 2
            continue
        if index + 2 >= len(value) or not re.fullmatch(r"[0-9A-Fa-f]{2}", value[index + 1 : index + 3]):
            return None
        escape = value[index + 1 : index + 3].lower()
        escape_count += 1
        has_hard_line_break = has_hard_line_break or escape in {"0a", "0d"}
        index += 3
    return escape_count, has_hard_line_break


def _decode_headerless_quoted_printable(
    value: str, max_chars: int, max_utf8_bytes: int, counters: Counter[str]
) -> tuple[str, bool]:
    scan = _scan_quoted_printable(value)
    if scan is None or scan[0] < 2 or not scan[1]:
        return value, False
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = quopri.decodestring(encoded).decode("utf-8", errors="strict")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value, False
    _check_output(decoded, max_chars, max_utf8_bytes)
    counters["headerless_quoted_printable_decoded"] += 1
    counters["quoted_printable_decoded"] += 1
    counters["mime_detected"] += 1
    return decoded, True


def _split_multipart(payload: str, boundary: str) -> _MultipartBody:
    if not boundary:
        raise _error(EnronCleaningReason.MIME_STRUCTURE)
    if len(boundary) > 70:
        raise _error(EnronCleaningReason.MIME_STRUCTURE_LIMIT)
    try:
        boundary.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise _error(EnronCleaningReason.MIME_STRUCTURE) from None
    if any(ord(character) < 33 or ord(character) > 126 for character in boundary):
        raise _error(EnronCleaningReason.MIME_STRUCTURE)

    opening = f"--{boundary}"
    closing = f"--{boundary}--"
    parts: list[str] = []
    preamble: list[str] = []
    epilogue: list[str] = []
    current: list[str] | None = None
    saw_opening = False
    saw_closing = False
    for line in payload.split("\n"):
        marker = line.rstrip(" \t")
        if saw_closing:
            epilogue.append(line)
            continue
        if marker == opening:
            saw_opening = True
            if current is not None:
                parts.append("\n".join(current))
                if len(parts) > _MAX_MIME_PARTS:
                    raise _error(EnronCleaningReason.MIME_STRUCTURE_LIMIT)
            current = []
            continue
        if marker == closing:
            if current is not None:
                parts.append("\n".join(current))
            saw_closing = True
            current = None
            continue
        if current is not None:
            current.append(line)
        elif not saw_opening:
            preamble.append(line)
    if len(parts) > _MAX_MIME_PARTS:
        raise _error(EnronCleaningReason.MIME_STRUCTURE_LIMIT)
    if not saw_opening or not saw_closing or not parts:
        raise _error(EnronCleaningReason.MIME_STRUCTURE)
    return _MultipartBody(tuple(parts), "\n".join(preamble), "\n".join(epilogue))


_HTML_SIGNAL_RE = re.compile(
    r"<(?:html|body|div|p|br|table|tr|td|th|ul|ol|li|span|a|strong|em|h[1-6]|"
    r"img|input|button|form|textarea|select|option|label|area|meter|progress)(?:\s[^<>]*|\s*)/?>",
    re.IGNORECASE,
)
_HTML_BLOCK_TAGS = frozenset(
    {
        "address",
        "article",
        "aside",
        "blockquote",
        "body",
        "div",
        "dl",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hr",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "tr",
        "ul",
    }
)
_HTML_HIDDEN_TAGS = frozenset({"head", "script", "style", "template"})
_HTML_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)
_HTML_GLOBAL_NATURAL_ATTRIBUTES = frozenset(
    {
        "aria-description",
        "aria-label",
        "aria-placeholder",
        "aria-roledescription",
        "aria-valuetext",
        "title",
    }
)
_HTML_MSO_CONDITIONAL_COMMENT_RE = re.compile(
    r"\A\[if(?=[^\]]*\bmso\b)[^\]]{0,64}\]>(.*)<!\[endif\]\Z",
    re.IGNORECASE | re.DOTALL,
)
_HTML_TAG_NATURAL_ATTRIBUTES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "area": frozenset({"alt"}),
        "button": frozenset({"value"}),
        "img": frozenset({"alt"}),
        "input": frozenset({"alt", "placeholder", "value"}),
        "meter": frozenset({"value"}),
        "option": frozenset({"label", "value"}),
        "progress": frozenset({"value"}),
        "textarea": frozenset({"placeholder"}),
    }
)


class _VisibleHTMLParser(HTMLParser):
    def __init__(self, max_chars: int, conditional_depth: int = 0) -> None:
        super().__init__(convert_charrefs=True)
        self.max_chars = max_chars
        self.pieces: list[str] = []
        self.output_chars = 0
        self.tags_seen = 0
        self.comments_dropped = 0
        self.conditional_comments_kept = 0
        self.conditional_comment_chars_kept = 0
        self.attribute_chars_dropped = 0
        self.attribute_chars_retained = 0
        self.attributes_dropped = 0
        self.attributes_retained = 0
        self.hidden_chars_dropped = 0
        self.stack: list[str] = []
        self.hidden_depth = 0
        self.pending_attribute_keys: set[str] = set()
        self.conditional_depth = conditional_depth

    def _append(self, value: str) -> None:
        if not value:
            return
        self.output_chars += len(value)
        if self.output_chars > self.max_chars:
            raise _error(EnronCleaningReason.OUTPUT_CHAR_LIMIT)
        self.pieces.append(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags_seen += 1
        tag = tag.lower()
        if tag not in _HTML_VOID_TAGS:
            self.stack.append(tag)
        if self.tags_seen > _MAX_HTML_TAGS or len(self.stack) > _MAX_HTML_DEPTH:
            raise _error(EnronCleaningReason.HTML_STRUCTURE_LIMIT)
        if tag in _HTML_HIDDEN_TAGS:
            self.hidden_depth += 1
            self._drop_attributes(attrs)
            return
        if self.hidden_depth:
            self._drop_attributes(attrs)
            return
        if tag == "br" or tag in _HTML_BLOCK_TAGS:
            self._append("\n")
        elif tag in {"td", "th"}:
            self._append(" ")
        self._retain_natural_attributes(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in _HTML_VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        was_hidden = bool(self.hidden_depth)
        if tag in self.stack:
            reverse_index = self.stack[::-1].index(tag)
            start = len(self.stack) - reverse_index - 1
            popped = self.stack[start:]
            del self.stack[start:]
            self.hidden_depth -= sum(item in _HTML_HIDDEN_TAGS for item in popped)
        if not was_hidden and (tag in _HTML_BLOCK_TAGS or tag in {"td", "th"}):
            self._append("\n" if tag in _HTML_BLOCK_TAGS else " ")

    def handle_data(self, data: str) -> None:
        if self.hidden_depth:
            self.hidden_chars_dropped += len(data)
        else:
            key = _html_attribute_dedup_key(data)
            if key and key in self.pending_attribute_keys:
                self.pending_attribute_keys.clear()
                return
            self.pending_attribute_keys.clear()
            self._append(data)

    def handle_comment(self, data: str) -> None:
        match = _HTML_MSO_CONDITIONAL_COMMENT_RE.fullmatch(data)
        if match is None or self.conditional_depth >= _MAX_MIME_DEPTH:
            self.comments_dropped += 1
            return
        nested = _VisibleHTMLParser(max(1, self.max_chars - self.output_chars), self.conditional_depth + 1)
        nested.feed(match.group(1))
        nested.close()
        self.tags_seen += nested.tags_seen
        if self.tags_seen > _MAX_HTML_TAGS:
            raise _error(EnronCleaningReason.HTML_STRUCTURE_LIMIT)
        self.comments_dropped += nested.comments_dropped
        self.conditional_comments_kept += nested.conditional_comments_kept
        self.conditional_comment_chars_kept += nested.conditional_comment_chars_kept
        self.attribute_chars_dropped += nested.attribute_chars_dropped
        self.attribute_chars_retained += nested.attribute_chars_retained
        self.attributes_dropped += nested.attributes_dropped
        self.attributes_retained += nested.attributes_retained
        self.hidden_chars_dropped += nested.hidden_chars_dropped
        retained = "".join(nested.pieces)
        self._append(retained)
        self.conditional_comments_kept += 1
        self.conditional_comment_chars_kept += len(retained)

    def _drop_attributes(self, attrs: list[tuple[str, str | None]]) -> None:
        for _, value in attrs:
            self.attributes_dropped += 1
            self.attribute_chars_dropped += len(value or "")

    def _retain_natural_attributes(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        allowed = _HTML_GLOBAL_NATURAL_ATTRIBUTES | _HTML_TAG_NATURAL_ATTRIBUTES.get(tag, frozenset())
        seen_on_tag: set[str] = set()
        for name, value in attrs:
            raw_value = value or ""
            key = _html_attribute_dedup_key(raw_value)
            if name not in allowed or not key or key in seen_on_tag:
                self.attributes_dropped += 1
                self.attribute_chars_dropped += len(raw_value)
                continue
            seen_on_tag.add(key)
            self.attributes_retained += 1
            self.attribute_chars_retained += len(raw_value)
            if self.pieces and not self.pieces[-1].endswith((" ", "\n", "\t")):
                self._append(" ")
            self._append(raw_value)
            self._append(" ")
            self.pending_attribute_keys.add(key)


def _html_attribute_dedup_key(value: str) -> str:
    return unicodedata.normalize("NFC", " ".join(value.split()))


def _html_to_visible(value: str, max_chars: int, max_utf8_bytes: int, counters: Counter[str]) -> str:
    parser = _VisibleHTMLParser(max_chars)
    parser.feed(value)
    parser.close()
    visible = "".join(parser.pieces)
    _check_output(visible, max_chars, max_utf8_bytes)
    counters["html_detected"] += 1
    counters["html_tags_seen"] += parser.tags_seen
    counters["html_comments_dropped"] += parser.comments_dropped
    counters["html_conditional_comments_kept"] += parser.conditional_comments_kept
    counters["html_conditional_comment_chars_kept"] += parser.conditional_comment_chars_kept
    counters["html_attribute_chars_dropped"] += parser.attribute_chars_dropped
    counters["html_attribute_chars_retained"] += parser.attribute_chars_retained
    counters["html_attributes_dropped"] += parser.attributes_dropped
    counters["html_attributes_retained"] += parser.attributes_retained
    counters["html_hidden_chars_dropped"] += parser.hidden_chars_dropped
    return visible


def _is_attachment(headers: Mapping[str, str], parameters: Mapping[str, str]) -> bool:
    disposition = headers.get("content-disposition", "").lower()
    return disposition.startswith("attachment") or "filename=" in disposition or "name" in parameters


def _decode_mime_entity(
    headers: Mapping[str, str],
    payload: str,
    depth: int,
    max_chars: int,
    max_utf8_bytes: int,
    counters: Counter[str],
) -> _DecodedMime:
    if depth > _MAX_MIME_DEPTH:
        raise _error(EnronCleaningReason.MIME_STRUCTURE_LIMIT)
    media_type, parameters = _parse_content_type(headers.get("content-type", "text/plain"))
    if _is_attachment(headers, parameters):
        counters["mime_attachment_chars_dropped"] += len(payload)
        counters["mime_attachments_dropped"] += 1
        return _DecodedMime("", 3)

    transfer_encoding = headers.get("content-transfer-encoding", "")
    if media_type.startswith("multipart/"):
        if transfer_encoding.strip().lower() not in {"", "7bit", "8bit", "binary"}:
            raise _error(EnronCleaningReason.MIME_TRANSFER_UNSUPPORTED)
        boundary = parameters.get("boundary")
        if boundary is None:
            raise _error(EnronCleaningReason.MIME_STRUCTURE)
        multipart = _split_multipart(payload, boundary)
        decoded_parts: list[_DecodedMime] = []
        if multipart.preamble:
            counters["mime_preamble_chars_kept"] += len(multipart.preamble)
            decoded_parts.append(_DecodedMime(multipart.preamble, 2))
        for raw_part in multipart.parts:
            counters["mime_parts_seen"] += 1
            block: _HeaderBlock | None
            visible_headers = ""
            if raw_part.startswith("\n"):
                block = _HeaderBlock(MappingProxyType({}), raw_part[1:], 1)
            else:
                looks_mime_headered = bool(
                    re.match(
                        r"\A(?:content-type|content-transfer-encoding|content-disposition|mime-version)\s*:",
                        raw_part,
                        re.IGNORECASE,
                    )
                )
                parsed = _parse_header_block(raw_part, require_content_type=False, strict=looks_mime_headered)
                if parsed is not None and any(
                    name in parsed.headers
                    for name in {"content-type", "content-transfer-encoding", "content-disposition", "mime-version"}
                ):
                    block = parsed
                    visible_headers = "\n".join(
                        f"{name}: {value}"
                        for name, value in parsed.headers.items()
                        if name
                        not in {"content-type", "content-transfer-encoding", "content-disposition", "mime-version"}
                    )
                else:
                    block = _HeaderBlock(MappingProxyType({}), raw_part, 0)
            counters["mime_headers_removed"] += block.line_count
            decoded_part = _decode_mime_entity(
                block.headers,
                block.payload,
                depth + 1,
                max_chars,
                max_utf8_bytes,
                counters,
            )
            if visible_headers:
                combined = "\n\n".join(part for part in (visible_headers, decoded_part.text) if part)
                _check_output(combined, max_chars, max_utf8_bytes)
                decoded_part = _DecodedMime(combined, decoded_part.rank)
            decoded_parts.append(decoded_part)
        if multipart.epilogue:
            counters["mime_epilogue_chars_kept"] += len(multipart.epilogue)
            decoded_parts.append(_DecodedMime(multipart.epilogue, 2))

        if media_type == "multipart/alternative":
            distinct: list[tuple[int, int, str]] = []
            seen: set[bytes] = set()
            for source_index, part in sorted(enumerate(decoded_parts), key=lambda item: (item[1].rank, item[0])):
                if not part.text:
                    continue
                local: Counter[str] = Counter()
                normalized = _normalize_line_endings(part.text, local)
                normalized = _normalize_unicode_layout(normalized, local)
                normalized_bytes = _check_output(normalized, max_chars, max_utf8_bytes)
                counters.update(local)
                if not normalized:
                    continue
                if normalized_bytes in seen:
                    counters["mime_alternative_duplicates_dropped"] += 1
                    counters["mime_alternative_parts_dropped"] += 1
                    continue
                seen.add(normalized_bytes)
                distinct.append((part.rank, source_index, normalized))
            if not distinct:
                return _DecodedMime("", 3)
            joined = "\n\n".join(text for _, _, text in distinct)
            _check_output(joined, max_chars, max_utf8_bytes)
            return _DecodedMime(joined, min(rank for rank, _, _ in distinct))
        nonempty = [part for part in decoded_parts if part.text]
        joined = "\n\n".join(part.text for part in nonempty)
        _check_output(joined, max_chars, max_utf8_bytes)
        return _DecodedMime(joined, min((part.rank for part in nonempty), default=3))

    if media_type == "message/rfc822":
        decoded = _decode_transfer(
            payload,
            transfer_encoding,
            parameters.get("charset"),
            max_chars,
            max_utf8_bytes,
            counters,
        )
        message_block = _parse_message_header_block(decoded)
        if message_block is None:
            counters["mime_message_parts_kept"] += 1
            return _DecodedMime(decoded, 2)
        counters["mime_headers_removed"] += message_block.removed_line_count
        counters["mime_message_header_lines_kept"] += message_block.retained_line_count
        counters["mime_message_headers_decoded"] += message_block.decoded_header_count
        counters["mime_message_header_decode_errors"] += message_block.decode_error_count
        nested = _decode_mime_entity(
            message_block.headers,
            message_block.payload,
            depth + 1,
            max_chars,
            max_utf8_bytes,
            counters,
        )
        visible = "\n\n".join(part for part in (message_block.visible_headers, nested.text) if part)
        _check_output(visible, max_chars, max_utf8_bytes)
        counters["mime_message_parts_kept"] += 1
        return _DecodedMime(visible, 2)

    if not media_type.startswith("text/"):
        counters["mime_nontext_chars_dropped"] += len(payload)
        counters["mime_nontext_parts_dropped"] += 1
        return _DecodedMime("", 3)

    decoded = _decode_transfer(
        payload,
        transfer_encoding,
        parameters.get("charset"),
        max_chars,
        max_utf8_bytes,
        counters,
    )
    counters["mime_text_parts_kept"] += 1
    if media_type == "text/html":
        return _DecodedMime(_html_to_visible(decoded, max_chars, max_utf8_bytes, counters), 1)
    return _DecodedMime(decoded, 0 if media_type == "text/plain" else 2)


def _decode_explicit_mime(value: str, max_chars: int, max_utf8_bytes: int, counters: Counter[str]) -> tuple[str, bool]:
    had_bom = value.startswith("\ufeff")
    candidate = value[1:] if had_bom else value
    if not _MIME_START_RE.match(candidate):
        return value, False
    block = _parse_header_block(candidate, require_content_type=True, strict=True)
    if block is None:
        raise _error(EnronCleaningReason.MIME_STRUCTURE)
    if had_bom:
        counters["zero_width_chars_removed"] += 1
    counters["mime_detected"] += 1
    counters["mime_headers_removed"] += block.line_count
    decoded = _decode_mime_entity(block.headers, block.payload, 0, max_chars, max_utf8_bytes, counters)
    return decoded.text, True


_ORIGINAL_MARKER_RE = re.compile(r"^\s*-{2,}\s*original message\s*-{2,}\s*$", re.IGNORECASE)
_FORWARD_MARKER_RE = re.compile(r"^\s*(?:-{2,}\s*)?(?:begin\s+)?forwarded message(?::|\s*-{2,})?\s*$", re.IGNORECASE)
_ON_WROTE_RE = re.compile(r"^\s*on\s+.{1,240}\s+wrote:\s*$", re.IGNORECASE)
_QUOTE_RE = re.compile(r"^\s*>+")
_REPLY_HEADER_RE = re.compile(r"^\s*(from|sent|date|to|cc|subject):\s*\S.*$", re.IGNORECASE)
_SEPARATOR_RE = re.compile(r"^\s*(?:_{8,}|-{8,})\s*$")


def _reply_header_block(lines: list[str], start: int) -> int | None:
    names: set[str] = set()
    end = start
    while end < len(lines) and end < start + 10:
        line = lines[end]
        if not line:
            break
        match = _REPLY_HEADER_RE.fullmatch(line)
        if match is None:
            if line.startswith((" ", "\t")) and names:
                end += 1
                continue
            break
        names.add(match.group(1).lower())
        end += 1
    if "from" in names and names.intersection({"sent", "date"}) and names.intersection({"to", "subject"}):
        return end
    return None


def _segment_current_body(full_body: str, counters: Counter[str]) -> str:
    lines = full_body.split("\n") if full_body else []
    kept: list[str] = []
    index = 0
    in_quote_run = False
    changed = False
    while index < len(lines):
        line = lines[index]
        if _ORIGINAL_MARKER_RE.fullmatch(line):
            changed = True
            removed = lines[index:]
            counters["reply_regions"] += 1
            counters["reply_lines_removed"] += len(removed)
            counters["reply_chars_removed"] += sum(len(item) for item in removed)
            break
        if _FORWARD_MARKER_RE.fullmatch(line):
            changed = True
            removed = lines[index:]
            counters["forward_regions"] += 1
            counters["forward_lines_removed"] += len(removed)
            counters["forward_chars_removed"] += sum(len(item) for item in removed)
            break

        header_end = None
        if _SEPARATOR_RE.fullmatch(line) and index + 1 < len(lines):
            header_end = _reply_header_block(lines, index + 1)
        if header_end is not None:
            changed = True
            removed = lines[index:]
            counters["reply_regions"] += 1
            counters["reply_lines_removed"] += len(removed)
            counters["reply_chars_removed"] += sum(len(item) for item in removed)
            break

        if _ON_WROTE_RE.fullmatch(line):
            changed = True
            counters["quoted_reply_markers"] += 1
            counters["reply_regions"] += 1
            counters["reply_lines_removed"] += 1
            counters["reply_chars_removed"] += len(line)
            in_quote_run = False
            index += 1
            continue

        if _QUOTE_RE.match(line):
            changed = True
            if not in_quote_run:
                counters["quoted_regions"] += 1
                in_quote_run = True
            counters["quoted_lines_removed"] += 1
            counters["quoted_chars_removed"] += len(line)
            index += 1
            continue

        in_quote_run = False
        kept.append(line)
        index += 1

    if not changed:
        return full_body
    local: Counter[str] = Counter()
    return _normalize_unicode_layout("\n".join(kept), local)


_MOBILE_TEMPLATE_RE = re.compile(
    r"^(?:sent from my (?:iphone|ipad|android|mobile device)|get outlook for (?:ios|android)|"
    r"sent from mail for windows)\.?$",
    re.IGNORECASE,
)
_CONFIDENTIAL_TEMPLATE_RE = re.compile(
    r"^(?:confidentiality notice:|this (?:e-?mail|message)(?: and any attachments)? (?:is|may be) confidential)",
    re.IGNORECASE,
)


def _annotate_tail(current_body: str, counters: Counter[str]) -> str:
    if not current_body:
        return ""
    lines = current_body.split("\n")
    signature_start: int | None = None
    tail_start = max(1, len(lines) - 16)
    for index in range(tail_start, len(lines)):
        if lines[index] == "--" and any(line for line in lines[index + 1 :]):
            signature_start = index
            break

    template_start: int | None = None
    for index in range(max(0, len(lines) - 30), len(lines)):
        line = lines[index]
        if _MOBILE_TEMPLATE_RE.fullmatch(line) or _CONFIDENTIAL_TEMPLATE_RE.match(line):
            template_start = index
            break

    if signature_start is not None:
        annotated = lines[signature_start:]
        counters["signature_regions"] += 1
        counters["signature_lines_annotated"] += len(annotated)
        counters["signature_chars_annotated"] += sum(len(line) for line in annotated)
    if template_start is not None:
        annotated = lines[template_start:]
        counters["template_regions"] += 1
        counters["template_lines_annotated"] += len(annotated)
        counters["template_chars_annotated"] += sum(len(line) for line in annotated)

    starts = [start for start in (signature_start, template_start) if start is not None]
    if not starts:
        return current_body
    local: Counter[str] = Counter()
    return _normalize_unicode_layout("\n".join(lines[: min(starts)]), local)


def _line_count(value: str) -> int:
    return value.count("\n") + 1 if value else 0


def clean_email_body(value: str, max_chars: int, max_utf8_bytes: int) -> CleanedBody:
    """Produce recall-bearing full/current body views and a grouping-only core.

    MIME is interpreted only when an explicit MIME header block starts the
    supplied value.  HTML is converted to visible text only when explicitly
    labelled or when a conservative known-tag signal is present.  No resource is
    fetched and no general RFC-822 message parser is invoked.
    """

    encoded = _validate_text(value, max_chars, max_utf8_bytes)
    counters: Counter[str] = Counter(input_chars=len(value), input_utf8_bytes=len(encoded))
    transport_normalized = _normalize_line_endings(value, counters)
    visible, explicit_mime = _decode_explicit_mime(transport_normalized, max_chars, max_utf8_bytes, counters)
    headerless_qp = False
    if not explicit_mime:
        visible, headerless_qp = _decode_headerless_quoted_printable(visible, max_chars, max_utf8_bytes, counters)
    if explicit_mime or headerless_qp:
        visible = _normalize_line_endings(visible, counters)
    if (not explicit_mime or headerless_qp) and _HTML_SIGNAL_RE.search(visible):
        visible = _html_to_visible(visible, max_chars, max_utf8_bytes, counters)
    full_body = _normalize_unicode_layout(visible, counters)
    full_bytes = _check_output(full_body, max_chars, max_utf8_bytes)

    current_body = _segment_current_body(full_body, counters)
    current_bytes = _check_output(current_body, max_chars, max_utf8_bytes)
    current_core = _annotate_tail(current_body, counters)
    core_bytes = _check_output(current_core, max_chars, max_utf8_bytes)

    counters["full_visible_chars"] = len(full_body)
    counters["full_visible_utf8_bytes"] = len(full_bytes)
    counters["full_visible_lines"] = _line_count(full_body)
    counters["current_body_chars"] = len(current_body)
    counters["current_body_utf8_bytes"] = len(current_bytes)
    counters["current_body_lines"] = _line_count(current_body)
    counters["current_core_chars"] = len(current_core)
    counters["current_core_utf8_bytes"] = len(core_bytes)
    counters["current_core_lines"] = _line_count(current_core)
    counters["output_chars"] = len(full_body)
    counters["output_utf8_bytes"] = len(full_bytes)
    return CleanedBody(full_body, current_body, current_core, _freeze_counters(counters))


def normalize_grouping_text(value: str) -> str:
    """Return a bounded compatibility/case-normalized grouping fingerprint text."""

    encoded = _validate_text(value, _MAX_GROUPING_CHARS, _MAX_GROUPING_UTF8_BYTES)
    counters: Counter[str] = Counter()
    value = _normalize_line_endings(value, counters)

    filtered: list[str] = []
    for index, character in enumerate(value):
        if (
            character in _BIDI_CONTROLS
            or character in _REMOVED_ZERO_WIDTH
            or _is_default_ignorable(character)
            or _is_identifier_join_control(value, index)
        ):
            continue
        if character != "\n" and unicodedata.category(character) == "Cc":
            filtered.append(" ")
        else:
            filtered.append(character)
    filtered_value = "".join(filtered)
    nfkc = unicodedata.normalize("NFKC", filtered_value)
    folded = nfkc.casefold()
    if len(folded) > _MAX_GROUPING_CHARS or len(folded) > len(value) * _MAX_GROUPING_EXPANSION:
        raise _error(EnronCleaningReason.GROUPING_EXPANSION_LIMIT)
    grouping = " ".join(folded.split())
    grouping_bytes = _check_output(grouping, _MAX_GROUPING_CHARS, _MAX_GROUPING_UTF8_BYTES)
    if len(grouping_bytes) > len(encoded) * _MAX_GROUPING_EXPANSION:
        raise _error(EnronCleaningReason.GROUPING_EXPANSION_LIMIT)
    return grouping


_THREAD_PREFIX_RE = re.compile(r"\A\s*(?:re|fw|fwd)\s*(?:\[\d+\])?\s*:\s*", re.IGNORECASE)


def normalize_thread_subject(value: str) -> str | None:
    """Normalize common reply/forward prefixes for deterministic thread grouping."""

    subject = normalize_grouping_text(value)
    previous = None
    while subject and subject != previous:
        previous = subject
        subject = _THREAD_PREFIX_RE.sub("", subject, count=1).strip()
    return subject or None


__all__ = [
    "CLEANING_POLICY_SHA256",
    "CLEANING_POLICY_VERSION",
    "GROUPING_TEXT_POLICY_SHA256",
    "GROUPING_TEXT_POLICY_VERSION",
    "CleanedBody",
    "CleanedText",
    "EnronCleaningError",
    "EnronCleaningReason",
    "clean_email_body",
    "clean_subject",
    "normalize_grouping_text",
    "normalize_natural_text",
    "normalize_thread_subject",
]
