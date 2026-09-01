#!/usr/bin/env python3
"""
Patch an iOS IPA without extracting/repacking the whole bundle on disk.

What it does:
  - copies IshinRedirect.dylib into Payload/<App>.app/Frameworks/
  - adds LC_LOAD_DYLIB to the main Mach-O IN PLACE (header padding only)
  - updates CFBundleDisplayName / CFBundleName / CFBundleIdentifier
  - replaces the old bundle-id prefix inside all plist string values
  - finds dpuzzle/dpuzzlegamelayer/sparking across iOS string/plist/text resources
  - updates localized InfoPlist.strings app names too
  - preserves original ZIP metadata and Unix permissions
  - validates the resulting IPA

This script uses only Python's standard library and works on Windows/macOS/Linux.
It intentionally refuses to patch if the Mach-O header has insufficient safe
padding. Refusing is much safer than shifting the binary and corrupting offsets.
"""

from __future__ import annotations

import argparse
import io
import os
import plistlib
import re
import stat
import struct
import sys
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

PATCHER_VERSION = "TRANSCEND-PATCHER-v6-2026-09-02"

DEFAULT_INPUT_IPA = "DokkanTranscend.ipa"
DEFAULT_OUTPUT_IPA = "modded.ipa"
DEFAULT_DYLIB = "IshinRedirect.dylib"
DEFAULT_APP_NAME = "TRANSCEND"
DEFAULT_BUNDLE_ID = "com.Transcend.dbzdokkanGLB"

# Optional legacy bundle-id prefix. The source IPA bundle ID is also auto-detected.
DEFAULT_OLD_BUNDLE_ID = "com.sparkingDokkan.GLB"
LOCALIZABLE_KEY = "dpuzzle/dpuzzlegamelayer/sparking"
LOCALIZABLE_VALUE = "TRANSCEND!!!"
LOCALIZABLE_OLD_VALUE = "SPARKING!!!"

LC_LOAD_DYLIB = 0x0000000C
LC_SEGMENT = 0x00000001
LC_SEGMENT_64 = 0x00000019
CPU_TYPE_ARM64 = 0x0100000C

# Raw magic byte sequences (avoids endianness ambiguity).
MH_MAGIC_32_LE = b"\xce\xfa\xed\xfe"
MH_MAGIC_32_BE = b"\xfe\xed\xfa\xce"
MH_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
MH_MAGIC_64_BE = b"\xfe\xed\xfa\xcf"
FAT_MAGIC_32_BE = b"\xca\xfe\xba\xbe"
FAT_MAGIC_32_LE = b"\xbe\xba\xfe\xca"
FAT_MAGIC_64_BE = b"\xca\xfe\xba\xbf"
FAT_MAGIC_64_LE = b"\xbf\xba\xfe\xca"


class PatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class ThinMachO:
    base: int
    size: int
    endian: str
    is_64: bool
    cputype: int


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def u32(data: bytes | bytearray, offset: int, endian: str) -> int:
    return struct.unpack_from(f"{endian}I", data, offset)[0]


def u64(data: bytes | bytearray, offset: int, endian: str) -> int:
    return struct.unpack_from(f"{endian}Q", data, offset)[0]


def identify_thin(data: bytes | bytearray, base: int, size: int) -> ThinMachO:
    if base < 0 or size < 4 or base + size > len(data):
        raise PatchError("Mach-O slice bounds are invalid")

    magic = bytes(data[base:base + 4])
    if magic == MH_MAGIC_64_LE:
        endian, is_64 = "<", True
    elif magic == MH_MAGIC_64_BE:
        endian, is_64 = ">", True
    elif magic == MH_MAGIC_32_LE:
        endian, is_64 = "<", False
    elif magic == MH_MAGIC_32_BE:
        endian, is_64 = ">", False
    else:
        raise PatchError(f"Unknown Mach-O magic at 0x{base:x}: {magic.hex()}")

    cputype = u32(data, base + 4, endian)
    return ThinMachO(base=base, size=size, endian=endian, is_64=is_64, cputype=cputype)


def enumerate_macho_slices(data: bytes | bytearray) -> list[ThinMachO]:
    if len(data) < 4:
        raise PatchError("Main executable is too small to be Mach-O")

    magic = bytes(data[:4])
    if magic in {MH_MAGIC_32_LE, MH_MAGIC_32_BE, MH_MAGIC_64_LE, MH_MAGIC_64_BE}:
        return [identify_thin(data, 0, len(data))]

    if magic == FAT_MAGIC_32_BE:
        endian, fat64 = ">", False
    elif magic == FAT_MAGIC_32_LE:
        endian, fat64 = "<", False
    elif magic == FAT_MAGIC_64_BE:
        endian, fat64 = ">", True
    elif magic == FAT_MAGIC_64_LE:
        endian, fat64 = "<", True
    else:
        raise PatchError(f"Unknown executable magic: {magic.hex()}")

    if len(data) < 8:
        raise PatchError("Truncated FAT header")

    nfat = u32(data, 4, endian)
    entry_size = 32 if fat64 else 20
    table_end = 8 + nfat * entry_size
    if nfat == 0 or nfat > 64 or table_end > len(data):
        raise PatchError(f"Invalid FAT architecture table (nfat={nfat})")

    slices: list[ThinMachO] = []
    for i in range(nfat):
        off = 8 + i * entry_size
        cputype = u32(data, off, endian)
        if fat64:
            arch_offset = u64(data, off + 8, endian)
            arch_size = u64(data, off + 16, endian)
        else:
            arch_offset = u32(data, off + 8, endian)
            arch_size = u32(data, off + 12, endian)

        if arch_offset + arch_size > len(data):
            raise PatchError(f"FAT slice {i} exceeds executable size")

        try:
            thin = identify_thin(data, arch_offset, arch_size)
        except PatchError:
            # Not every FAT slice necessarily needs to be a Mach-O we can patch.
            continue

        # The cputype in the FAT entry and thin header should agree. If they don't,
        # refuse rather than touching a suspicious/corrupt file.
        if thin.cputype != cputype:
            raise PatchError(
                f"FAT slice {i} CPU mismatch: table=0x{cputype:x}, header=0x{thin.cputype:x}"
            )
        slices.append(thin)

    if not slices:
        raise PatchError("No patchable Mach-O slices found")
    return slices


def build_load_dylib_command(dylib_install_name: str, endian: str) -> bytes:
    name = dylib_install_name.encode("utf-8") + b"\0"
    header_size = 24
    cmd_size = align_up(header_size + len(name), 8)
    padding = cmd_size - header_size - len(name)
    return struct.pack(
        f"{endian}IIIIII",
        LC_LOAD_DYLIB,
        cmd_size,
        header_size,
        0,          # timestamp
        0x00010000, # current_version 1.0.0
        0x00010000, # compatibility_version 1.0.0
    ) + name + (b"\0" * padding)


def iter_load_commands(data: bytes | bytearray, thin: ThinMachO):
    header_size = 32 if thin.is_64 else 28
    base = thin.base
    if thin.size < header_size:
        raise PatchError("Truncated Mach-O header")

    ncmds = u32(data, base + 16, thin.endian)
    sizeofcmds = u32(data, base + 20, thin.endian)
    commands_start = base + header_size
    commands_end = commands_start + sizeofcmds
    slice_end = base + thin.size

    if ncmds > 10000:
        raise PatchError(f"Unreasonable Mach-O ncmds={ncmds}")
    if commands_end > slice_end:
        raise PatchError("Mach-O load command region exceeds slice")

    pos = commands_start
    for index in range(ncmds):
        if pos + 8 > commands_end:
            raise PatchError(f"Load command {index} header exceeds sizeofcmds")
        cmd = u32(data, pos, thin.endian)
        cmdsize = u32(data, pos + 4, thin.endian)
        if cmdsize < 8 or pos + cmdsize > commands_end:
            raise PatchError(f"Invalid load command {index}: cmdsize={cmdsize}")
        yield index, pos, cmd, cmdsize
        pos += cmdsize

    if pos != commands_end:
        raise PatchError(
            f"Load commands do not exactly match sizeofcmds: parsed=0x{pos:x}, expected=0x{commands_end:x}"
        )


def dylib_already_loaded(data: bytes | bytearray, thin: ThinMachO, install_name: str) -> bool:
    for _, pos, cmd, cmdsize in iter_load_commands(data, thin):
        # LC_LOAD_WEAK_DYLIB etc. have LC_REQ_DYLD bit set. Mask it for comparison.
        base_cmd = cmd & 0x7FFFFFFF
        if base_cmd not in {LC_LOAD_DYLIB, 0x18, 0x1F, 0x23, 0x20}:
            continue
        if cmdsize < 24:
            continue
        name_off = u32(data, pos + 8, thin.endian)
        if name_off >= cmdsize:
            continue
        start = pos + name_off
        end_limit = pos + cmdsize
        end = data.find(b"\0", start, end_limit)
        if end == -1:
            end = end_limit
        existing = bytes(data[start:end]).decode("utf-8", "replace")
        if existing == install_name or existing.endswith("/" + PurePosixPath(install_name).name):
            return True
    return False


def earliest_file_data_offset(data: bytes | bytearray, thin: ThinMachO) -> int:
    """Return earliest known file-backed section offset within this thin slice.

    This is used to determine how much header padding exists after load commands.
    We prefer section offsets because __TEXT's segment fileoff is normally zero
    (it includes the Mach-O header itself).
    """
    candidates: list[int] = []

    for _, pos, cmd, cmdsize in iter_load_commands(data, thin):
        base_cmd = cmd & 0x7FFFFFFF
        if base_cmd == LC_SEGMENT_64 and thin.is_64:
            if cmdsize < 72:
                raise PatchError("Truncated LC_SEGMENT_64")
            fileoff = u64(data, pos + 40, thin.endian)
            filesize = u64(data, pos + 48, thin.endian)
            nsects = u32(data, pos + 64, thin.endian)
            expected = 72 + nsects * 80
            if expected > cmdsize:
                raise PatchError("LC_SEGMENT_64 sections exceed command size")
            if fileoff > 0 and filesize > 0:
                candidates.append(fileoff)
            sec = pos + 72
            for _ in range(nsects):
                offset = u32(data, sec + 48, thin.endian)
                size = u64(data, sec + 40, thin.endian)
                if offset > 0 and size > 0:
                    candidates.append(offset)
                sec += 80

        elif base_cmd == LC_SEGMENT and not thin.is_64:
            if cmdsize < 56:
                raise PatchError("Truncated LC_SEGMENT")
            fileoff = u32(data, pos + 32, thin.endian)
            filesize = u32(data, pos + 36, thin.endian)
            nsects = u32(data, pos + 48, thin.endian)
            expected = 56 + nsects * 68
            if expected > cmdsize:
                raise PatchError("LC_SEGMENT sections exceed command size")
            if fileoff > 0 and filesize > 0:
                candidates.append(fileoff)
            sec = pos + 56
            for _ in range(nsects):
                offset = u32(data, sec + 40, thin.endian)
                size = u32(data, sec + 36, thin.endian)
                if offset > 0 and size > 0:
                    candidates.append(offset)
                sec += 68

    header_size = 32 if thin.is_64 else 28
    sizeofcmds = u32(data, thin.base + 20, thin.endian)
    lc_end_rel = header_size + sizeofcmds

    valid = [x for x in candidates if lc_end_rel <= x < thin.size]
    if not valid:
        # Conservative fallback: never guess an offset. Without a known section
        # boundary we cannot prove that overwriting bytes is safe.
        raise PatchError("Could not determine safe end of Mach-O header padding")
    return min(valid)


def patch_thin_slice(data: bytearray, thin: ThinMachO, install_name: str) -> bool:
    if dylib_already_loaded(data, thin, install_name):
        print(f"[=] Slice @0x{thin.base:x}: dylib already loaded")
        return False

    # We only need arm64 for the target app/dylib. Refusing other architectures
    # avoids creating a FAT binary whose non-arm64 slice references an arm64-only dylib.
    if thin.cputype != CPU_TYPE_ARM64:
        print(f"[-] Slice @0x{thin.base:x}: CPU 0x{thin.cputype:x}, skipped")
        return False

    header_size = 32 if thin.is_64 else 28
    ncmds = u32(data, thin.base + 16, thin.endian)
    sizeofcmds = u32(data, thin.base + 20, thin.endian)
    lc_end_rel = header_size + sizeofcmds
    first_data_rel = earliest_file_data_offset(data, thin)

    command = build_load_dylib_command(install_name, thin.endian)
    available = first_data_rel - lc_end_rel
    if available < len(command):
        raise PatchError(
            "Not enough Mach-O header padding for LC_LOAD_DYLIB: "
            f"need {len(command)} bytes, have {available} bytes. "
            "Refusing to shift binary contents because that would invalidate file offsets."
        )

    write_start = thin.base + lc_end_rel
    write_end = write_start + len(command)
    padding_region = bytes(data[write_start:thin.base + first_data_rel])

    # Normal Mach-O header padding is zero-filled. Refuse if the exact bytes we
    # need are not zero, since those bytes may contain meaningful data.
    if any(data[write_start:write_end]):
        preview = bytes(data[write_start:min(write_end, write_start + 16)]).hex()
        raise PatchError(
            f"Mach-O header padding is not zero-filled at 0x{write_start:x} (starts {preview})."
        )

    data[write_start:write_end] = command
    struct.pack_into(f"{thin.endian}I", data, thin.base + 16, ncmds + 1)
    struct.pack_into(f"{thin.endian}I", data, thin.base + 20, sizeofcmds + len(command))

    print(
        f"[+] Slice @0x{thin.base:x}: LC_LOAD_DYLIB added "
        f"({len(command)} bytes, {available - len(command)} bytes padding remain)"
    )
    return True


def patch_macho(executable: bytes, install_name: str) -> bytes:
    data = bytearray(executable)
    slices = enumerate_macho_slices(data)
    patched = 0
    arm64_seen = 0

    for thin in slices:
        if thin.cputype == CPU_TYPE_ARM64:
            arm64_seen += 1
        if patch_thin_slice(data, thin, install_name):
            patched += 1

    if arm64_seen == 0:
        raise PatchError("No ARM64 Mach-O slice found in main executable")

    # patched==0 is fine if it was already injected. Verify below either way.
    for thin in enumerate_macho_slices(data):
        if thin.cputype == CPU_TYPE_ARM64 and not dylib_already_loaded(data, thin, install_name):
            raise PatchError("Post-patch verification failed: ARM64 slice does not load dylib")

    print(f"[*] Mach-O verification OK ({arm64_seen} ARM64 slice(s), {patched} newly patched)")
    return bytes(data)


def find_main_app(zf: zipfile.ZipFile) -> tuple[str, zipfile.ZipInfo]:
    candidates: list[tuple[str, zipfile.ZipInfo]] = []
    for info in zf.infolist():
        p = PurePosixPath(info.filename)
        # Exact shape: Payload/Foo.app/Info.plist
        if len(p.parts) == 3 and p.parts[0] == "Payload" and p.parts[1].endswith(".app") and p.name == "Info.plist":
            candidates.append((str(PurePosixPath(*p.parts[:2])) + "/", info))

    if len(candidates) != 1:
        raise PatchError(f"Expected exactly one main app in Payload/, found {len(candidates)}")
    return candidates[0]


def clone_info(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    new = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    new.compress_type = info.compress_type
    new.comment = info.comment
    new.extra = info.extra
    new.internal_attr = info.internal_attr
    new.external_attr = info.external_attr
    new.create_system = info.create_system
    new.create_version = info.create_version
    new.extract_version = info.extract_version
    new.flag_bits = info.flag_bits
    new.volume = info.volume
    return new


def force_unix_mode(info: zipfile.ZipInfo, mode: int, is_dir: bool = False) -> None:
    info.create_system = 3  # Unix
    type_bits = stat.S_IFDIR if is_dir else stat.S_IFREG
    info.external_attr = (type_bits | mode) << 16
    if is_dir:
        info.external_attr |= 0x10  # DOS directory flag


def dump_plist_preserving_format(original: bytes, obj: dict) -> bytes:
    fmt = plistlib.FMT_BINARY if original.startswith(b"bplist00") else plistlib.FMT_XML
    out = io.BytesIO()
    plistlib.dump(obj, out, fmt=fmt, sort_keys=False)
    return out.getvalue()



def replace_bundle_id_in_object(obj, old_bundle_id: str, new_bundle_id: str):
    """Recursively replace a bundle-id prefix inside plist string values.

    This intentionally touches plist strings only. It does NOT modify the
    embedded provisioning profile or arbitrary binary data.
    """
    changed = 0

    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            new_value, count = replace_bundle_id_in_object(value, old_bundle_id, new_bundle_id)
            out[key] = new_value
            changed += count
        return out, changed

    if isinstance(obj, list):
        out = []
        for value in obj:
            new_value, count = replace_bundle_id_in_object(value, old_bundle_id, new_bundle_id)
            out.append(new_value)
            changed += count
        return out, changed

    if isinstance(obj, tuple):
        out = []
        for value in obj:
            new_value, count = replace_bundle_id_in_object(value, old_bundle_id, new_bundle_id)
            out.append(new_value)
            changed += count
        return tuple(out), changed

    if isinstance(obj, str) and old_bundle_id and old_bundle_id in obj:
        return obj.replace(old_bundle_id, new_bundle_id), obj.count(old_bundle_id)

    return obj, 0


def patch_plist_bytes(original: bytes, old_bundle_id: str, new_bundle_id: str) -> tuple[bytes, int]:
    """Patch occurrences of the old bundle ID in a plist, preserving plist format."""
    try:
        obj = plistlib.loads(original)
    except plistlib.InvalidFileException:
        return original, 0

    patched, changed = replace_bundle_id_in_object(obj, old_bundle_id, new_bundle_id)
    if not changed:
        return original, 0

    fmt = plistlib.FMT_BINARY if original.startswith(b"bplist00") else plistlib.FMT_XML
    out = io.BytesIO()
    plistlib.dump(patched, out, fmt=fmt, sort_keys=False)
    return out.getvalue(), changed


def patch_exact_dict_key(obj, key: str, new_value: str):
    """Recursively replace the value of an exact dictionary key.

    Useful for binary/XML plist-backed .strings/.stringsdict/custom string tables.
    Only the value for the exact requested key is changed.
    """
    changed = 0
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k == key and isinstance(v, str):
                out[k] = new_value
                changed += 1
            else:
                nv, c = patch_exact_dict_key(v, key, new_value)
                out[k] = nv
                changed += c
        return out, changed
    if isinstance(obj, list):
        out = []
        for v in obj:
            nv, c = patch_exact_dict_key(v, key, new_value)
            out.append(nv)
            changed += c
        return out, changed
    if isinstance(obj, tuple):
        out = []
        for v in obj:
            nv, c = patch_exact_dict_key(v, key, new_value)
            out.append(nv)
            changed += c
        return tuple(out), changed
    return obj, 0


def patch_plist_exact_key(data: bytes, key: str, new_value: str) -> tuple[bytes, int]:
    """Patch an exact localization key in an XML/binary plist-like resource."""
    try:
        obj = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError):
        return data, 0
    patched, changed = patch_exact_dict_key(obj, key, new_value)
    if not changed:
        return data, 0
    fmt = plistlib.FMT_BINARY if data.startswith(b"bplist00") else plistlib.FMT_XML
    out = io.BytesIO()
    plistlib.dump(patched, out, fmt=fmt, sort_keys=False)
    return out.getvalue(), changed


def decode_strings_file(data: bytes) -> tuple[str, str, bytes]:
    """Return (text, codec, bom) for common .strings encodings."""
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le"), "utf-16-le", b"\xff\xfe"
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be"), "utf-16-be", b"\xfe\xff"
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8"), "utf-8", b"\xef\xbb\xbf"

    # Most modern .strings files are UTF-8. Some older bundles contain UTF-16
    # without a BOM; use the NUL pattern as a conservative hint.
    try:
        return data.decode("utf-8"), "utf-8", b""
    except UnicodeDecodeError:
        pass

    if len(data) >= 4:
        even_nuls = data[0::2].count(0)
        odd_nuls = data[1::2].count(0)
        if odd_nuls > even_nuls * 2:
            try:
                return data.decode("utf-16-le"), "utf-16-le", b""
            except UnicodeDecodeError:
                pass
        if even_nuls > odd_nuls * 2:
            try:
                return data.decode("utf-16-be"), "utf-16-be", b""
            except UnicodeDecodeError:
                pass

    raise PatchError("Unsupported .strings text encoding")


def encode_strings_file(text: str, codec: str, bom: bytes) -> bytes:
    return bom + text.encode(codec)


def escape_strings_value(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def patch_strings_key(data: bytes, key: str, new_value: str) -> tuple[bytes, int]:
    """Change only the value belonging to one exact key in an iOS string table.

    Handles binary/XML plist dictionaries plus common text syntaxes:
      "key" = "value";        (.strings)
      "key": "value"          (JSON-like tables)
      key = "value"            (custom text tables)
    """
    # Binary plist-backed .strings files are common enough to support directly.
    if data.startswith(b"bplist00"):
        return patch_plist_exact_key(data, key, new_value)

    try:
        text, codec, bom = decode_strings_file(data)
    except PatchError:
        return data, 0

    escaped_key = re.escape(key)
    replacement_value = '"' + escape_strings_value(new_value) + '"'
    quoted_string = r'"(?:\\.|[^"\\])*"'

    patterns = [
        # Apple .strings format, exact key, only replace RHS string.
        re.compile(rf'(?m)(^[ \t]*"{escaped_key}"[ \t]*=[ \t]*)({quoted_string})([ \t]*;)'),
        # JSON/custom dictionary text.
        re.compile(rf'(?m)([ \t]*"{escaped_key}"[ \t]*:[ \t]*)({quoted_string})'),
        # Unquoted custom assignment table.
        re.compile(rf'(?m)(^[ \t]*{escaped_key}[ \t]*=[ \t]*)({quoted_string})([ \t]*;?)'),
    ]

    total = 0
    patched = text
    for i, pattern in enumerate(patterns):
        if i == 1:
            patched, count = pattern.subn(lambda m: m.group(1) + replacement_value, patched)
        else:
            patched, count = pattern.subn(lambda m: m.group(1) + replacement_value + m.group(3), patched)
        total += count

    if total == 0:
        return data, 0
    return encode_strings_file(patched, codec, bom), total



def _patch_raw_strings_assignment_for_encoding(
    data: bytes,
    key: str,
    new_value: str,
    encoding: str,
) -> tuple[bytes, int]:
    """Byte-level fallback for unusual .strings files.

    Some games ship files named Localizable.strings that contain valid-looking
    Apple assignments but also contain bytes that prevent decoding the *whole*
    file as UTF-8/UTF-16.  In that case, only inspect the bytes around the exact
    key and replace the RHS of that one assignment.

    Supported forms (with arbitrary spaces/tabs/comments between key and '='):
        "key" = "value";
        key = "value";

    The file may grow/shrink because it is a standalone resource in the ZIP,
    not a Mach-O binary. No executable offsets are involved here.
    """
    if encoding == "utf-8":
        unit = 1
    elif encoding in {"utf-16-le", "utf-16-be"}:
        unit = 2
    else:
        return data, 0

    key_b = key.encode(encoding)
    eq_b = "=".encode(encoding)
    quote_b = '"'.encode(encoding)
    slash_b = "/".encode(encoding)
    star_b = "*".encode(encoding)
    newline_b = "\n".encode(encoding)
    cr_b = "\r".encode(encoding)
    semicolon_b = ";".encode(encoding)
    backslash_b = "\\".encode(encoding)
    new_b = escape_strings_value(new_value).encode(encoding)

    # Whitespace sequences encoded as one code unit each.
    whitespace = {
        " ".encode(encoding),
        "\t".encode(encoding),
        "\r".encode(encoding),
        "\n".encode(encoding),
    }

    def token_at(buf: bytes, pos: int, token: bytes) -> bool:
        return buf[pos:pos + len(token)] == token

    def skip_ws_and_comments(buf: bytes, pos: int, hard_end: int) -> int:
        # Apple .strings can contain /* ... */ comments. Accept them between the
        # key and '=' while keeping the search local to this assignment.
        while pos < hard_end:
            one = bytes(buf[pos:pos + unit])
            if one in whitespace:
                pos += unit
                continue
            if token_at(buf, pos, slash_b) and token_at(buf, pos + unit, star_b):
                close = ("*/").encode(encoding)
                end_comment = buf.find(close, pos + 2 * unit, hard_end)
                if end_comment == -1:
                    return pos
                pos = end_comment + len(close)
                continue
            break
        return pos

    out = bytearray(data)
    count = 0
    search_from = 0

    while True:
        idx = bytes(out).find(key_b, search_from)
        if idx == -1:
            break

        # UTF-16 code units must stay 2-byte aligned. Without this guard, an
        # LE string can look like the same BE ASCII key shifted by one byte.
        if unit == 2 and (idx % 2):
            search_from = idx + 1
            continue

        # Avoid matching the key as a substring of a longer identifier. In a
        # quoted key, the surrounding quote satisfies this naturally.
        before = idx - unit
        after = idx + len(key_b)
        if before >= 0:
            prev = bytes(out[before:idx])
            # If previous code unit is an ASCII-ish identifier character, skip.
            try:
                prev_ch = prev.decode(encoding)
            except Exception:
                prev_ch = ""
            if prev_ch and (prev_ch.isalnum() or prev_ch in "_/-") and prev != quote_b:
                search_from = idx + len(key_b)
                continue

        # Key may be quoted. If so, consume the closing quote after the key.
        pos = after
        if token_at(out, pos, quote_b):
            pos += len(quote_b)

        # Do not roam through the whole file looking for some later '='. 4 KiB
        # is intentionally generous for whitespace/comments but still local.
        hard_end = min(len(out), idx + 4096 * unit)
        pos = skip_ws_and_comments(out, pos, hard_end)
        if not token_at(out, pos, eq_b):
            search_from = idx + len(key_b)
            continue
        pos += len(eq_b)
        pos = skip_ws_and_comments(out, pos, hard_end)

        # Standard .strings RHS is quoted. Parse escapes so an escaped quote does
        # not terminate the value early.
        if token_at(out, pos, quote_b):
            value_start = pos + len(quote_b)
            cur = value_start
            escaped = False
            value_end = None
            while cur + unit <= len(out) and cur < hard_end:
                tok = bytes(out[cur:cur + unit])
                if escaped:
                    escaped = False
                    cur += unit
                    continue
                if tok == backslash_b:
                    escaped = True
                    cur += unit
                    continue
                if tok == quote_b:
                    value_end = cur
                    break
                cur += unit
            if value_end is None:
                search_from = idx + len(key_b)
                continue

            out[value_start:value_end] = new_b
            count += 1
            search_from = value_start + len(new_b) + len(quote_b)
            continue

        # Rare custom variant: unquoted RHS. Replace up to ';' or line ending,
        # preserving trailing whitespace and the terminator.
        value_start = pos
        candidates = []
        for term in (semicolon_b, newline_b, cr_b):
            x = bytes(out).find(term, value_start, hard_end)
            if x != -1:
                candidates.append(x)
        if not candidates:
            search_from = idx + len(key_b)
            continue
        value_end = min(candidates)
        # Trim encoded spaces/tabs before the terminator.
        while value_end - unit >= value_start and bytes(out[value_end-unit:value_end]) in {
            " ".encode(encoding), "\t".encode(encoding)
        }:
            value_end -= unit
        out[value_start:value_end] = new_b
        count += 1
        search_from = value_start + len(new_b)

    return bytes(out), count


def patch_strings_key_raw(data: bytes, key: str, new_value: str) -> tuple[bytes, int]:
    """Fallback patcher that does not require decoding the whole .strings file."""
    # Prefer the encoding in which the exact key is actually present. Trying all
    # three is safe because each pass requires a complete key -> '=' assignment.
    patched = data
    total = 0
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        if key.encode(encoding) not in patched:
            continue
        patched, count = _patch_raw_strings_assignment_for_encoding(
            patched, key, new_value, encoding
        )
        total += count
    return patched, total


def resource_contains_text(data: bytes, text: str) -> bool:
    """Detect text in UTF-8/ASCII or UTF-16 without assuming a file extension."""
    return (
        text.encode("utf-8") in data
        or text.encode("utf-16-le") in data
        or text.encode("utf-16-be") in data
    )


def resource_contains_key(data: bytes, key: str) -> bool:
    return resource_contains_text(data, key)


def patch_localization_resource(data: bytes, key: str, new_value: str) -> tuple[bytes, int]:
    """Patch one exact localization key using progressively more tolerant parsers."""
    # First try plist dictionaries (.plist/.stringsdict/binary .strings/custom plist tables).
    patched, count = patch_plist_exact_key(data, key, new_value)
    if count:
        return patched, count

    # Then normal textual string-table syntaxes.
    patched, count = patch_strings_key(data, key, new_value)
    if count:
        return patched, count

    # Last resort for Localizable.strings that contain extra/non-text bytes:
    # parse only the exact key -> '=' -> RHS bytes.
    return patch_strings_key_raw(data, key, new_value)

def patch_infoplist_strings(data: bytes, app_name: str) -> tuple[bytes, int]:
    """Keep localized app names from overriding the new display name."""
    total = 0
    for key in ("CFBundleDisplayName", "CFBundleName"):
        data, count = patch_strings_key(data, key, app_name)
        total += count
    return data, total


def validate_output(
    output_ipa: str,
    app_prefix: str,
    binary_entry: str,
    plist_entry: str,
    dylib_entry: str,
    install_name: str,
    app_name: str,
    bundle_id: str,
    expected_dylib_bytes: bytes,
) -> None:
    with zipfile.ZipFile(output_ipa, "r") as zf:
        bad = zf.testzip()
        if bad:
            raise PatchError(f"ZIP CRC validation failed for {bad}")

        names = set(zf.namelist())
        for required in (binary_entry, plist_entry, dylib_entry):
            if required not in names:
                raise PatchError(f"Output IPA missing {required}")

        plist = plistlib.loads(zf.read(plist_entry))
        if plist.get("CFBundleIdentifier") != bundle_id:
            raise PatchError("Output bundle identifier verification failed")
        if plist.get("CFBundleDisplayName") != app_name:
            raise PatchError("Output display name verification failed")

        executable = zf.read(binary_entry)
        for thin in enumerate_macho_slices(executable):
            if thin.cputype == CPU_TYPE_ARM64 and not dylib_already_loaded(executable, thin, install_name):
                raise PatchError("Output executable no longer contains LC_LOAD_DYLIB")

        # Make sure an older copy in the IPA was really overwritten by the
        # exact dylib supplied next to this script.
        if zf.read(dylib_entry) != expected_dylib_bytes:
            raise PatchError("Injected dylib verification failed: output contains different bytes")

        binary_info = zf.getinfo(binary_entry)
        dylib_info = zf.getinfo(dylib_entry)
        binary_mode = (binary_info.external_attr >> 16) & 0o777
        dylib_mode = (dylib_info.external_attr >> 16) & 0o777
        if not (binary_mode & 0o111):
            raise PatchError(f"Main executable is not executable in ZIP metadata (mode {binary_mode:o})")
        if not (dylib_mode & 0o111):
            raise PatchError(f"Injected dylib is not executable in ZIP metadata (mode {dylib_mode:o})")

    print("[✓] Final IPA validation passed")


def patch_ipa(
    input_ipa: str,
    output_ipa: str,
    dylib_path: str,
    app_name: str,
    bundle_id: str,
    old_bundle_id: str,
) -> None:
    if not os.path.isfile(input_ipa):
        raise PatchError(f"Input IPA not found: {input_ipa}")
    if not zipfile.is_zipfile(input_ipa):
        raise PatchError(f"Input is not a valid ZIP/IPA: {input_ipa}")
    if not os.path.isfile(dylib_path):
        raise PatchError(f"Dylib not found: {dylib_path}")

    with open(dylib_path, "rb") as f:
        dylib_bytes = f.read()
    if len(dylib_bytes) < 4 or dylib_bytes[:4] not in {
        MH_MAGIC_32_LE, MH_MAGIC_32_BE, MH_MAGIC_64_LE, MH_MAGIC_64_BE,
        FAT_MAGIC_32_BE, FAT_MAGIC_32_LE, FAT_MAGIC_64_BE, FAT_MAGIC_64_LE,
    }:
        raise PatchError("Injected dylib does not look like a Mach-O file")

    if os.path.abspath(input_ipa) == os.path.abspath(output_ipa):
        raise PatchError("Input and output IPA paths must be different")

    print(f"[*] Reading {input_ipa}")
    with zipfile.ZipFile(input_ipa, "r") as zin:
        app_prefix, plist_info = find_main_app(zin)
        plist_entry = plist_info.filename
        original_plist_bytes = zin.read(plist_entry)
        plist = plistlib.loads(original_plist_bytes)
        if not isinstance(plist, dict):
            raise PatchError("Main Info.plist is not a dictionary")

        executable_name = plist.get("CFBundleExecutable")
        if not executable_name or not isinstance(executable_name, str):
            raise PatchError("CFBundleExecutable missing from main Info.plist")
        binary_entry = app_prefix + executable_name
        if binary_entry not in set(zin.namelist()):
            raise PatchError(f"Main executable not found in IPA: {binary_entry}")

        dylib_name = os.path.basename(dylib_path)
        dylib_entry = app_prefix + "Frameworks/" + dylib_name
        frameworks_dir_entry = app_prefix + "Frameworks/"
        install_name = f"@executable_path/Frameworks/{dylib_name}"

        print(f"[*] App: {app_prefix.rstrip('/')}")
        print(f"[*] Executable: {binary_entry}")
        print(f"[*] Dylib install name: {install_name}")

        patched_executable = patch_macho(zin.read(binary_entry), install_name)

        # Auto-detect the actual source bundle ID. This fixes cases where the IPA
        # is not using DEFAULT_OLD_BUNDLE_ID at all.
        detected_bundle_id = plist.get("CFBundleIdentifier")
        old_bundle_ids = []
        for candidate in (detected_bundle_id, old_bundle_id):
            if isinstance(candidate, str) and candidate and candidate != bundle_id and candidate not in old_bundle_ids:
                old_bundle_ids.append(candidate)
        print(f"[*] Source bundle ID: {detected_bundle_id or '<missing>'}")
        print(f"[*] New bundle ID:    {bundle_id}")

        main_plist_replacements = 0
        for old_id in old_bundle_ids:
            plist, count = replace_bundle_id_in_object(plist, old_id, bundle_id)
            main_plist_replacements += count
        plist["CFBundleDisplayName"] = app_name
        plist["CFBundleName"] = app_name
        plist["CFBundleIdentifier"] = bundle_id
        patched_plist = dump_plist_preserving_format(original_plist_bytes, plist)

        # Pre-patch other textual resources directly from the ZIP.
        replacements: dict[str, bytes] = {
            binary_entry: patched_executable,
            plist_entry: patched_plist,
        }
        bundle_replacement_count = main_plist_replacements
        localization_replacement_count = 0
        infoplist_name_replacement_count = 0

        localization_candidate_hits: list[str] = []
        localization_unpatched_hits: list[str] = []
        old_value_only_hits: list[str] = []
        string_table_files_scanned = 0

        for info in zin.infolist():
            name = info.filename
            if not name.startswith(app_prefix) or name in replacements or name.endswith("/"):
                continue

            base_name = PurePosixPath(name).name
            suffix = PurePosixPath(name).suffix.lower()
            original = None

            # Replace every detected old bundle-id prefix inside plist string values
            # (main app, extensions, URL identifiers, shared identifiers, etc.).
            if suffix == ".plist":
                original = zin.read(name)
                patched = original
                total_count = 0
                for old_id in old_bundle_ids:
                    patched, count = patch_plist_bytes(patched, old_id, bundle_id)
                    total_count += count
                if total_count:
                    replacements[name] = patched
                    bundle_replacement_count += total_count
                    original = patched

            # Localized app name can override Info.plist on the device.
            if base_name == "InfoPlist.strings":
                if original is None:
                    original = zin.read(name)
                patched, count = patch_infoplist_strings(original, app_name)
                if count:
                    replacements[name] = patched
                    infoplist_name_replacement_count += count
                    original = patched

            # IMPORTANT: iOS does NOT require localization tables to be named
            # Localizable.strings. Search every .strings/.stringsdict/.plist first.
            likely_localization = suffix in {".strings", ".stringsdict", ".plist"}
            if likely_localization:
                string_table_files_scanned += 1
                if original is None:
                    original = zin.read(name)
                has_key = resource_contains_key(original, LOCALIZABLE_KEY)
                if has_key:
                    localization_candidate_hits.append(name)
                    patched, count = patch_localization_resource(
                        original, LOCALIZABLE_KEY, LOCALIZABLE_VALUE
                    )
                    if count:
                        replacements[name] = patched
                        localization_replacement_count += count
                        original = patched
                    else:
                        localization_unpatched_hits.append(name)
                elif resource_contains_text(original, LOCALIZABLE_OLD_VALUE):
                    old_value_only_hits.append(name)

            # Diagnostic fallback: some games store their string table in a custom
            # .txt/.json/.bytes/.dat/etc. resource. Search the raw bytes for the key.
            # If it is textual, patch safely; if it is an unknown binary blob, report
            # the exact path instead of corrupting it by changing its length blindly.
            elif info.file_size <= 64 * 1024 * 1024:
                original = zin.read(name)
                if resource_contains_key(original, LOCALIZABLE_KEY):
                    localization_candidate_hits.append(name)
                    patched, count = patch_localization_resource(
                        original, LOCALIZABLE_KEY, LOCALIZABLE_VALUE
                    )
                    if count:
                        replacements[name] = patched
                        localization_replacement_count += count
                    else:
                        localization_unpatched_hits.append(name)
                elif resource_contains_text(original, LOCALIZABLE_OLD_VALUE):
                    old_value_only_hits.append(name)

        print(f"[*] iOS .strings/.stringsdict/.plist resources scanned: {string_table_files_scanned}")
        print(f"[+] Bundle-ID replacements in plists: {bundle_replacement_count}")
        print(
            f"[+] Localization key '{LOCALIZABLE_KEY}' changed to "
            f"'{LOCALIZABLE_VALUE}' in {localization_replacement_count} occurrence(s)"
        )
        if localization_candidate_hits:
            print("[*] Files containing the localization key:")
            for candidate in localization_candidate_hits:
                status = "PATCHED" if candidate in replacements and candidate not in localization_unpatched_hits else "FOUND"
                print(f"    [{status}] {candidate}")
        if infoplist_name_replacement_count:
            print(
                f"[+] Localized app-name entries changed: "
                f"{infoplist_name_replacement_count}"
            )

        if localization_replacement_count == 0 and old_value_only_hits:
            print(f"[*] '{LOCALIZABLE_OLD_VALUE}' was found without the exact key in:")
            for candidate in old_value_only_hits[:30]:
                print(f"    [VALUE FOUND] {candidate}")
            if len(old_value_only_hits) > 30:
                print(f"    ... and {len(old_value_only_hits) - 30} more")

        if localization_unpatched_hits:
            raise PatchError(
                "Localization key was found but could not be patched in: "
                + ", ".join(localization_unpatched_hits)
            )
        if localization_replacement_count == 0:
            print(
                f"[!] Warning: localization key '{LOCALIZABLE_KEY}' was not found "
                "anywhere in the app resources scanned by the patcher."
            )

        # Build output by copying original ZIP entries verbatim (metadata + bytes),
        # replacing only the files we intentionally change. This is Windows-safe
        # and preserves symlinks/permissions much better than extractall/os.walk.
        tmp_output = output_ipa + ".tmp"
        if os.path.exists(tmp_output):
            os.remove(tmp_output)
        if os.path.exists(output_ipa):
            os.remove(output_ipa)

        existing_names = set(zin.namelist())
        if dylib_entry in existing_names:
            print(f"[+] Existing {dylib_name} found in IPA -> replacing it with the new file")
        else:
            print(f"[+] No existing {dylib_name} found -> adding it")

        with zipfile.ZipFile(tmp_output, "w", allowZip64=True) as zout:
            for info in zin.infolist():
                if info.filename == binary_entry:
                    out_info = clone_info(info)
                    force_unix_mode(out_info, 0o755)
                    zout.writestr(out_info, replacements[binary_entry], compress_type=info.compress_type)
                elif info.filename in replacements:
                    out_info = clone_info(info)
                    # Modified plists/.strings are ordinary data files.
                    force_unix_mode(out_info, 0o644)
                    zout.writestr(out_info, replacements[info.filename], compress_type=info.compress_type)
                elif info.filename == dylib_entry:
                    # Replace an old injected copy if present.
                    out_info = clone_info(info)
                    force_unix_mode(out_info, 0o755)
                    zout.writestr(out_info, dylib_bytes, compress_type=zipfile.ZIP_DEFLATED)
                else:
                    out_info = clone_info(info)
                    zout.writestr(out_info, zin.read(info.filename), compress_type=info.compress_type)

            if frameworks_dir_entry not in existing_names:
                dir_info = zipfile.ZipInfo(frameworks_dir_entry)
                force_unix_mode(dir_info, 0o755, is_dir=True)
                zout.writestr(dir_info, b"")

            if dylib_entry not in existing_names:
                dylib_info = zipfile.ZipInfo(dylib_entry)
                force_unix_mode(dylib_info, 0o755)
                zout.writestr(dylib_info, dylib_bytes, compress_type=zipfile.ZIP_DEFLATED)

    os.replace(tmp_output, output_ipa)
    print(f"[+] Wrote {output_ipa}")

    validate_output(
        output_ipa=output_ipa,
        app_prefix=app_prefix,
        binary_entry=binary_entry,
        plist_entry=plist_entry,
        dylib_entry=dylib_entry,
        install_name=install_name,
        app_name=app_name,
        bundle_id=bundle_id,
        expected_dylib_bytes=dylib_bytes,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inject a dylib into an IPA safely")
    parser.add_argument("--input", default=os.environ.get("INPUT_IPA", DEFAULT_INPUT_IPA))
    parser.add_argument("--output", default=os.environ.get("OUTPUT_IPA", DEFAULT_OUTPUT_IPA))
    parser.add_argument("--dylib", default=os.environ.get("DYLIB", DEFAULT_DYLIB))
    parser.add_argument("--name", default=os.environ.get("APP_NAME", DEFAULT_APP_NAME))
    parser.add_argument("--bundle-id", default=os.environ.get("BUNDLE_ID", DEFAULT_BUNDLE_ID))
    parser.add_argument(
        "--old-bundle-id",
        default=os.environ.get("OLD_BUNDLE_ID", DEFAULT_OLD_BUNDLE_ID),
        help="Optional extra old bundle-ID prefix; source IPA ID is auto-detected too",
    )
    return parser.parse_args()


def main() -> int:
    print(f"=== {PATCHER_VERSION} ===")
    print("[*] This build patches unusual .strings at byte level when normal decoding fails")
    args = parse_args()
    try:
        patch_ipa(args.input, args.output, args.dylib, args.name, args.bundle_id, args.old_bundle_id)
    except (PatchError, zipfile.BadZipFile, plistlib.InvalidFileException, OSError, struct.error) as exc:
        print(f"\n[!] PATCH FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"\n[✓] {args.output} is ready for signing/installing with KSign")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
