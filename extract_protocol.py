#!/usr/bin/env python3
"""Extract RadiaCode Android-app protocol messages from debug log files.

The Android app writes debug logs containing every USB/BLE protocol message as
hexdump lines. This tool parses those lines, reconstructs each request and its
full response, captures the app's own human-readable interpretation, and then
re-decodes each message with the `radiacode` library decoders so the output can
be compared against what the app reported.

Output: one JSON file per input log (written next to the source file, e.g.
`radiacode_logs_1.json`), plus a console summary of how many messages of each
command were found and how many could be re-decoded.

Log display conventions handled here
-------------------------------------
The app prints the protocol header in *display* order: `seq 00 cmd_be`
(e.g. `8A 00 08 25`), not the wire order `cmd_le 00 seq`. The 4-byte length
prefix and the 4-byte header are each printed as 8 hex digits with no inner
spaces; request args and payload bytes are printed one byte per token. The
`Got N bytes:` lines are the raw received bytes in wire order (length prefix
included). See `PROTOCOL.md` for the full wire description.

Device-initiated pushes and screen mirroring (not decoded)
-----------------------------------------------------------
Some log variants (e.g. the RC-103G capture) include a screen-mirror session.
While mirrored, the device pushes raw `Got N bytes:` lines with *no* REQ/RESP
markers; the parser therefore does not build messages for them and simply stops
appending them to the previous request's response once that response is fully
captured (see `_response_complete`).

The mirroring uses two undocumented commands that are intentionally left
undecoded here (emulating keypresses or parsing the framebuffer is unnecessary
when the same state is reachable via VSFR reads/writes):

- `VIRT_KB_CMD` (0x0A02): request is a single u32 key/button code; response is
  a retcode u32. Issued by the app to send input to the device's mirror UI.
- Screen push (0x0A06): device-initiated framebuffer notifications. A short
  info message carries `retcode(u32) + width(u32) + height(u32)` (e.g.
  128 x 48 for the RC-103G display); subsequent larger messages carry
  `retcode(u32) + framebuffer bytes` in 20-byte chunks.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import struct
import sys
import types
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the radiacode decoder modules without requiring the whole package
# (which pulls in `bleak` / `pyusb`). We synthesize a minimal `radiacode`
# package in sys.modules so `from radiacode.bytes_buffer import ...` works.
# The source tree location is given on the command line (`--source`) and is
# resolved lazily so it can be changed at runtime.
# ---------------------------------------------------------------------------


def _import_decoders(src: Path):
    global BytesBuffer, rtypes
    global decode_VS_DATA_BUF, decode_RC_RD_FLASH_AREA, decode_RC_VS_SPECTRUM
    global decode_RC_VS_SPEC_RESET, decode_RC_VS_SPEC_DIFF, decode_SET_EXCHANGE
    global _VS_NAMES, _VSFR_NAMES, _VS_DECODERS
    pkg_dir = src / 'radiacode'
    if not (pkg_dir / 'bytes_buffer.py').exists():
        raise RuntimeError(f'radiacode source tree not found under {src}')
    import types as _stdlib_types
    if 'radiacode' not in sys.modules or not getattr(
        sys.modules['radiacode'], '__path__', None
    ):
        pkg = _stdlib_types.ModuleType('radiacode')
        pkg.__path__ = [str(pkg_dir)]
        sys.modules['radiacode'] = pkg
    from radiacode import bytes_buffer, types
    from radiacode.decoders import databuf, exchange, flash, spectrum
    BytesBuffer = bytes_buffer.BytesBuffer
    rtypes = types
    decode_VS_DATA_BUF = databuf.decode_VS_DATA_BUF
    decode_RC_RD_FLASH_AREA = flash.decode_RC_RD_FLASH_AREA
    decode_RC_VS_SPECTRUM = spectrum.decode_RC_VS_SPECTRUM
    decode_RC_VS_SPEC_RESET = spectrum.decode_RC_VS_SPEC_RESET
    decode_RC_VS_SPEC_DIFF = spectrum.decode_RC_VS_SPEC_DIFF
    decode_SET_EXCHANGE = exchange.decode_SET_EXCHANGE
    _VS_NAMES = {int(v): k for k, v in rtypes.VS.__members__.items()}
    _VSFR_NAMES = {int(v): k for k, v in rtypes.VSFR.__members__.items()}
    _build_vs_decoders()

# ---------------------------------------------------------------------------
# Line parsers
# ---------------------------------------------------------------------------
_REQ_RE = re.compile(r'\[([0-9A-F]+)\.([A-Z0-9_]+):\s*(\d+)\]\s*')
_GOT_RE = re.compile(r'Got\s+(\d+)\s+bytes:\s*')
_RESP_RE = re.compile(r'<([0-9A-F]+)\.([A-Z0-9_]+):\s*(\d+),\s*([0-9]+)/([0-9]+)\s*ms>\s*')


def _bytes(tokens: list[str]) -> bytes:
    return bytes(int(t, 16) for t in tokens)


# A per-byte hex dump: 2 hex digits + a space per token. The trailing token may
# omit its space, but only if it is NOT glued to more hex / a timestamp
# fragment (e.g. `08:02:53.6`). This rejects the `08` in `00 01 00 00 08:02:53.6`.
_BYTE_RE = re.compile(
    r'((?:[0-9A-F]{2}\s)+[0-9A-F]{2}(?![0-9A-F:.])'
    r'|(?:[0-9A-F]{2}\s)+'
    r'|[0-9A-F]{2}(?![0-9A-F:.]))'
)


def _bytes_run(text: str) -> list[str]:
    m = _BYTE_RE.match(text)
    return m.group(1).split() if m else []


# The app prints the length prefix and header as 8-hex-digit groups with no
# inner spaces, then the args / payload one byte per token.
_DISPLAY_RE = re.compile(r'([0-9A-F]{8})\s+([0-9A-F]{8})\s*')


def _display_run(text: str):
    """Split `len(8 hex) hdr(8 hex) <per-byte>` display hex -> (len, hdr, bytes)."""
    m = _DISPLAY_RE.match(text)
    if not m:
        return None
    return m.group(1), m.group(2), _bytes_run(text[m.end():])


def _parse_request_hex(disp):
    """disp = (len(8 hex), hdr(8 hex display), [args bytes...]) -> dict."""
    if disp is None:
        return None
    len_hex, disp_hex, args_tokens = disp
    try:
        length = int(len_hex, 16)
        seq = int(disp_hex[0:2], 16)
        cmd_be = int(disp_hex[4:8], 16)          # bytes 2..8 = '00' + cmd_be
        args = _bytes(args_tokens)
    except ValueError:
        return None
    return {'length': length, 'seq': seq, 'cmd': cmd_be, 'args': args}


def _parse_response_hex(disp):
    """Same display layout as requests: (len, hdr, payload bytes)."""
    return _parse_request_hex(disp)


def _display_to_wire(disp):
    """Convert a display-hex tuple (len, hdr, per-byte payload) to wire bytes.

    Display order is `len(8 hex) seq 00 cmd_be <payload>`; the wire layout is
    `length(u32 LE) cmd_le 00 seq <payload>`. Some log variants print the full
    response inline after the RESP header with no separate `Got N bytes:`
    dump; this reconstructs the raw bytes for those.
    """
    len_hex, disp_hex, tokens = disp
    length = int(len_hex, 16)
    seq = int(disp_hex[0:2], 16)
    cmd_be = int(disp_hex[4:8], 16)
    wire_hdr = struct.pack('<HBB', cmd_be, 0, seq)
    return struct.pack('<I', length) + wire_hdr + _bytes(tokens)


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------
_HEADER_RE = re.compile(r'^\ufeff?#RadiaCode Log file (.*)$')
_DATE_RE = re.compile(r'(\w{3})\s+(\d{1,2}),\s+(\d{4})')
_MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}
_TIME_RE = re.compile(r'^(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?')


def parse_log(path: Path):
    """Parse one log file into (header_info, messages)."""
    header: dict[str, str] = {}
    log_date: datetime.datetime | None = None
    messages: list[dict] = []

    cur: dict | None = None      # current message under construction
    cur_started = False
    cur_line = 0
    interp_lines: list[str] = []  # interpretation lines awaiting a message

    def finalize(msg):
        if msg is not None:
            messages.append(msg)

    with open(path, encoding='utf-8', errors='ignore') as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip('\n')

            # --- header block (before any protocol message) ---
            if not cur_started:
                m = _HEADER_RE.match(line)
                if m:
                    log_date = _parse_log_date(m.group(1))
                    header['date'] = m.group(1)
                    continue
                if ':' in line and log_date is None:
                    header.setdefault('first_line', line)
                if _REQ_RE.search(line) or _GOT_RE.search(line):
                    cur_started = True
                else:
                    if line and header.get('first_line') is None:
                        header.setdefault('first_line', line)
                    continue

            # --- protocol messages ---
            events = []
            for pat, kind in ((_REQ_RE, 'req'), (_GOT_RE, 'got'), (_RESP_RE, 'resp')):
                m = pat.search(line)
                if m:
                    events.append((m.start(), kind, m))
            events.sort()

            for pos, kind, m in events:
                if kind == 'req':
                    # Edge case: the *previous* message's response tail may be
                    # merged onto this request line (a log artifact). If the
                    # previous message is still incomplete (it announced a
                    # `resp_total` via its RESP header but captured fewer bytes),
                    # route a trailing GOT on this line to it before starting a
                    # new message.
                    skip_got_end = None
                    if cur is not None and cur.get('resp_total') is not None:
                        captured = len(cur.get('_resp', b''))
                        if captured < cur['resp_total']:
                            got = _GOT_RE.search(line[m.end():])
                            if got:
                                _append_got(cur, line[m.end() + got.end():])
                                skip_got_end = m.end() + got.end()
                    finalize(cur)
                    disp = _display_run(line[m.end():])
                    parsed = None
                    tokens = None
                    if disp:
                        parsed = _parse_request_hex(disp)
                        tokens = [disp[0], disp[1]] + disp[2]
                    cur = {
                        'index': int(m.group(1), 16),
                        'command': m.group(2),
                        'len': int(m.group(3)),
                        'line': lineno,
                        'request_hex': ' '.join(tokens) if tokens else None,
                        'seq': parsed['seq'] if parsed else None,
                        'cmd': parsed['cmd'] if parsed else None,
                        'args': parsed['args'] if parsed else None,
                        'response_hex': None,
                        'payload_hex': None,
                        'app_interpretation': list(interp_lines),
                        'ts': _log_timestamp(line, log_date),
                        '_skip_got_line': lineno,
                        '_skip_got_end': skip_got_end,
                    }
                    interp_lines = []

                elif kind == 'got' and cur is not None:
                    if (
                        not _response_complete(cur)
                        and (
                            cur.get('_skip_got_line') != lineno
                            or cur.get('_skip_got_end') is None
                            or m.start() >= cur['_skip_got_end']
                        )
                    ):
                        _append_got(cur, line[m.end():])

                elif kind == 'resp' and cur is not None:
                    disp = _display_run(line[m.end():])
                    tokens = [disp[0], disp[1]] + disp[2] if disp else []
                    cur['response_hex'] = ' '.join(tokens) or cur['response_hex']
                    cur['resp_time'] = f"{m.group(4)}/{m.group(5)} ms"
                    cur['resp_total'] = int(m.group(3))
                    # Log variants without `Got N bytes:` dumps carry the raw
                    # response inline after the RESP header; reconstruct it.
                    if disp and not cur.get('_resp'):
                        cur['_resp'] = bytearray(_display_to_wire(disp))
                    rest = line[m.end():]
                    hex_text = ' '.join(tokens)
                    interp_rest = rest[len(hex_text):] if tokens else rest
                    cur.setdefault('inline_interp', []).append(interp_rest.strip())

    finalize(cur)
    # attach the tail interpretation lines
    if messages and interp_lines:
        messages[-1]['app_interpretation'].extend(interp_lines)
    return header, messages


def _append_got(cur: dict, text: str):
    tokens = _bytes_run(text)
    if not tokens:
        return
    cur.setdefault('_resp', bytearray()).extend(_bytes(tokens))


def _response_complete(cur: dict | None) -> bool:
    """True once the current message has captured all bytes its RESP announced.

    A device-initiated push (e.g. the screen-mirror framebuffer updates) arrives
    as bare `Got N bytes:` lines with no REQ/RESP markers. Once a request's
    response is fully captured (resp_total reached), later `Got` lines belong to
    such a push and must NOT be appended to the request's response.
    """
    if cur is None:
        return True
    total = cur.get('resp_total')
    if total is None:
        return False
    return len(cur.get('_resp', b'')) >= total


def _parse_log_date(header_date: str):
    m = _DATE_RE.search(header_date)
    if not m:
        return None
    mon, day, year = m.group(1), int(m.group(2)), int(m.group(3))
    return datetime.datetime(year, _MONTHS[mon], day)


def _log_timestamp(line: str, log_date: datetime.datetime | None):
    m = _TIME_RE.match(line.lstrip())
    if not m or log_date is None:
        return None
    h, mi, s = int(m.group(1)), int(m.group(2)), int(m.group(3))
    micro = int(m.group(4) or 0) * 100000
    return datetime.datetime(
        log_date.year, log_date.month, log_date.day, h, mi, s, micro
    )


def _finalize_message(msg: dict) -> dict:
    """Build the raw-wire hex fields (length prefix + header + body)."""
    raw = msg.pop('_resp', None)
    resp = bytes(raw) if raw is not None else b''
    msg['response_raw_hex'] = ' '.join(f'{b:02X}' for b in resp) or None
    msg['response_payload_hex'] = ' '.join(f'{b:02X}' for b in resp[8:]) or None
    return msg


# ---------------------------------------------------------------------------
# Re-decoding
# ---------------------------------------------------------------------------
_CMD_IDS = {
    'SET_EXCHANGE': 0x0007,
    'GET_STATUS': 0x0005,
    'GET_VERSION': 0x000A,
    'GET_SERIAL': 0x000B,
    'FW_IMAGE_GET_INFO': 0x0012,
    'FW_IMAGE_WRITE': 0x0013,
    'FW_IMAGE_UPDATE': 0x0014,
    'RD_SIGNAT': 0x0101,
    'FW_SIGNATURE': 0x0101,
    'RD_HW_CONFIG': 0x0807,
    'RD_FLASH_AREA': 0x081C,
    'RD_FLASH': 0x081C,
    'RD_VIRT_SFR': 0x0824,
    'WR_VIRT_SFR': 0x0825,
    'RD_VIRT_STRING': 0x0826,
    'WR_VIRT_STRING': 0x0827,
    'RD_VIRT_SFR_BATCH': 0x082A,
    'WR_VIRT_SFR_BATCH': 0x082B,
    'RD_VIRT_STRING_BATCH': 0x082C,
    'WR_VIRT_STRING_BATCH': 0x082D,
    'SET_LOCAL_TIME': 0x0A04,
    'SET_TIME': 0x0A04,
    'SET_BT_EXCHANGE_ID': 0x0903,
}


def _strip_trailing_nul(data: bytes, flen: int) -> bytes:
    # the firmware sometimes appends a stray 0x00 after the data
    if len(data) == flen + 1 and data[-1] == 0x00:
        return data[:-1]
    return data


def decode_message(msg: dict, ctx: dict) -> dict:
    """Re-decode one message; returns a structured dict. Raises on failure."""
    command = msg['command']
    resp = msg.get('_resp') or b''
    if len(resp) < 8:
        raise ValueError('response shorter than 8 bytes (length prefix + header)')
    payload = resp[8:]  # everything after the 4-byte length prefix + header
    bb = BytesBuffer(payload)

    if command == 'SET_EXCHANGE':
        ex = decode_SET_EXCHANGE(bb)
        return {
            'target_id': f'0x{ex.target_id:08X}',
            'tx_size': ex.tx_size,
            'rx_size': ex.rx_size,
            'if_ready': ex.if_ready,
            'if_type': ex.if_type.name,
            'if_type_value': int(ex.if_type),
            'tail': payload[bb._pos:].hex(' ') or None,
        }

    if command == 'GET_STATUS':
        flags = bb.unpack('<I')[0]
        assert bb.size() == 0
        df = rtypes.DeviceFlags(flags)
        return {'status': f'0x{flags:08X}', 'bits': df.set}

    if command == 'GET_VERSION':
        boot_minor, boot_major = bb.unpack('<HH')
        boot_date = bb.unpack_string()
        target_minor, target_major = bb.unpack('<HH')
        target_date = bb.unpack_string()
        return {
            'boot': {'major': boot_major, 'minor': boot_minor, 'date': boot_date},
            'target': {'major': target_major, 'minor': target_minor, 'date': target_date},
        }

    if command == 'FW_IMAGE_GET_INFO':
        # body: image_size(u32) + write_buffer_size(u32) + signature(u32) + crc32(u32)
        image_size = bb.unpack('<I')[0]
        buffer_size = bb.unpack('<I')[0]
        signature = bb.unpack('<I')[0]
        crc32 = bb.unpack('<I')[0]
        return {
            'image_size': image_size,
            'buffer_size': buffer_size,
            'signature': f'0x{signature:08X}',
            'crc32': f'0x{crc32:08X}',
        }

    if command == 'FW_IMAGE_UPDATE':
        # request: exchange_target(u32) + 0(u32) + image_signature(u32);
        # response: retcode(u32) + value(u32)
        args = msg.get('args') or b''
        return {
            'exchange_target': f'0x{int.from_bytes(args[0:4], "little"):08X}' if len(args) >= 4 else None,
            'zero': int.from_bytes(args[4:8], 'little') if len(args) >= 8 else None,
            'signature': f'0x{int.from_bytes(args[8:12], "little"):08X}' if len(args) >= 12 else None,
            'retcode': bb.unpack('<I')[0],
            'value': bb.unpack('<I')[0],
        }

    if command == 'FW_IMAGE_WRITE':
        # request: image_signature(u32) + offset(u32) + count(u32) + data(count);
        # response: retcode(u32)
        args = msg.get('args') or b''
        return {
            'signature': f'0x{int.from_bytes(args[0:4], "little"):08X}' if len(args) >= 4 else None,
            'offset': int.from_bytes(args[4:8], 'little') if len(args) >= 8 else None,
            'count': int.from_bytes(args[8:12], 'little') if len(args) >= 12 else None,
            'retcode': bb.unpack('<I')[0],
        }

    if command == 'RD_FLASH_AREA':
        fa = decode_RC_RD_FLASH_AREA(BytesBuffer(payload))
        return {
            'public_signature': f'0x{fa.public_signature:08X}',
            'struct_len': fa.struct_len,
            'boot_signature': f'0x{fa.boot_signature:08X}',
            'boot_date': fa.boot_date.isoformat(),
            'prod_serial_number': fa.prod_serial_number,
            'trg_file_name': fa.trg_file_name,
            'prod_name': fa.prod_name,
            'calib_bp0': fa.calib_bp0,
            'calib_bp290': fa.calib_bp290,
            'vid': f'0x{fa.vid:04X}',
            'pid': f'0x{fa.pid:04X}',
            'mnfct_name': fa.mnfct_name,
            'target_id': f'0x{fa.target_id:08X}',
            'target_start_timeout': fa.target_start_timeout,
        }

    if command in ('RD_SIGNAT', 'FW_SIGNATURE'):
        signature = bb.unpack('<I')[0]
        filename = bb.unpack_string()
        idstring = bb.unpack_string()
        return {
            'signature': f'0x{signature:08X}',
            'filename': filename,
            'idstring': idstring,
            'extra': payload[bb._pos:].hex(' ') or None,
        }

    if command == 'GET_SERIAL':
        serial_len = bb.unpack('<I')[0]
        groups = [bb.unpack('<I')[0] for _ in range(serial_len // 4)]
        return {'serial': '-'.join(f'{v:08X}' for v in groups)}

    if command == 'RD_HW_CONFIG':
        count = bb.unpack('<I')[0]
        fields = {}
        # best-effort: the app prints sensor counts then LCD + frame tick
        if bb.size() >= 8:
            vals = [bb.unpack('<B')[0] for _ in range(7)]
            fields.update({
                'photo_sensors': vals[0],
                'ad_sensors': vals[1],
                'pumps': vals[2],
                'fast_valves': vals[3],
                'slow_valves': vals[4],
                'sd_cards': vals[5],
                'lcd': vals[6],
            })
        if bb.size() >= 2:
            fields['frame_tick_us'] = bb.unpack('<H')[0]
        return {'count': count, **fields, 'raw_tail': payload[bb._pos:].hex(' ') or None}

    if command == 'RD_VIRT_SFR_BATCH':
        return _decode_vsfr_batch(bb, msg)

    if command in ('WR_VIRT_SFR', 'WR_VIRT_STRING', 'WR_VIRT_SFR_BATCH'):
        retcode = bb.unpack('<I')[0]
        return {'retcode': retcode}

    if command == 'RD_VIRT_SFR':
        retcode = bb.unpack('<I')[0]
        value = bb.unpack('<I')[0]
        return {'retcode': retcode, 'value': value, 'value_hex': f'0x{value:08X}'}

    if command == 'RD_VIRT_STRING':
        return _decode_virtual_string(bb, msg, ctx)

    if command == 'SET_LOCAL_TIME':
        args = msg.get('args') or b''
        if len(args) == 8:
            day, mon, year0, _, sec, minute, hour, _ = struct.unpack('<BBBBBBBB', args)
            return {'local_time': f'{year0 + 2000:04}-{mon:02}-{day:02} {hour:02}:{minute:02}:{sec:02}'}
        return {'note': 'empty'}

    raise ValueError(f'no decoder for command {command}')


def _decode_vsfr_batch(bb: BytesBuffer, msg: dict) -> dict:
    valid_flags = bb.unpack('<I')[0]
    nvsfr = int.from_bytes((msg.get('args') or b'')[:4], 'little') if msg.get('args') else 0
    ids = [
        int.from_bytes(msg['args'][4 + 4 * i: 8 + 4 * i], 'little')
        for i in range(nvsfr)
    ] if msg.get('args') else []
    values = bb.unpack(f'<{len(ids)}I') if ids else []
    decoded = []
    for i, v in enumerate(values):
        fmt = rtypes._VSFR_FORMATS.get(rtypes.VSFR(ids[i])) if ids[i] in rtypes._VSFR_FORMATS else None
        name = _VSFR_NAMES.get(ids[i], f'0x{ids[i]:04X}')
        entry = {'vsfr': name, 'id': f'0x{ids[i]:04X}', 'raw': v}
        if fmt:
            parsed = struct.unpack(f'<{fmt}', struct.pack('<I', v))
            entry['value'] = parsed[0]
            entry['format'] = fmt
        decoded.append(entry)
    return {
        'valid_flags': f'0x{valid_flags:08X}',
        'valid_flags_bits': f'{valid_flags:016b}',
        'values': decoded,
    }


def _build_vs_decoders():
    global _VS_DECODERS
    _VS_DECODERS = {
        int(rtypes.VS.CONFIGURATION): 'string_cp1251',
        int(rtypes.VS.FW_DESCRIPTOR): 'string_ascii',
        int(rtypes.VS.SERIAL_NUMBER): 'string_ascii',
        int(rtypes.VS.TEXT_MESSAGE): 'string_ascii',
        int(rtypes.VS.MEM_SNAPSHOT): 'raw',
        int(rtypes.VS.SFR_FILE): 'string_ascii',
        int(rtypes.VS.DATA_BUF): 'databuf',
        int(rtypes.VS.SPECTRUM): 'spectrum',
        int(rtypes.VS.ENERGY_CALIB): 'calib',
        int(rtypes.VS.SPEC_ACCUM): 'spectrum',
        int(rtypes.VS.SPEC_DIFF): 'spec_diff',
        int(rtypes.VS.SPEC_RESET): 'spec_reset',
    }


def _decode_virtual_string(bb: BytesBuffer, msg: dict, ctx: dict) -> dict:
    retcode, flen = bb.unpack('<II')
    data = _strip_trailing_nul(bb.data(), flen)
    vsid = int.from_bytes((msg.get('args') or b'')[:4], 'little')
    vs_name = _VS_NAMES.get(vsid, f'0x{vsid:04X}')
    kind = _VS_DECODERS.get(vsid, 'raw')

    out = {'vs': vs_name, 'id': f'0x{vsid:04X}', 'retcode': retcode, 'flen': flen}
    out['data_hex'] = data.hex(' ')

    if kind == 'string_cp1251':
        out['text'] = data.decode('cp1251', errors='replace')
    elif kind == 'string_ascii':
        out['text'] = data.decode('ascii', errors='replace')
    elif kind == 'calib':
        if len(data) >= 12:
            a0, a1, a2 = struct.unpack('<fff', data[:12])
            out['a0'] = a0
            out['a1'] = a1
            out['a2'] = a2
    elif kind == 'spectrum':
        # observed data is always v1 run-length regardless of SpecFormatVersion
        sp = decode_RC_VS_SPECTRUM(BytesBuffer(data), 1)
        out.update(_spectrum_to_dict(sp))
    elif kind == 'spec_reset':
        sp = decode_RC_VS_SPEC_RESET(BytesBuffer(data), 1)
        out.update(_spectrum_to_dict(sp))
    elif kind == 'spec_diff':
        dur, diffs = decode_RC_VS_SPEC_DIFF(BytesBuffer(data), 1)
        out['duration_sec'] = dur
        out['channels'] = diffs
        out['total'] = sum(diffs)
    elif kind == 'databuf':
        base = ctx.get('base_time') or datetime.datetime.now()
        records = decode_VS_DATA_BUF(BytesBuffer(data), base)
        out['records'] = [_record_to_dict(r) for r in records]
    return out


def _spectrum_to_dict(sp) -> dict:
    return {
        'duration_sec': sp.duration.total_seconds(),
        'a0': sp.a0,
        'a1': sp.a1,
        'a2': sp.a2,
        'channels': sp.counts,
        'total_counts': sum(sp.counts),
        'channels_len': len(sp.counts),
    }


def _record_to_dict(rec) -> dict:
    d = {'type': type(rec).__name__, 'dt': rec.dt.isoformat()}
    for field in rec.__dataclass_fields__:
        val = getattr(rec, field)
        if field == 'dt':
            continue
        if isinstance(val, (rtypes.RecordFlags, rtypes.RealTimeFlags)):
            d[field] = {'value': f'0x{int(val):04X}', 'set': val.set}
        elif isinstance(val, rtypes.EventId):
            d[field] = val.name
        else:
            d[field] = val
    return d


def _json_default(obj):
    """Serialize bytes as hex, datetimes as isoformat, enums/flags as ints."""
    if isinstance(obj, bytes):
        return obj.hex(' ')
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    return str(obj)


# ---------------------------------------------------------------------------
# Command-line
# ---------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('logs', nargs='+', help='radiacode_logs_*.txt files')
    parser.add_argument('--source', default='./radiacode/src',
                        help='radiacode source directory (containing the radiacode/ package)')
    parser.add_argument('--outdir', default=None, help='directory for JSON output')
    parser.add_argument('--no-decode', action='store_true', help='do not re-decode')
    args = parser.parse_args(argv)

    _import_decoders(Path(args.source))

    summary: dict[str, dict] = {}
    for path in map(Path, args.logs):
        header, msgs = parse_log(path)
        decoded_ok = 0
        decoded_fail = 0
        for msg in msgs:
            resp = msg.get('_resp') or b''
            if len(resp) < 8:
                # No response captured at all (e.g. the BLE connection dropped
                # right after the request, or the log was truncated).
                msg['decodable'] = False
                msg['decode_error'] = f'no response captured ({len(resp)} bytes)'
                decoded_fail += 1
                _finalize_message(msg)
                key = msg['command']
                s = summary.setdefault(key, {'found': 0, 'ok': 0, 'fail': 0})
                s['found'] += 1
                s['fail'] += 1
                continue
            try:
                if not args.no_decode:
                    ctx = {'base_time': msg['ts']}
                    msg['decoded'] = decode_message(msg, ctx)
                msg['decodable'] = True
                decoded_ok += 1
            except Exception as exc:  # noqa: BLE001
                msg['decodable'] = False
                msg['decode_error'] = f'{type(exc).__name__}: {exc}'
                decoded_fail += 1
            _finalize_message(msg)
            key = msg['command']
            s = summary.setdefault(key, {'found': 0, 'ok': 0, 'fail': 0})
            s['found'] += 1
            s['ok'] += int(msg['decodable'])
            s['fail'] += int(not msg['decodable'])

        out = {'source': path.name, 'header': header, 'messages': msgs}
        out_path = Path(args.outdir) / (path.stem + '.json') if args.outdir else path.with_suffix('.json')
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump(out, fh, ensure_ascii=False, indent=1, default=_json_default)
        print(f'{path.name}: {len(msgs):6d} messages, {decoded_ok:6d} decoded, {decoded_fail:6d} failed -> {out_path}')

    print('\nPer-command summary (found / decoded / failed):')
    for cmd, s in sorted(summary.items()):
        print(f'  {cmd:28s} {s["found"]:8d} {s["ok"]:8d} {s["fail"]:8d}')


if __name__ == '__main__':
    main()
