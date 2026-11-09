#!/usr/bin/env python3
"""Measure whether the databuf decoder's `_resync` recovery path is still needed.

`decode_VS_DATA_BUF` skips a malformed/truncated record and re-syncs to the next
plausible record boundary via `_resync`. This tool answers: across a set of logs,
how often does that path actually fire, and how many records does it recover that
a "stop at the first bad byte" decoder would drop?

Method: for every `VS_DATA_BUF` (0x100) response in each log, decode the buffer
twice -

  * with the real `_resync` (counting how many times it is called and how many
    times it finds a re-sync point), and
  * with `_resync` stubbed to always return False, which is exactly what removing
    the recovery would do (the decode loop `break`s on the first malformed
    record).

The difference in record counts is the number of records `_resync` rescues. A
file with `resync_calls=0` never exercises the path; a large `recovered` count
means removing it would silently lose data.

Usage:
    ./analyze_resync.py                      # all *.txt in the cwd
    ./analyze_resync.py rc103-*.txt          # specific logs
    ./analyze_resync.py --source ./radiacode/src
"""

from __future__ import annotations

import argparse
import datetime
import glob
import sys
from pathlib import Path


def _load(source: str):
    """Import extract_protocol and the databuf decoders from `source`/radiacode."""
    sys.path.insert(0, str(Path.cwd()))
    import extract_protocol as ep

    ep._import_decoders(Path(source))
    from radiacode.bytes_buffer import BytesBuffer
    import radiacode.decoders.databuf as db

    return ep, BytesBuffer, db


def databuf_payloads(ep, BytesBuffer, path: Path):
    """Yield the raw record bytes of every VS_DATA_BUF (0x100) response in a log."""
    _, msgs = ep.parse_log(path)
    for msg in msgs:
        if msg['command'] != 'RD_VIRT_STRING':
            continue
        resp = msg.get('_resp') or b''
        if len(resp) < 8:
            continue
        bb = BytesBuffer(resp[8:])
        try:
            _retcode, flen = bb.unpack('<II')
        except Exception:
            continue
        if int.from_bytes((msg.get('args') or b'')[:4], 'little') != 0x100:
            continue
        yield ep._strip_trailing_nul(bb.data(), flen)


def decode_pair(db, BytesBuffer, data: bytes, base: datetime.datetime):
    """Decode `data` with and without resync recovery.

    Returns (n_with, n_without, calls, hits): record counts with the real
    `_resync` and with it disabled, plus how many times `_resync` was called and
    how many of those calls located a re-sync point.
    """
    real_resync = db._resync
    calls = hits = 0

    def counting(br, rt=15, max_scan=512):
        nonlocal calls, hits
        calls += 1
        found = real_resync(br, rt, max_scan)
        hits += int(found)
        return found

    db._resync = counting
    try:
        n_with = len(db.decode_VS_DATA_BUF(BytesBuffer(data), base, ignore_errors=True))
    finally:
        db._resync = real_resync

    db._resync = lambda br, rt=15, max_scan=512: False  # simulate removing recovery
    try:
        n_without = len(db.decode_VS_DATA_BUF(BytesBuffer(data), base, ignore_errors=True))
    finally:
        db._resync = real_resync

    return n_with, n_without, calls, hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('logs', nargs='*', help='log files (default: *.txt in the cwd)')
    ap.add_argument('--source', default='./radiacode/src',
                    help='radiacode source dir containing the radiacode/ package')
    args = ap.parse_args(argv)

    ep, BytesBuffer, db = _load(args.source)
    base = datetime.datetime(2026, 1, 1)  # only affects dt, not record counts

    files = args.logs or sorted(glob.glob('*.txt'))
    tot = dict(bufs=0, calls=0, hits=0, with_=0, without=0, hit_bufs=0)
    for path in files:
        bufs = calls = hits = n_with = n_without = hit_bufs = 0
        for data in databuf_payloads(ep, BytesBuffer, Path(path)):
            bufs += 1
            w, wo, c, h = decode_pair(db, BytesBuffer, data, base)
            n_with += w
            n_without += wo
            calls += c
            hits += h
            hit_bufs += int(c > 0)
        recovered = n_with - n_without
        for k, v in dict(bufs=bufs, calls=calls, hits=hits, with_=n_with, without=n_without, hit_bufs=hit_bufs).items():
            tot[k] += v
        flag = '  <== resync used' if calls else ''
        print(f'{path:34s} bufs={bufs:6d} resync_calls={calls:3d} hits={hits:3d} recovered_recs={recovered:5d}{flag}')

    print(f"\nTOTAL buffers={tot['bufs']} resync_calls={tot['calls']} resync_hits={tot['hits']} "
          f"buffers_using_resync={tot['hit_bufs']} recovered_records={tot['with_'] - tot['without']}")
    verdict = 'NEEDED (recovers data)' if tot['with_'] > tot['without'] else 'never fired (could be removed)'
    print(f'VEDICT: _resync is {verdict}')


if __name__ == '__main__':
    main()
