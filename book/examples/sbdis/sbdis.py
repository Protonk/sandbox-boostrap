#!/usr/bin/env python3

"""
HISTORICAL EXAMPLE (legacy decision-tree profiles)

`sbdis` targets the early “decision-tree” compiled profile format and is kept for historical inspection.
It is not a decoder for the modern graph-based compiled profile format used on this host baseline.
"""

import binascii
import pprint
import struct
import sys

from pathlib import Path

import redis
import find_operations
sys.path.append(str(Path(__file__).resolve().parents[3]))
from book.api.profile_tools import ingestion as ingestion  # noqa: E402
# Header/section parsing now flows through the shared Axis 4.1 ingestion layer.

# u2 re_table_offset (8-byte words from start of sb)
# u1 re_table_count (really just the low byte)
# u1 padding
# u2[] op_table (8-byte word offset)

def load_op_names_ios():
  global OP_TABLE_COUNT
  OP_TABLE_COUNT = 0x49
  with open('ops.txt', 'r') as f:
    ops = [s.strip() for s in f.readlines()]
  return ops[0:OP_TABLE_COUNT]

def load_op_names_osx():
  try:
    ops = find_operations.get_operations("/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox")
  except Exception:
    ops = []
  return ops

def show_filter(typ, arg, re_table):
  if typ == 1:
    return 'path.match("%s")' % (re_table[arg],)
  elif typ == 3:
    return 'file-mode == %d' % (arg,)
  elif typ == 4:
    return 'mach-global.match("%s")' % (re_table[arg],)
  elif typ == 11:
    return 'iokit.match("%s")' % (re_table[arg],)
  elif typ == 12:
    return 'path_in_extensions'
  else:
    return 'filter(%d, %d)' % (typ, arg)

def usage():
  print('usage:')
  print('    sbdis (ios | osx) binary.sb.bin')
  print()
  print('    This will turn a binary sandbox profile into something human')
  print('    readable.  Be sure to specify OSX or iOS on the commandline')
  print('    to match the origin of the profile.')
  sys.exit(-1)

if len(sys.argv) != 3:
  usage()

mode = sys.argv[1]
ops = []
if mode == 'ios':
  ops = load_op_names_ios()
elif mode == 'osx':
  ops = load_op_names_osx()
else:
  usage()

path = Path(sys.argv[2])
blob = ingestion.ProfileBlob(bytes=path.read_bytes(), source="sbdis")
header = ingestion.parse_header(blob)
if header.format_variant != "legacy-decision-tree":
  print(f"unsupported profile format: {header.format_variant} (expected legacy decision-tree)")
  sys.exit(1)
sections = ingestion.slice_sections(blob, header)

data = blob.bytes
op_table = struct.unpack_from(f"<{header.operation_count}H", sections.op_table, 0)
regex_table = []
if header.regex_count:
  re_table = struct.unpack_from(f"<{header.regex_count}H", sections.regex_literals, 0)
  for offset in re_table:
    start = offset * 8
    if start + 4 > len(data):
      regex_table.append("<invalid-regex-offset>")
      continue
    re_count = struct.unpack_from("<I", data, start)[0]
    raw = data[start + 4 : start + 4 + re_count]
    g = redis.reToGraph(raw)
    re = redis.graphToRegEx(g)
    regex_table.append(re)

op_count = header.operation_count
if len(ops) < op_count:
  # Fallback generic names when we cannot resolve all operations
  ops.extend([f'op_{i}' for i in range(len(ops), op_count)])

op_bag = {}
for i, op_offset in enumerate(op_table):
  if op_offset not in op_bag:
    op_bag[op_offset] = set()
  op_bag[op_offset].add(i)

def parse_filter(data, offset_words):
  base = offset_words * 8
  if base >= len(data):
    return (True, "<invalid-offset>")
  is_terminal = data[base] == 1
  if is_terminal:
    result = data[base + 2] if base + 2 < len(data) else 0
    resultstr = {0 : 'allow', 1 : 'deny'}.get(result & 1, f'unknown-{result & 1}')
    resultstr += {0 : '', 2 : '-with-log'}[result & 2]
    resultstr += {True : '', False : '-with-unknown-modifiers'}[(result & 0xfffc) == 0]
    return (True, resultstr)
  else:
    if base + 8 > len(data):
      return (True, "<truncated-nonterminal>")
    filter, filter_arg, match, unmatch = struct.unpack_from('<BHHH', data, base + 1)
    return (False, (filter, filter_arg), parse_filter(data, match), parse_filter(data, unmatch))


for i, op_offset in enumerate(op_table):
  # default is special case
  if i != 0 and op_offset == op_table[0]:
    continue

  if op_offset not in op_bag:
    continue

  if i != 0:
    op_list = list(op_bag[op_offset])
  else:
    op_list = [0]

  del op_bag[op_offset]

  filter = parse_filter(data, op_offset)
  #pprint.pprint(filter)

  def make_pfilter(filter):
    pfilter = []
    while filter is not None:
      if filter[0]:
        pfilter.append(filter[1])
        filter = None
      else:
        typ, arg = filter[1]
        true_filter = filter[2]
        false_filter = filter[3]

        if not true_filter[0] and \
           not false_filter[0]:
          pfilter.append(('if', show_filter(typ, arg, regex_table),
            make_pfilter(true_filter), make_pfilter(false_filter)))
          filter = None
        elif true_filter[0]:
          pfilter.append((true_filter[1], show_filter(typ, arg, regex_table)))
          filter = false_filter
        elif false_filter[0]:
          ff = 'true'
          if false_filter[1] == 'true':
            ff = 'false'
          pfilter.append((ff, show_filter(typ, arg, regex_table)))
          filter = true_filter
    return pfilter

  pfilter = ([ops[op] for op in op_list], make_pfilter(filter))
  pprint.pprint(pfilter)
