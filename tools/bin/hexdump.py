#!/usr/bin/env python3
import sys
import os

def main():
    args = sys.argv[1:]
    files = []
    format_mode = None
    canonical = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '-v':
            pass
        elif arg == '-C':
            canonical = True
        elif arg == '-e':
            i += 1
            if i < len(args):
                format_mode = args[i]
        elif not arg.startswith('-'):
            files.append(arg)
        i += 1

    if files:
        data = b''
        for f in files:
            try:
                with open(f, 'rb') as fp:
                    data += fp.read()
            except Exception:
                pass
    else:
        try:
            data = sys.stdin.buffer.read()
        except Exception:
            data = b''

    if canonical:
        # Canonical hex+ascii dump
        offset = 0
        for chunk_idx in range(0, len(data), 16):
            chunk = data[chunk_idx:chunk_idx+16]
            hex_part1 = " ".join(f"{b:02x}" for b in chunk[:8])
            hex_part2 = " ".join(f"{b:02x}" for b in chunk[8:])
            hex_str = f"{hex_part1:<23}  {hex_part2:<23}"
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            sys.stdout.write(f"{offset:08x}  {hex_str}  |{ascii_str}|\n")
            offset += len(chunk)
        if len(data) > 0:
            sys.stdout.write(f"{len(data):08x}\n")
    elif format_mode and ("%02X" in format_mode or "%02x" in format_mode):
        sep = "," if ",\\" in format_mode or ",$" in format_mode else ""
        uppercase = "%02X" in format_mode
        if uppercase:
            sys.stdout.write(data.hex().upper())
        else:
            sys.stdout.write(data.hex().lower())
    else:
        # Default hex output
        sys.stdout.write(data.hex().upper())

if __name__ == '__main__':
    main()
