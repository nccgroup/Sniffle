# Written by Sultan Qasim Khan
# Copyright (c) 2024, NCC Group plc
# Released as open source under GPLv3

def printable(s):
    pchar = lambda a: chr(a) if 32 <= a < 127 else '.'
    return ''.join([pchar(a) for a in s])

def hexline(s, bytes_per_group=8):
    chunks = []
    for i in range(0, len(s), bytes_per_group):
        chunks.append(' '.join([f'{c:02x}' for c in s[i:i+bytes_per_group]]))
    return '  '.join(chunks)

def hexdump(s, bytes_per_line=16, bytes_per_group=8):
    prev_chunk = None
    in_repeat = False
    hexline_len = 3*bytes_per_line + bytes_per_line//bytes_per_group - 2
    lines = []
    for i in range(0, len(s), bytes_per_line):
        chunk = s[i:i+bytes_per_line]
        if chunk == prev_chunk and i + bytes_per_line < len(s):
            if not in_repeat:
                lines.append('*')
                in_repeat = True
        else:
            lines.append(f'0x{i:04x}:  {hexline(chunk, bytes_per_group):{hexline_len}}  {printable(chunk)}')
            in_repeat = False
        prev_chunk = chunk
    return '\n'.join(lines)

