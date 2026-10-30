"""Writes the frames of a pcap file as hexadecimal lines, each after the tcpdump summary of the frame."""
import struct, sys
pcap, summary, out = sys.argv[1:4]
data = open(pcap, 'rb').read()
magic, = struct.unpack('<I', data[:4])
assert magic == 0xa1b2c3d4, hex(magic)
linktype, = struct.unpack('<I', data[20:24])
assert linktype == 1
frames = []
offset = 24
while offset < len(data):
    _, _, captured, original = struct.unpack('<IIII', data[offset:offset + 16])
    assert captured == original
    frames.append(data[offset + 16:offset + 16 + captured])
    offset += 16 + captured
entries = []
for line in open(summary).read().splitlines():
    if line[:1].isdigit():
        entries.append([line[27:]])
    else:
        entries[-1].append(line.strip())
assert len(entries) == len(frames), (len(entries), len(frames))
with open(out, 'w') as file:
    for lines, frame in zip(entries, frames):
        for line in lines:
            file.write('# ' + line + '\n')
        file.write(frame.hex() + '\n\n')
