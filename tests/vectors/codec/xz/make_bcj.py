"""Writes bcj.bin: 16 KiB of pseudo-random small bytes with instructions of the eight BCJ
architectures at their alignments, so that every filter converts something."""
import random, struct, sys
random.seed(20261025)
data = bytearray(random.getrandbits(3) for _ in range(16384))
for position in range(0, 16384 - 16, 16):
    kind = (position // 16) % 9
    target = random.randrange(-2**20, 2**20)
    if kind == 0:   # x86 CALL rel32
        data[position:position + 5] = b"\xE8" + struct.pack("<i", target)
    elif kind == 1: # PowerPC BL
        data[position:position + 4] = struct.pack(">I", 0x48000001 | (target << 2 & 0x03FFFFFC))
    elif kind == 2: # ARM BL
        data[position:position + 4] = struct.pack("<I", 0xEB000000 | (target & 0xFFFFFF))
    elif kind == 3: # ARM Thumb BL pair
        data[position:position + 4] = bytes([target >> 11 & 0xFF, 0xF0 | (target >> 19 & 7), target & 0xFF, 0xF8 | (target >> 8 & 7)])
    elif kind == 4: # SPARC CALL
        data[position:position + 4] = struct.pack(">I", 0x40000000 | (target & 0x3FFFFF))
    elif kind == 5: # ARM64 BL and ADRP
        data[position:position + 4] = struct.pack("<I", 0x94000000 | (target & 0x03FFFFFF))
        data[position + 4:position + 8] = struct.pack("<I", 0x90000000 | (target & 3) << 29 | (target >> 2 & 0x7FFF) << 5 | 3)
    elif kind == 6: # RISC-V JAL ra and AUIPC t1 + JALR
        data[position:position + 4] = struct.pack("<I", 0x000000EF | (target & 0xFFFFF) << 12)
        data[position + 4:position + 8] = struct.pack("<I", 0x00000317 | (target & 0xFFFFF) << 12)
        data[position + 8:position + 12] = struct.pack("<I", 0x000300E7 | (target & 0xFFF) << 20)
    elif kind == 7: # IA-64 bundle of template 0x10 with a branch in slot 2
        bundle = int.from_bytes(bytes(data[position:position + 16]), "little")
        bundle = (bundle & ~0x1F) | 0x10
        slot = (0x5 << 37) | ((target & 0xFFFFF) << 13)
        bundle &= ~(((1 << 41) - 1) << 87)
        bundle |= slot << 87
        data[position:position + 16] = bundle.to_bytes(16, "little")
open(sys.argv[1], "wb").write(bytes(data))
