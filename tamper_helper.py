import os, struct, sys
data = bytearray(open(sys.argv[1], 'rb').read())
trailer_size = 121
trailer = data[-trailer_size:]
tar_offset = struct.unpack('>Q', trailer[0:8])[0]
flip_pos = tar_offset + 16
data[flip_pos] ^= 0xFF
open(sys.argv[2], 'wb').write(bytes(data))
os.chmod(sys.argv[2], 0o755)
print('Flipped byte at offset', flip_pos, '(payload starts at', tar_offset, ')')
