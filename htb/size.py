import struct, sys, pathlib

path = pathlib.Path(sys.argv[1])
with path.open('rb') as f:
    riff, fsize, webp = struct.unpack('<4sI4s', f.read(12))
    print(f"Total payload (FileSize field): {fsize} bytes")
    pos = 12
    while pos < fsize + 8:
        tag = f.read(4).decode('ascii')
        csize = struct.unpack('<I', f.read(4))[0]
        print(f"Chunk {tag.strip()}: {csize} bytes")
        f.seek(csize + (csize & 1), 1)  # skip payload + pad
        pos += 8 + csize + (csize & 1)
