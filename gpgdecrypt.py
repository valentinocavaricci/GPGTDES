import hashlib
from DESGpg import TDES 

with open("test.txt.gpg", "rb") as f:
    contents = f.read()

print(contents)
print(len(contents))

offset = 0
eof = len(contents)

valid_packet_mask = 0x80
packet_version_mask = 0x40
old_tag_mask = 0x3c
old_len_mask = 0x03

packets = []   

while offset < eof:
    header_byte = contents[offset]

    print("header:", hex(header_byte))

    valid = header_byte & valid_packet_mask
    print("valid:", valid != 0)

    version = header_byte & packet_version_mask
    print("old format:", version == 0)

    if version == 0:
        tag = (header_byte & old_tag_mask) >> 2
        len_type = header_byte & old_len_mask

        if len_type == 0:
            packet_length = contents[offset + 1]
            header_size = 2
        elif len_type == 1:
            packet_length = int.from_bytes(contents[offset+1:offset+3], "big")
            header_size = 3
        elif len_type == 2:
            packet_length = int.from_bytes(contents[offset+1:offset+5], "big")
            header_size = 5
        elif len_type == 3:
            raise ValueError("invallid length")

        body = contents[offset+header_size : offset+header_size+packet_length]

        print("packet length:", packet_length)
        print("BODY---------------------------", body)

        packets.append((tag, body))

        offset += header_size + packet_length
    else:
       
        tag = header_byte & 0x3F
        length = contents[offset + 1]

        if length < 192:
            packet_length = length
            header_size = 2
        elif length < 224:
            b1 = length
            b2 = contents[offset + 2]
            packet_length = ((b1 - 192) << 8) + b2 + 192
            header_size = 3

        elif length == 255:
            packet_length = int.from_bytes(contents[offset+2:offset+6], "big")
            header_size = 6

        body = contents[offset+header_size : offset+header_size+packet_length]

        print("packet length:", packet_length)
        print("BODY---------------------------", body)

        packets.append((tag, body))

        offset += header_size + packet_length
        



for tag, body in packets:
    print("Tag:", tag, "Length:", len(body))

tag, body = packets[0]

print("\n========BODY DATA======")
if len(body) >= 4:
    print("Packet Version:", body[0])
    print("Cipher Algorithm:", body[1])
    print("S2K Type:", body[2])
    print("Hash Algorithm:", body[3])

if body[1] != 2 or body[2] != 0 or body[3] != 1:
    raise ValueError("invalid")


def s2k0(password):
    result = b""
    bytes_filled = pass_count = 0

    while len(result) < 24:
        padding = b"\x00" * pass_count
        hash_val = hashlib.md5(padding + password).digest()
        result += hash_val
        pass_count += 1
    return result[:24]


password = b"test"
session_key = s2k0(password)
print("\nSession Key:", s2k0(password))

encbody = None

for t, b in packets:
    if t == 18:
        encbody = b
        break

if encbody == None:
    raise ValueError("18 wasn't found")


ciphertext = encbody[1:]

tdes = TDES(session_key, mode="GPG") 
plaintext = tdes.decrypt(ciphertext, key=session_key, mode="GPG")
print("THIS IS THE DECRYPTED PLAINTEXT===========================")
print(plaintext)

p = plaintext
start = p.find(b'b')
p = p[start:]


type = p[0]
filelen = p[1]
filename = p[2: 2+filelen].decode(errors="ignore")
timestart = 2 + filelen
timeend = timestart + 4
timebytes = p[timestart : timeend]
timestamp = int.from_bytes(timebytes, "big")
message_start = timeend
message = p[message_start:]

print("type:", type)
print("Filename length:", filelen)
print("Filename:", filename)
print("Timestamp:", timestamp)
print("============= MESSAGE ======================")
print(message.decode(errors="ignore"))

with open(filename, 'wb') as f:
    f.write(message)

print(f'saved the message to {filename}')