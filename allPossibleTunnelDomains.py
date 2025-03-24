import hashlib
import struct

ASSIGNED_TUNNEL_SERVER_DOMAINS = ["cable.ua5v.com", "cable.auth.com"]

def decode_tunnel_server_domain(encoded: int) -> tuple[str, bool]:
    if encoded < 256:
        if encoded >= len(ASSIGNED_TUNNEL_SERVER_DOMAINS):
            return "", False
        return ASSIGNED_TUNNEL_SERVER_DOMAINS[encoded], True

    sha_input = bytearray([
        0x63, 0x61, 0x42, 0x4c, 0x45, 0x76, 0x32, 0x20,
        0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73,
        0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x64, 0x6f,
        0x6d, 0x61, 0x69, 0x6e
    ])
    
    sha_input.extend(struct.pack("<H", encoded))  # Little-endian uint16
    sha_input.append(0)  # Append zero byte

    digest = hashlib.sha256(sha_input).digest()
    v = struct.unpack("<Q", digest[:8])[0]  # Read first 8 bytes as little-endian uint64

    tld_index = v & 3  # Extract last 2 bits for TLD
    v >>= 2  # Shift right to remove those bits

    ret = "cable."
    BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567"

    while v != 0:
        ret += BASE32_CHARS[v & 31]
        v >>= 5  # Shift right by 5 bits

    TLDS = [".com", ".org", ".net", ".info"]
    ret += TLDS[tld_index & 3]  # Select TLD

    return ret, True

# Write all possible values to a file
output_file = "decoded_tunnel_domains.txt"
with open(output_file, "w") as f:
    for encoded in range(256, 65536):
        domain, _ = decode_tunnel_server_domain(encoded)
        f.write(f"{encoded}: {domain}\n")

print(f"All decoded domain names are written to {output_file}")
