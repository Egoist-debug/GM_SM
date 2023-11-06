from array import array
import binascii

Tj_rl = array(
    "L", ((0x79CC4519 << j | 0x79CC4519 >> 32 - j) & 0xFFFFFFFF for j in range(16))
)
Tj_rl.extend(
    (0x7A879D8A << (j & 31) | 0x7A879D8A >> (32 - j & 31)) & 0xFFFFFFFF
    for j in range(16, 64)
)
V0 = array(
    "L",
    [
        0x7380166F,
        0x4914B2B9,
        0x172442D7,
        0xDA8A0600,
        0xA96F30BC,
        0x163138AA,
        0xE38DEE4D,
        0xB0FB0E4E,
    ],
)


def CF(V, B):
    W = array("L", B)
    for j in range(16, 68):
        X = W[j - 16] ^ W[j - 9] ^ (W[j - 3] << 15 | W[j - 3] >> 17) & 0xFFFFFFFF
        W.append(
            (
                X
                ^ (X << 15 | X >> 17)
                ^ (X << 23 | X >> 9)
                ^ (W[j - 13] << 7 | W[j - 13] >> 25)
                ^ W[j - 6]
            )
            & 0xFFFFFFFF
        )
    W_ = array("L", (W[j] ^ W[j + 4] for j in range(64)))
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        A_rl12 = A << 12 | A >> 20
        tmp = (A_rl12 + E + Tj_rl[j]) & 0xFFFFFFFF
        SS1 = tmp << 7 | tmp >> 25
        SS2 = SS1 ^ A_rl12
        if j & 0x30:  # 16 <= j
            FF, GG = A & B | A & C | B & C, E & F | ~E & G
        else:
            FF, GG = A ^ B ^ C, E ^ F ^ G
        TT1, TT2 = (FF + D + SS2 + W_[j]) & 0xFFFFFFFF, (
            GG + H + SS1 + W[j]
        ) & 0xFFFFFFFF
        C, D, G, H = (
            (B << 9 | B >> 23) & 0xFFFFFFFF,
            C,
            (F << 19 | F >> 13) & 0xFFFFFFFF,
            G,
        )
        A, B, E, F = (
            TT1,
            A,
            (TT2 ^ (TT2 << 9 | TT2 >> 23) ^ (TT2 << 17 | TT2 >> 15)) & 0xFFFFFFFF,
            E,
        )
    return (
        A ^ V[0],
        B ^ V[1],
        C ^ V[2],
        D ^ V[3],
        E ^ V[4],
        F ^ V[5],
        G ^ V[6],
        H ^ V[7],
    )


def digest(data):
    # 填充
    pad_num = 64 - (len(data) + 1 & 0x3F)
    data += b"\x80" + (len(data) << 3).to_bytes(
        pad_num if pad_num >= 8 else pad_num + 64, "big"
    )
    V, B = V0, array("L", data)
    B.byteswap()
    # 迭代压缩
    for i in range(0, len(B), 16):
        V = CF(V, B[i : i + 16])
    V = array("L", V)
    V.byteswap()
    return V.tobytes()


def sm3(message):
    message = message.encode()
    result = digest(message)
    result = result.hex()
    return result


if __name__ == "__main__":
    message = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    result = digest(message)
    result = result.hex()
    print("杂凑值:", result)
