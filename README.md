#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <stdint.h>
#include <windows.h>

using namespace std;

// ============================================================================
// 1. IMPLEMENTAÇÃO NATIVA DO SHA-256
// ============================================================================
class SHA256 {
private:
    vector<uint32_t> state;
    uint64_t bitlen;
    vector<uint8_t> data;
    uint32_t datalen;

    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform() {
        static const uint32_t k_arr[] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        vector<uint32_t> m(64, 0);
        for (int i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | (uint32_t)data[j + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
            uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k_arr[i] + m[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

public:
    SHA256() : state(8, 0), bitlen(0), data(64, 0), datalen(0) {}

    static vector<uint8_t> hash(const vector<uint8_t>& input) {
        SHA256 ctx;
        ctx.state[0] = 0x6a09e667; ctx.state[1] = 0xbb67ae85;
        ctx.state[2] = 0x3c6ef372; ctx.state[3] = 0xa54ff53a;
        ctx.state[4] = 0x510e527f; ctx.state[5] = 0x9b05688c;
        ctx.state[6] = 0x1f83d9ab; ctx.state[7] = 0x5be0cd19;

        for (size_t i = 0; i < input.size(); ++i) {
            ctx.data[ctx.datalen++] = input[i];
            if (ctx.datalen == 64) {
                ctx.transform();
                ctx.bitlen += 512;
                ctx.datalen = 0;
            }
        }

        uint32_t i = ctx.datalen;
        if (ctx.datalen < 56) {
            ctx.data[i++] = 0x80;
            while (i < 56) ctx.data[i++] = 0x00;
        } else {
            ctx.data[i++] = 0x80;
            while (i < 64) ctx.data[i++] = 0x00;
            ctx.transform();
            for (int j = 0; j < 56; ++j) ctx.data[j] = 0x00;
        }

        ctx.bitlen += ctx.datalen * 8;
        for (int j = 0; j < 8; ++j) {
            ctx.data[63 - j] = (ctx.bitlen >> (j * 8)) & 0xff;
        }
        ctx.transform();

        vector<uint8_t> digest(32);
        for (int j = 0; j < 4; ++j) {
            for (int k = 0; k < 8; ++k) {
                digest[k * 4 + j] = (ctx.state[k] >> (24 - j * 8)) & 0xff;
            }
        }
        return digest;
    }
};

// ============================================================================
// 2. IMPLEMENTAÇÃO NATIVA DO RIPEMD-160
// ============================================================================
class RIPEMD160 {
private:
    static inline uint32_t rol(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t f(int j, uint32_t x, uint32_t y, uint32_t z) {
        if (j < 16) return x ^ y ^ z;
        if (j < 32) return (x & y) | (~x & z);
        if (j < 48) return (x | ~y) ^ z;
        if (j < 64) return (x & z) | (y & ~z);
        return x ^ (y | ~z);
    }

    static inline uint32_t K(int j) {
        if (j < 16) return 0x00000000;
        if (j < 32) return 0x5A827999;
        if (j < 48) return 0x6ED9EBA1;
        if (j < 64) return 0x8F1BBCDC;
        return 0xA953FD4E;
    }

    static inline uint32_t Kp(int j) {
        if (j < 16) return 0x50A28BE6;
        if (j < 32) return 0x5C4DD124;
        if (j < 48) return 0x6D703EF3;
        if (j < 64) return 0x7A6D76E9;
        return 0x00000000;
    }

public:
    static vector<uint8_t> hash(const vector<uint8_t>& input) {
        static const int r[] = {
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
            7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
            3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
            1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
            4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
        };
        static const int rp[] = {
            5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
            6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
            15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
            8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
            12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
        };
        static const int s[] = {
            11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
            7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
            11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
            11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
            9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
        };
        static const int sp[] = {
            8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
            9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
            9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
            15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
            8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
        };

        vector<uint8_t> msg = input;
        uint64_t bitlen = (uint64_t)msg.size() * 8;
        msg.push_back(0x80);
        while ((msg.size() % 64) != 56) msg.push_back(0x00);
        for (int i = 0; i < 8; i++) msg.push_back((bitlen >> (i * 8)) & 0xFF);

        uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

        for (size_t offset = 0; offset < msg.size(); offset += 64) {
            vector<uint32_t> X(16, 0);
            for (int i = 0; i < 16; i++) {
                X[i] = (uint32_t)msg[offset + i * 4] |
                       ((uint32_t)msg[offset + i * 4 + 1] << 8) |
                       ((uint32_t)msg[offset + i * 4 + 2] << 16) |
                       ((uint32_t)msg[offset + i * 4 + 3] << 24);
            }

            uint32_t al = h0, bl = h1, cl = h2, dl = h3, el = h4;
            uint32_t ar = h0, br = h1, cr = h2, dr = h3, er = h4;

            for (int j = 0; j < 80; j++) {
                uint32_t t = rol(al + f(j, bl, cl, dl) + X[r[j]] + K(j), s[j]) + el;
                al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;

                t = rol(ar + f(79 - j, br, cr, dr) + X[rp[j]] + Kp(j), sp[j]) + er;
                ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
            }

            uint32_t t = h1 + cl + dr;
            h1 = h2 + dl + er;
            h2 = h3 + el + ar;
            h3 = h4 + al + br;
            h4 = h0 + bl + cr;
            h0 = t;
        }

        vector<uint8_t> out(20);
        uint32_t h[] = {h0, h1, h2, h3, h4};
        for (int i = 0; i < 5; i++) {
            out[i * 4] = h[i] & 0xFF;
            out[i * 4 + 1] = (h[i] >> 8) & 0xFF;
            out[i * 4 + 2] = (h[i] >> 16) & 0xFF;
            out[i * 4 + 3] = (h[i] >> 24) & 0xFF;
        }
        return out;
    }
};

// ============================================================================
// 3. MATEMÁTICA DE CURVA ELÍPTICA SECP256K1 (256-bit BigInt Modular)
// ============================================================================
struct uint256_t {
    vector<uint32_t> d;

    uint256_t() : d(8, 0) {}
    
    static uint256_t fromBytes(const vector<uint8_t>& b) {
        uint256_t res;
        for (int i = 0; i < 8; i++) {
            res.d[7 - i] = ((uint32_t)b[i * 4] << 24) |
                           ((uint32_t)b[i * 4 + 1] << 16) |
                           ((uint32_t)b[i * 4 + 2] << 8) |
                           ((uint32_t)b[i * 4 + 3]);
        }
        return res;
    }

    vector<uint8_t> toBytes() const {
        vector<uint8_t> b(32);
        for (int i = 0; i < 8; i++) {
            uint32_t val = d[7 - i];
            b[i * 4] = (val >> 24) & 0xFF;
            b[i * 4 + 1] = (val >> 16) & 0xFF;
            b[i * 4 + 2] = (val >> 8) & 0xFF;
            b[i * 4 + 3] = val & 0xFF;
        }
        return b;
    }

    bool isZero() const {
        for (int i = 0; i < 8; i++) if (d[i] != 0) return false;
        return true;
    }

    bool getBit(int bit) const {
        return (d[bit / 32] >> (bit % 32)) & 1;
    }
};

uint256_t getSecp256k1P() {
    uint256_t p;
    p.d[0] = 0xFFFFFC2F; p.d[1] = 0xFFFFFFFE;
    for (int i = 2; i < 8; i++) p.d[i] = 0xFFFFFFFF;
    return p;
}

int cmp256(const uint256_t& a, const uint256_t& b) {
    for (int i = 7; i >= 0; i--) {
if (a.d[i] > b.d[i]) return 1;
if (a.d[i] < b.d[i]) return -1;
}
return 0;
}
uint256_t sub256(const uint256_t& a, const uint256_t& b) {
uint256_t res;
uint64_t borrow = 0;
for (int i = 0; i < 8; i++) {
uint64_t diff = (uint64_t)a.d[i] - b.d[i] - borrow;
res.d[i] = (uint32_t)diff;
borrow = (diff >> 63) & 1;
}
return res;
}
uint256_t addModP(const uint256_t& a, const uint256_t& b) {
uint256_t res, P = getSecp256k1P();
uint64_t carry = 0;
for (int i = 0; i < 8; i++) {
uint64_t sum = (uint64_t)a.d[i] + b.d[i] + carry;
res.d[i] = (uint32_t)sum;
carry = sum >> 32;
}
if (carry || cmp256(res, P) >= 0) res = sub256(res, P);
return res;
}
uint256_t subModP(const uint256_t& a, const uint256_t& b) {
uint256_t P = getSecp256k1P();
if (cmp256(a, b) >= 0) return sub256(a, b);
uint256_t diff = sub256(b, a);
return sub256(P, diff);
}
uint256_t mulModP(const uint256_t& a, const uint256_t& b) {
vector<uint32_t> prod(16, 0);
for (int i = 0; i < 8; i++) {
uint64_t carry = 0;
for (int j = 0; j < 8; j++) {
uint64_t uv = (uint64_t)a.d[i] * b.d[j] + prod[i + j] + carry;
prod[i + j] = (uint32_t)uv;
carry = uv >> 32;
}
prod[i + 8] = (uint32_t)carry;
}
uint64_t c = 0;
vector<uint32_t> r(10, 0);
for (int i = 0; i < 8; i++) r[i] = prod[i];
for (int i = 0; i < 8; i++) {
uint64_t hi = prod[i + 8];
uint64_t v = r[i] + hi * 977ULL + c;
r[i] = (uint32_t)v;
c = v >> 32;
}
r[8] = (uint32_t)c;
c = 0;
for (int i = 0; i < 8; i++) {
uint64_t hi = prod[i + 8];
uint64_t v = (uint64_t)r[i + 1] + hi + c;
r[i + 1] = (uint32_t)v;
c = v >> 32;
}
r[9] = (uint32_t)c;
while (r[8] != 0 || r[9] != 0) {
uint64_t hi0 = r[8], hi1 = r[9];
r[8] = 0; r[9] = 0;
uint64_t carry = 0;
uint64_t v0 = r[0] + hi0 * 977ULL; r[0] = (uint32_t)v0; carry = v0 >> 32;
uint64_t v1 = r[1] + hi0 + hi1 * 977ULL + carry; r[1] = (uint32_t)v1; carry = v1 >> 32;
uint64_t v2 = r[2] + hi1 + carry; r[2] = (uint32_t)v2; carry = v2 >> 32;
for (int i = 3; i < 8 && carry; i++) {
uint64_t vi = r[i] + carry;
r[i] = (uint32_t)vi;
carry = vi >> 32;
}
r[8] = (uint32_t)carry;
}
uint256_t res, P = getSecp256k1P();
for (int i = 0; i < 8; i++) res.d[i] = r[i];
if (cmp256(res, P) >= 0) res = sub256(res, P);
return res;
}
uint256_t invModP(const uint256_t& a) {
uint256_t P = getSecp256k1P();
uint256_t two; two.d[0] = 2;
uint256_t exp = sub256(P, two);
uint256_t res; res.d[0] = 1;
uint256_t base = a;
for (int i = 0; i < 256; i++) {
if (exp.getBit(i)) res = mulModP(res, base);
base = mulModP(base, base);
}
return res;
}
struct Point {
uint256_t x, y;
bool inf;
Point() : inf(true) {}
};
Point pointDouble(const Point& p) {
if (p.inf || p.y.isZero()) return Point();
uint256_t x2 = mulModP(p.x, p.x);
uint256_t num = addModP(addModP(x2, x2), x2);
uint256_t den = addModP(p.y, p.y);
uint256_t lambda = mulModP(num, invModP(den));
Point r; r.inf = false;
uint256_t l2 = mulModP(lambda, lambda);
r.x = subModP(subModP(l2, p.x), p.x);
r.y = subModP(mulModP(lambda, subModP(p.x, r.x)), p.y);
return r;
}
Point pointAdd(const Point& p1, const Point& p2) {
if (p1.inf) return p2;
if (p2.inf) return p1;
if (cmp256(p1.x, p2.x) == 0) {
if (cmp256(p1.y, p2.y) == 0) return pointDouble(p1);
return Point();
}
uint256_t num = subModP(p2.y, p1.y);
uint256_t den = subModP(p2.x, p1.x);
uint256_t lambda = mulModP(num, invModP(den));
Point r; r.inf = false;
uint256_t l2 = mulModP(lambda, lambda);
r.x = subModP(subModP(l2, p1.x), p2.x);
r.y = subModP(mulModP(lambda, subModP(p1.x, r.x)), p1.y);
return r;
}
Point derivePublicKeyPoint(const vector<uint8_t>& privBytes) {
Point G; G.inf = false;
uint32_t gx[] = {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E};
uint32_t gy[] = {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77};
for (int i = 0; i < 8; i++) {
G.x.d[i] = gx[i];
G.y.d[i] = gy[i];
}
uint256_t k = uint256_t::fromBytes(privBytes);
Point R;
Point Q = G;
for (int i = 0; i < 256; i++) {
if (k.getBit(i)) R = pointAdd(R, Q);
Q = pointDouble(Q);
}
return R;
}
// ============================================================================
// 4. CODIFICAÇÃO BASE58 E FUNÇÕES BITCOIN
// ============================================================================
const string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
string encodeBase58(const vector<uint8_t>& data) {
vector<uint8_t> digits((data.size() * 138 / 100) + 1, 0);
size_t digitslen = 1;
for (size_t i = 0; i < data.size(); i++) {
uint32_t carry = data[i];
for (size_t j = 0; j < digitslen; j++) {
carry += (uint32_t)(digits[j]) << 8;
digits[j] = carry % 58;
carry /= 58;
}
while (carry > 0) {
digits[digitslen++] = carry % 58;
carry /= 58;
}
}
string result = "";
for (size_t i = 0; i < data.size() && data[i] == 0; i++) result += '1';
for (size_t i = 0; i < digitslen; i++) result += BASE58_ALPHABET[digits[digitslen - 1 - i]];
return result;
}
vector<uint8_t> decodeBase58(const string& str) {
vector<uint8_t> result(37, 0);
for (size_t i = 0; i < str.length(); i++) {
size_t val = BASE58_ALPHABET.find(str[i]);
if (val == string::npos) return vector<uint8_t>();
uint32_t carry = val;
for (int j = 36; j >= 0; j--) {
carry += 58 * result[j];
result[j] = carry % 256;
carry /= 256;
}
}
return result;
}
vector<uint8_t> hexToBytes(const string& hex) {
vector<uint8_t> bytes;
for (size_t i = 0; i < hex.length(); i += 2) {
string byteString = hex.substr(i, 2);
bytes.push_back((uint8_t)strtol(byteString.c_str(), NULL, 16));
}
return bytes;
}
string bytesToHex(const vector<uint8_t>& bytes) {
stringstream ss;
ss << hex << uppercase << setfill('0');
for (size_t i = 0; i < bytes.size(); i++) ss << setw(2) << (int)bytes[i];
return ss.str();
}
// Gera 32 bytes combinando relógio de alta precisão do Windows e SHA-256 (Zero libs externas)
vector<uint8_t> gerarChaveAleatoria() {
vector<uint8_t> seed;
LARGE_INTEGER perfCount;
QueryPerformanceCounter(&perfCount);
DWORD tick = GetTickCount();
DWORD pid = GetCurrentProcessId();
srand((unsigned int)(time(NULL) ^ perfCount.LowPart ^ tick ^ pid));
for (int i = 0; i < 64; i++) {
seed.push_back((uint8_t)(rand() & 0xFF));
seed.push_back((uint8_t)((perfCount.QuadPart >> (i % 8)) & 0xFF));
}
return SHA256::hash(seed);
}
string gerarWIF51(const vector<uint8_t>& keyBytes) {
vector<uint8_t> payload;
payload.push_back(0x80);
payload.insert(payload.end(), keyBytes.begin(), keyBytes.end());
vector<uint8_t> hash2 = SHA256::hash(SHA256::hash(payload));
payload.insert(payload.end(), hash2.begin(), hash2.begin() + 4);
return encodeBase58(payload);
}
string gerarEnderecoLegacy(const vector<uint8_t>& keyBytes) {
Point pub = derivePublicKeyPoint(keyBytes);
vector<uint8_t> xBytes = pub.x.toBytes();
vector<uint8_t> yBytes = pub.y.toBytes();
vector<uint8_t> pubKeyUncompressed;
pubKeyUncompressed.push_back(0x04);
pubKeyUncompressed.insert(pubKeyUncompressed.end(), xBytes.begin(), xBytes.end());
pubKeyUncompressed.insert(pubKeyUncompressed.end(), yBytes.begin(), yBytes.end());
vector<uint8_t> sha = SHA256::hash(pubKeyUncompressed);
vector<uint8_t> hash160 = RIPEMD160::hash(sha);
vector<uint8_t> addrPayload;
addrPayload.push_back(0x00);
addrPayload.insert(addrPayload.end(), hash160.begin(), hash160.end());
vector<uint8_t> checksum = SHA256::hash(SHA256::hash(addrPayload));
addrPayload.insert(addrPayload.end(), checksum.begin(), checksum.begin() + 4);
return encodeBase58(addrPayload);
}
bool reverterWIF51(const string& wif, vector<uint8_t>& outPrivBytes, string& erroMsg) {
if (wif.length() != 51 || wif[0] != '5') {
erroMsg = "A WIF nao comprimida deve ter exatamente 51 caracteres e comecar com '5'.";
return false;
}
vector<uint8_t> decoded = decodeBase58(wif);
if (decoded.size() != 37 || decoded[0] != 0x80) {
erroMsg = "Caracteres Base58 invalidos ou prefixo incorreto.";
return false;
}
vector<uint8_t> payload(decoded.begin(), decoded.begin() + 33);
vector<uint8_t> checksum(decoded.begin() + 33, decoded.end());
vector<uint8_t> hash2 = SHA256::hash(SHA256::hash(payload));
for (int i = 0; i < 4; i++) {
if (hash2[i] != checksum[i]) {
erroMsg = "Checksum invalido! A chave foi digitada errada ou esta corrompida.";
return false;
}
}
outPrivBytes.assign(payload.begin() + 1, payload.end());
return true;
}
// ============================================================================
// 5. FUNÇÃO PASSO A PASSO DETALHADO (k, P, Gx, Gy, Qx, Qy, Endereço)
// ============================================================================
void mostrarPassoAPasso(const string& wif) {
vector<uint8_t> privBytes;
string erro;
if (!reverterWIF51(wif, privBytes, erro)) {
cout << "Erro: " << erro << endl;
return;
}
cout << "\n=======================================================" << endl;
cout << " PASSO 1: DA CHAVE WIF PARA O ESCALAR PRIVADO (k)" << endl;
cout << "=======================================================" << endl;
cout << "WIF Entrada : " << wif << endl;
cout << "Valor k Hex : " << bytesToHex(privBytes) << endl;
cout << "\n=======================================================" << endl;
cout << " PASSO 2: O MODULO PRIMO DA CURVA (P)" << endl;
cout << "=======================================================" << endl;
uint256_t P = getSecp256k1P();
cout << "Valor P Hex : " << bytesToHex(P.toBytes()) << endl;
cout << "\n=======================================================" << endl;
cout << " PASSO 3: O PONTO GERADOR FIXO (G = Gx, Gy)" << endl;
cout << "=======================================================" << endl;
cout << "Valor Gx Hex: 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" << endl;
cout << "Valor Gy Hex: 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8" << endl;
cout << "\n=======================================================" << endl;
cout << " PASSO 4: CALCULO DA CURVA ELIPTICA (Q = k * G)" << endl;
cout << "=======================================================" << endl;
Point Q = derivePublicKeyPoint(privBytes);
string qxHex = bytesToHex(Q.x.toBytes());
string qyHex = bytesToHex(Q.y.toBytes());
cout << "Result. Qx  : " << qxHex << endl;
cout << "Result. Qy  : " << qyHex << endl;
cout << "\n=======================================================" << endl;
cout << " PASSO 5: CHAVE PUBLICA E ENDERECO BITCOIN FINAL" << endl;
cout << "=======================================================" << endl;
cout << "PubKey (04+Qx+Qy): 04" << qxHex << qyHex << endl;
cout << "Endereco Bitcoin : " << gerarEnderecoLegacy(privBytes) << endl;
}
// ============================================================================
// 6. MENU PRINCIPAL
// ============================================================================
int main() {
int opcao = -1;
while (opcao != 0) {
cout << "\n=======================================================" << endl;
cout << "     GERADOR E ENGENHARIA REVERSA BITCOIN (WIF 51)     " << endl;
cout << "=======================================================" << endl;
cout << "1 - Gerar NOVA carteira aleatoria + Passo a Passo" << endl;
cout << "2 - Converter Chave HEX (64 chars) -> WIF 51 + Passo a Passo" << endl;
cout << "3 - Engenharia Reversa WIF 51 -> Passo a Passo Completo" << endl;
cout << "0 - Sair" << endl;
cout << "-------------------------------------------------------" << endl;
cout << "Escolha uma opcao: ";
if (!(cin >> opcao)) {
cin.clear();
cin.ignore(10000, '\n');
continue;
}
if (opcao == 1) {
vector<uint8_t> privBytes = gerarChaveAleatoria();
string wifKey = gerarWIF51(privBytes);
mostrarPassoAPasso(wifKey);
}
else if (opcao == 2) {
string hexInput;
cout << "\nDigite a chave privada HEX (64 caracteres): ";
cin >> hexInput;
if (hexInput.length() != 64) {
cout << "Erro: A chave HEX precisa ter exatamente 64 caracteres!" << endl;
} else {
vector<uint8_t> privBytes = hexToBytes(hexInput);
string wifKey = gerarWIF51(privBytes);
mostrarPassoAPasso(wifKey);
}
}
else if (opcao == 3) {
string wifInput;
cout << "\nDigite a chave WIF (51 caracteres): ";
cin >> wifInput;
mostrarPassoAPasso(wifInput);
}
}
return 0;
}
