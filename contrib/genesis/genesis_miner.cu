// TRAP genesis block miner (CUDA).
//
// Searches for a nonce so that SHA256d(header) meets the target encoded by
// nBits = 0x1d00ffff (difficulty 1). When the 32-bit nonce space is exhausted
// nTime is incremented by one and the search continues.
//
// Build (Windows, "x64 Native Tools Command Prompt for VS"):
//   nvcc -O3 -arch=sm_86 genesis_miner.cu -o genesis_miner.exe
// Build (Linux):
//   nvcc -O3 -arch=sm_86 genesis_miner.cu -o genesis_miner
//
// Usage:
//   genesis_miner --selftest          verify against Bitcoin's genesis block
//   genesis_miner <76-byte-header-hex> mine (header without the nonce)
//   genesis_miner --miner-tests <genesis-hash> <genesis-time>
//       mine the 110 blocks used by src/test/miner_tests.cpp (BLOCKINFO) on
//       top of the given mainnet genesis block and print the table
//   genesis_miner --mainnet-alt <genesis-hash> <genesis-time> <output.json>
//       mine the 2016 blocks of test/functional/data/mainnet_alt.json (used by
//       mining_mainnet.py) and write the timestamps and nonces to output.json

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <vector>

#ifndef CPU_TEST
#include <cuda_runtime.h>
#define HD __host__ __device__
#else
#define HD
#endif

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#ifndef CPU_TEST
__constant__
#endif
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#ifdef CPU_TEST
static const uint32_t* const K_HOST = K;
#else
static const uint32_t K_HOST[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
#endif

HD static inline void Compress(uint32_t s[8], const uint32_t in[16], const uint32_t* k)
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = in[i];
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
        uint32_t t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

HD static inline uint32_t Bswap(uint32_t x)
{
    return (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24);
}

HD static inline void InitState(uint32_t s[8])
{
    s[0] = 0x6a09e667; s[1] = 0xbb67ae85; s[2] = 0x3c6ef372; s[3] = 0xa54ff53a;
    s[4] = 0x510e527f; s[5] = 0x9b05688c; s[6] = 0x1f83d9ab; s[7] = 0x5be0cd19;
}

// SHA256d of the header given the midstate of its first 64 bytes and the
// big-endian words 16..18 of the header (merkle tail, nTime, nBits).
HD static inline void HashNonce(const uint32_t mid[8], const uint32_t tail[3], uint32_t nonce,
                                uint32_t out[8], const uint32_t* k)
{
    uint32_t w[16] = {tail[0], tail[1], tail[2], Bswap(nonce), 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640};
    uint32_t s[8];
    for (int i = 0; i < 8; ++i) s[i] = mid[i];
    Compress(s, w, k);
    uint32_t w2[16] = {s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 0x80000000, 0, 0, 0, 0, 0, 0, 256};
    InitState(out);
    Compress(out, w2, k);
}

// 256-bit target as eight 32-bit words, least significant first.
struct Target {
    uint32_t w[8];
};

// The hash is compared as a little-endian 256-bit number, as CheckProofOfWork does.
HD static inline bool MeetsTarget(const uint32_t h[8], const Target& t)
{
    for (int i = 7; i >= 0; --i) {
        uint32_t v = Bswap(h[i]);
        if (v != t.w[i]) return v < t.w[i];
    }
    return true;
}

static Target TargetFromBits(uint32_t bits)
{
    Target t{};
    int size = bits >> 24;
    uint32_t mantissa = bits & 0x007fffff;
    for (int i = 0; i < 3; ++i) {
        int byte = size - 3 + i; // position of mantissa byte i (little-endian)
        if (byte >= 0 && byte < 32) t.w[byte / 4] |= ((mantissa >> (8 * i)) & 0xff) << (8 * (byte % 4));
    }
    return t;
}

static const uint32_t DIFF_1_BITS = 0x1d00ffff;

#ifndef CPU_TEST
__global__ void MineKernel(const uint32_t* mid_in, const uint32_t* tail_in, uint64_t start, uint64_t count,
                           Target target, unsigned long long* found)
{
    __shared__ uint32_t k[64];
    for (int i = threadIdx.x; i < 64; i += blockDim.x) k[i] = K[i];
    __syncthreads();
    uint32_t mid[8], tail[3], h[8];
    for (int i = 0; i < 8; ++i) mid[i] = mid_in[i];
    for (int i = 0; i < 3; ++i) tail[i] = tail_in[i];
    uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
    for (uint64_t i = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x; i < count; i += stride) {
        uint32_t nonce = (uint32_t)(start + i);
        HashNonce(mid, tail, nonce, h, k);
        if (MeetsTarget(h, target)) atomicMin(found, (unsigned long long)nonce);
    }
}
#endif

static bool ParseHex(const char* hex, uint8_t* out, size_t len)
{
    if (strlen(hex) != len * 2) return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

static uint32_t ReadBE(const uint8_t* p) { return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }

static uint32_t ReadLE(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }

static void WriteLE(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

static void Prepare(const uint8_t hdr[76], uint32_t mid[8], uint32_t tail[3])
{
    uint32_t w[16];
    for (int i = 0; i < 16; ++i) w[i] = ReadBE(hdr + 4 * i);
    InitState(mid);
    Compress(mid, w, K_HOST);
    for (int i = 0; i < 3; ++i) tail[i] = ReadBE(hdr + 64 + 4 * i);
}

static void PrintHash(const uint32_t h[8])
{
    // Display order is the reversed byte string, as Bitcoin prints hashes.
    for (int i = 7; i >= 0; --i) printf("%08x", Bswap(h[i]));
}

// Plain SHA256 of an arbitrary message (host only, used for the coinbase txid).
static void Sha256(const uint8_t* data, size_t len, uint8_t out[32])
{
    uint32_t s[8];
    InitState(s);
    std::vector<uint8_t> msg(data, data + len);
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0);
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 7; i >= 0; --i) msg.push_back((uint8_t)(bits >> (8 * i)));
    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; ++i) w[i] = ReadBE(&msg[off + 4 * i]);
        Compress(s, w, K_HOST);
    }
    for (int i = 0; i < 8; ++i) {
        out[4 * i] = s[i] >> 24; out[4 * i + 1] = s[i] >> 16; out[4 * i + 2] = s[i] >> 8; out[4 * i + 3] = s[i];
    }
}

static void Sha256d(const uint8_t* data, size_t len, uint8_t out[32])
{
    uint8_t tmp[32];
    Sha256(data, len, tmp);
    Sha256(tmp, 32, out);
}

// Serialization of `CScript() << n` for a non-negative integer.
static void PushInt(std::vector<uint8_t>& script, int64_t n)
{
    if (n == 0) { script.push_back(0x00); return; }            // OP_0
    if (n >= 1 && n <= 16) { script.push_back(0x50 + n); return; } // OP_1..OP_16
    std::vector<uint8_t> num;
    while (n) { num.push_back(n & 0xff); n >>= 8; }
    if (num.back() & 0x80) num.push_back(0);
    script.push_back((uint8_t)num.size());
    script.insert(script.end(), num.begin(), num.end());
}

static void PutLE(std::vector<uint8_t>& v, uint64_t x, int bytes)
{
    for (int i = 0; i < bytes; ++i) v.push_back((uint8_t)(x >> (8 * i)));
}

// Builds the 76-byte header prefix of the block that miner_tests.cpp creates
// at `height` on top of `prev_hash` (internal byte order).
static void BuildMinerTestHeader(int height, uint32_t extranonce, const uint8_t prev_hash[32], uint32_t time,
                                 uint8_t hdr[76])
{
    std::vector<uint8_t> script_sig;
    PushInt(script_sig, height);
    PushInt(script_sig, extranonce);
    std::vector<uint8_t> tx;
    PutLE(tx, 1, 4);                          // version
    tx.push_back(1);                          // vin count
    tx.insert(tx.end(), 32, 0);               // null prevout hash
    PutLE(tx, 0xffffffff, 4);                 // null prevout index
    tx.push_back((uint8_t)script_sig.size());
    tx.insert(tx.end(), script_sig.begin(), script_sig.end());
    PutLE(tx, 0xfffffffe, 4);                 // MAX_SEQUENCE_NONFINAL
    tx.push_back(1);                          // vout count
    PutLE(tx, 50ULL * 100000000ULL, 8);       // block reward
    tx.push_back(0);                          // empty scriptPubKey
    PutLE(tx, (uint32_t)(height - 1), 4);     // nLockTime
    uint8_t merkle[32];
    Sha256d(tx.data(), tx.size(), merkle);

    std::vector<uint8_t> h;
    PutLE(h, 0x20000000, 4);                  // VERSIONBITS_TOP_BITS
    h.insert(h.end(), prev_hash, prev_hash + 32);
    h.insert(h.end(), merkle, merkle + 32);
    PutLE(h, time, 4);
    PutLE(h, 0x1d00ffff, 4);
    memcpy(hdr, h.data(), 76);
}

struct MinerTestChain {
    std::vector<uint32_t> times;
    uint8_t tip[32];

    MinerTestChain(const char* genesis_hash_hex, uint32_t genesis_time)
    {
        uint8_t be[32];
        ParseHex(genesis_hash_hex, be, 32);
        for (int i = 0; i < 32; ++i) tip[i] = be[31 - i];
        times.push_back(genesis_time);
    }

    uint32_t NextTime() const
    {
        std::vector<uint32_t> last(times.end() - std::min<size_t>(11, times.size()), times.end());
        std::sort(last.begin(), last.end());
        return last[last.size() / 2] + 1;
    }

    int NextHeight() const { return (int)times.size(); }

    // Returns true if the block with this extranonce/nonce meets the target, and
    // if so appends it to the chain.
    bool Connect(uint32_t extranonce, uint32_t nonce)
    {
        uint8_t hdr[80];
        uint32_t time = NextTime();
        BuildMinerTestHeader(NextHeight(), extranonce, tip, time, hdr);
        WriteLE(hdr + 76, nonce);
        uint8_t hash[32];
        Sha256d(hdr, 80, hash);
        uint32_t h[8];
        for (int i = 0; i < 8; ++i) h[i] = ReadBE(hash + 4 * i);
        if (!MeetsTarget(h, TargetFromBits(DIFF_1_BITS))) return false;
        memcpy(tip, hash, 32);
        times.push_back(time);
        return true;
    }
};

// Header prefix of block `height` of the alternate mainnet chain in
// mining_mainnet.py: coinbase from create_coinbase() paying to a fixed P2PKH
// script, with nLockTime 0 and a final sequence.
static void BuildMainnetAltHeader(int height, const uint8_t prev_hash[32], uint32_t time, uint32_t bits, uint8_t hdr[76])
{
    static const uint8_t SPK[25] = {0x76, 0xa9, 0x14, 0xea, 0xdb, 0xac, 0x7f, 0x36, 0xc3, 0x7e, 0x39, 0x36,
                                    0x11, 0x68, 0xb7, 0xaa, 0xee, 0x3c, 0xb2, 0x4a, 0x25, 0x31, 0x2d, 0x88, 0xac};
    std::vector<uint8_t> script_sig;
    PushInt(script_sig, height);
    if (height <= 16) script_sig.push_back(0x00); // padding to satisfy bad-cb-length
    std::vector<uint8_t> tx;
    PutLE(tx, 2, 4);                          // version
    tx.push_back(1);
    tx.insert(tx.end(), 32, 0);
    PutLE(tx, 0xffffffff, 4);
    tx.push_back((uint8_t)script_sig.size());
    tx.insert(tx.end(), script_sig.begin(), script_sig.end());
    PutLE(tx, 0xffffffff, 4);                 // SEQUENCE_FINAL
    tx.push_back(1);
    PutLE(tx, 50ULL * 100000000ULL, 8);
    tx.push_back(sizeof(SPK));
    tx.insert(tx.end(), SPK, SPK + sizeof(SPK));
    PutLE(tx, 0, 4);                          // nLockTime
    uint8_t merkle[32];
    Sha256d(tx.data(), tx.size(), merkle);

    std::vector<uint8_t> h;
    PutLE(h, 0x20000000, 4);
    h.insert(h.end(), prev_hash, prev_hash + 32);
    h.insert(h.end(), merkle, merkle + 32);
    PutLE(h, time, 4);
    PutLE(h, bits, 4);
    memcpy(hdr, h.data(), 76);
}

static const uint32_t DIFF_4_BITS = 0x1c3fffc0;

static uint32_t MainnetAltBits(int height) { return height < 2016 ? DIFF_1_BITS : DIFF_4_BITS; }

// Checks one block of the alternate mainnet chain and advances prev_hash.
static bool ConnectMainnetAlt(int height, uint8_t prev_hash[32], uint32_t time, uint32_t nonce)
{
    uint8_t hdr[80];
    BuildMainnetAltHeader(height, prev_hash, time, MainnetAltBits(height), hdr);
    WriteLE(hdr + 76, nonce);
    uint8_t hash[32];
    Sha256d(hdr, 80, hash);
    uint32_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = ReadBE(hash + 4 * i);
    if (!MeetsTarget(h, TargetFromBits(MainnetAltBits(height)))) return false;
    memcpy(prev_hash, hash, 32);
    return true;
}

static void ParseGenesisHash(const char* hex, uint8_t out[32])
{
    uint8_t be[32];
    ParseHex(hex, be, 32);
    for (int i = 0; i < 32; ++i) out[i] = be[31 - i];
}

static void PrintBlockInfo(const std::vector<std::pair<uint32_t, uint32_t>>& info)
{
    printf("} BLOCKINFO[]{");
    for (size_t i = 0; i < info.size(); ++i) {
        char cell[32];
        snprintf(cell, sizeof(cell), "{%u, %u}%s", info[i].first, info[i].second, i + 1 < info.size() ? "," : "};");
        if (i && i % 6 == 0) printf("\n              ");
        printf(i + 1 < info.size() && (i + 1) % 6 ? "%-18s" : "%s", cell);
    }
    printf("\n");
}

static const char* BTC_GENESIS_PREFIX =
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d";
static const uint32_t BTC_GENESIS_NONCE = 2083236893;
static const char* BTC_GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

#ifdef CPU_TEST
int main(int argc, char** argv)
{
    uint8_t hdr[76];
    uint32_t mid[8], tail[3], h[8];
    ParseHex(BTC_GENESIS_PREFIX, hdr, 76);
    Prepare(hdr, mid, tail);
    HashNonce(mid, tail, BTC_GENESIS_NONCE, h, K_HOST);
    printf("hash ");
    PrintHash(h);
    const Target diff1{TargetFromBits(DIFF_1_BITS)};
    printf("\nmeets target: %d, wrong nonce meets target: ", MeetsTarget(h, diff1));
    HashNonce(mid, tail, BTC_GENESIS_NONCE + 1, h, K_HOST);
    printf("%d\n", MeetsTarget(h, diff1));

    // Replay "timestamp nonce" lines of mainnet_alt.json from stdin.
    if (argc == 4 && strcmp(argv[1], "--mainnet-alt") == 0) {
        uint8_t prev[32];
        ParseGenesisHash(argv[2], prev);
        unsigned t, n, height = 0;
        while (scanf("%u %u", &t, &n) == 2) {
            ++height;
            if (!ConnectMainnetAlt(height, prev, t, n)) { printf("block %u does not meet the target\n", height); return 1; }
        }
        printf("mainnet_alt blocks valid: %u\n", height);
        return 0;
    }

    // Replay "extranonce nonce" pairs from stdin on top of the given genesis.
    if (argc == 3) {
        MinerTestChain chain(argv[1], (uint32_t)strtoul(argv[2], nullptr, 10));
        unsigned e, n, ok = 0, total = 0;
        while (scanf("%u %u", &e, &n) == 2) {
            ++total;
            if (chain.Connect(e, n)) ++ok; else { printf("block %u does not meet the target\n", total); break; }
        }
        printf("miner_tests blocks valid: %u/%u\n", ok, total);
        return ok == total ? 0 : 1;
    }
    return 0;
}
#else
#define CUDA_CHECK(x) do { cudaError_t e = (x); if (e != cudaSuccess) { \
    fprintf(stderr, "CUDA error %s at %s:%d\n", cudaGetErrorString(e), __FILE__, __LINE__); exit(1); } } while (0)

// Searches nonces [start, start+count); returns true and sets *nonce on success.
static bool Search(const uint8_t hdr[76], uint64_t start, uint64_t count, uint32_t* nonce, bool progress,
                   uint32_t bits = DIFF_1_BITS)
{
    uint32_t mid[8], tail[3];
    Prepare(hdr, mid, tail);
    uint32_t *d_mid, *d_tail;
    unsigned long long* d_found;
    CUDA_CHECK(cudaMalloc(&d_mid, sizeof(mid)));
    CUDA_CHECK(cudaMalloc(&d_tail, sizeof(tail)));
    CUDA_CHECK(cudaMalloc(&d_found, sizeof(unsigned long long)));
    CUDA_CHECK(cudaMemcpy(d_mid, mid, sizeof(mid), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_tail, tail, sizeof(tail), cudaMemcpyHostToDevice));
    unsigned long long found = ~0ULL;
    CUDA_CHECK(cudaMemcpy(d_found, &found, sizeof(found), cudaMemcpyHostToDevice));

    const uint64_t batch = 1ULL << 28;
    auto t0 = std::chrono::steady_clock::now();
    for (uint64_t done = 0; done < count && found == ~0ULL; done += batch) {
        uint64_t n = count - done < batch ? count - done : batch;
        MineKernel<<<4096, 256>>>(d_mid, d_tail, start + done, n, TargetFromBits(bits), d_found);
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaMemcpy(&found, d_found, sizeof(found), cudaMemcpyDeviceToHost));
        if (progress) {
            double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            printf("  progress %5.1f%%  %.1f MH/s\n", 100.0 * (done + n) / count, (done + n) / secs / 1e6);
            fflush(stdout);
        }
    }
    cudaFree(d_mid);
    cudaFree(d_tail);
    cudaFree(d_found);
    if (found == ~0ULL) return false;
    *nonce = (uint32_t)found;
    return true;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s --selftest | --miner-tests <genesis-hash> <genesis-time> | --mainnet-alt <genesis-hash> <genesis-time> <output.json> | <76-byte-header-hex>\n", argv[0]);
        return 1;
    }
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    printf("GPU: %s\n", prop.name);

    uint8_t hdr[76];
    if (strcmp(argv[1], "--selftest") == 0) {
        ParseHex(BTC_GENESIS_PREFIX, hdr, 76);
        uint32_t nonce;
        bool ok = Search(hdr, BTC_GENESIS_NONCE - (1u << 20), 1u << 21, &nonce, false);
        uint32_t mid[8], tail[3], h[8];
        Prepare(hdr, mid, tail);
        HashNonce(mid, tail, nonce, h, K_HOST);
        printf("selftest nonce %u hash ", nonce);
        PrintHash(h);
        printf("\nexpected nonce %u hash %s\n", BTC_GENESIS_NONCE, BTC_GENESIS_HASH);
        bool pass = ok && nonce == BTC_GENESIS_NONCE;
        printf("SELFTEST %s\n", pass ? "PASSED" : "FAILED");
        return pass ? 0 : 1;
    }

    if (strcmp(argv[1], "--mainnet-alt") == 0) {
        if (argc != 5) {
            fprintf(stderr, "usage: %s --mainnet-alt <genesis-hash> <genesis-time> <output.json>\n", argv[0]);
            return 1;
        }
        uint8_t prev[32];
        ParseGenesisHash(argv[2], prev);
        uint32_t time = (uint32_t)strtoul(argv[3], nullptr, 10);
        std::vector<uint32_t> times, nonces;
        auto t0 = std::chrono::steady_clock::now();
        for (int height = 1; height <= 2016; ++height) {
            // One second apart: keeps the chain in the past and triggers the
            // maximum difficulty increase at the first retarget.
            ++time;
            for (;; ++time) {
                uint8_t block_hdr[76];
                BuildMainnetAltHeader(height, prev, time, MainnetAltBits(height), block_hdr);
                uint32_t nonce;
                if (Search(block_hdr, 0, 1ULL << 32, &nonce, false, MainnetAltBits(height))) {
                    if (!ConnectMainnetAlt(height, prev, time, nonce)) {
                        fprintf(stderr, "internal error: found nonce does not verify\n");
                        return 1;
                    }
                    times.push_back(time);
                    nonces.push_back(nonce);
                    break;
                }
            }
            double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            printf("block %4d/2016  time %u  nonce %10u  (%.0f min elapsed, ~%.0f min left)\n", height, time,
                   nonces.back(), secs / 60, secs / 60 / height * (2016 - height));
            fflush(stdout);
        }
        FILE* f = fopen(argv[4], "w");
        if (!f) { perror(argv[4]); return 1; }
        fprintf(f, "{\n    \"timestamps\": [");
        for (size_t i = 0; i < times.size(); ++i) fprintf(f, "%s%u", i ? ", " : "", times[i]);
        fprintf(f, "],\n    \"nonces\": [");
        for (size_t i = 0; i < nonces.size(); ++i) fprintf(f, "%s%u", i ? ", " : "", nonces[i]);
        fprintf(f, "]\n}\n");
        fclose(f);
        printf("\nWrote %s\n", argv[4]);
        return 0;
    }

    if (strcmp(argv[1], "--miner-tests") == 0) {
        if (argc != 4) {
            fprintf(stderr, "usage: %s --miner-tests <genesis-hash> <genesis-time>\n", argv[0]);
            return 1;
        }
        MinerTestChain chain(argv[2], (uint32_t)strtoul(argv[3], nullptr, 10));
        std::vector<std::pair<uint32_t, uint32_t>> info;
        auto t0 = std::chrono::steady_clock::now();
        while (info.size() < 110) {
            for (uint32_t extranonce = 0;; extranonce += 100) {
                uint8_t block_hdr[76];
                BuildMinerTestHeader(chain.NextHeight(), extranonce, chain.tip, chain.NextTime(), block_hdr);
                uint32_t nonce;
                if (Search(block_hdr, 0, 1ULL << 32, &nonce, false)) {
                    if (!chain.Connect(extranonce, nonce)) {
                        fprintf(stderr, "internal error: found nonce does not verify\n");
                        return 1;
                    }
                    info.emplace_back(extranonce, nonce);
                    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                    printf("block %3zu/110  extranonce %4u  nonce %10u  (%.0fs elapsed)\n", info.size(), extranonce, nonce, secs);
                    fflush(stdout);
                    break;
                }
            }
        }
        printf("\nReplace BLOCKINFO in src/test/miner_tests.cpp with:\n\n");
        PrintBlockInfo(info);
        return 0;
    }

    if (argc != 2) {
        fprintf(stderr, "usage: %s --selftest | <76-byte-header-hex>\n", argv[0]);
        return 1;
    }
    if (!ParseHex(argv[1], hdr, 76)) {
        fprintf(stderr, "header must be exactly 152 hex characters\n");
        return 1;
    }
    for (;;) {
        uint32_t time = ReadLE(hdr + 68);
        printf("mining nTime=%u\n", time);
        uint32_t nonce;
        if (Search(hdr, 0, 1ULL << 32, &nonce, true)) {
            uint32_t mid[8], tail[3], h[8];
            Prepare(hdr, mid, tail);
            HashNonce(mid, tail, nonce, h, K_HOST);
            printf("FOUND time %u nonce %u hash ", time, nonce);
            PrintHash(h);
            printf("\n");
            return 0;
        }
        WriteLE(hdr + 68, time + 1);
    }
}
#endif
