/*
 * rp2350-miner.c - Stratum solo miner for the RP2350 (Pico SDK), TRAP edition
 *
 * Copyright (c) 2026 The Trap Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * One file with three layers:
 *
 *   transport   YOUR CODE: Wi-Fi and the TCP connection to ckpool. Implement
 *               stratum_transport_send() and hand received bytes to
 *               stratum_receive(). Nothing else is needed from you.
 *   stratum     mining.subscribe / authorize / submit, parsing of
 *               mining.notify / set_difficulty / responses, extranonce2 and
 *               nonce bookkeeping.
 *   miner       header assembly and SHA-256d scanning.
 *
 * ---------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------------
 *
 *   POOL_USER   Your TRAP address, a dot and a worker name. ckpool runs in solo
 *               mode, so block rewards are paid to this address: ckpool puts it
 *               in the coinbase it sends to the miner. Use an address from a
 *               wallet you control (trapcoin-qt: Receive -> Create new address).
 *   POOL_PASS   Ignored by ckpool; any string.
 *
 * ---------------------------------------------------------------------------
 * Wiring it to your network code
 * ---------------------------------------------------------------------------
 *
 *   void stratum_transport_send(const char *line)
 *       You implement this: write the line (it already ends with '\n') to the
 *       TCP connection.
 *
 *   stratum_begin()             call after every (re)connect; it starts a new
 *                               session (subscribe + authorize).
 *   stratum_receive(data, len)  call with every chunk of received bytes, from
 *                               your main loop (not from an interrupt or lwIP
 *                               callback: copy the data out there first).
 *   stratum_mine(n)             call repeatedly from the main loop; it hashes up
 *                               to n nonces and submits any share it finds.
 *                               Keep n small (e.g. 8192) so the network code
 *                               can run in between.
 *
 *   Example main loop:
 *
 *       tcp_connect_to("156.238.237.84", 3333);     // your code
 *       stratum_begin();
 *       for (;;) {
 *           your_network_poll();                     // calls stratum_receive()
 *           stratum_mine(8192);
 *       }
 *
 * Messages exchanged with ckpool (one JSON object per line):
 *
 *   -> {"id":1,"method":"mining.subscribe","params":["rp2350-miner/1.0"]}
 *   <- {"id":1,"result":[[...],"<extranonce1>",<extranonce2_size>],"error":null}
 *   -> {"id":2,"method":"mining.authorize","params":["<POOL_USER>","<POOL_PASS>"]}
 *   <- {"id":2,"result":true,"error":null}
 *   <- {"id":null,"method":"mining.set_difficulty","params":[1]}
 *   <- {"id":null,"method":"mining.notify","params":["<job_id>","<prevhash>",
 *        "<coinb1>","<coinb2>",["<merkle>",...],"<version>","<nbits>","<ntime>",true]}
 *   -> {"id":3,"method":"mining.submit","params":["<POOL_USER>","<job_id>",
 *        "<extranonce2>","<ntime>","<nonce>"]}
 *   <- {"id":3,"result":true,"error":null}
 *
 * Mining TRAP with ckpool: set the pool's share difficulty to 1 (mindiff,
 * startdiff and maxdiff in ckpool.conf, see doc/trap-deploy.md). While the
 * network difficulty is also 1, every share is a block. Do not use
 * mining.configure / version-rolling; this miner keeps the job's version.
 *
 * Expected speed: a software SHA-256d on one Cortex-M33 core runs at tens of
 * kH/s, so at difficulty 1 (about 4.3e9 hashes) one RP2350 finds a share about
 * once a day. miner_scan() is reentrant: to use both cores, run it on core 1
 * too (multicore_launch_core1) over a disjoint nonce range.
 *
 * ---------------------------------------------------------------------------
 * Build (Pico SDK 2.x, board pico2 or pico2_w)
 * ---------------------------------------------------------------------------
 *
 * Put this file in a directory together with pico_sdk_import.cmake (from
 * $PICO_SDK_PATH/external) and this CMakeLists.txt:
 *
 *     cmake_minimum_required(VERSION 3.13)
 *     include(pico_sdk_import.cmake)
 *     project(rp2350_miner C CXX ASM)
 *     pico_sdk_init()
 *     add_executable(rp2350_miner rp2350-miner.c)
 *     target_compile_options(rp2350_miner PRIVATE -O3)
 *     target_link_libraries(rp2350_miner pico_stdlib)
 *     pico_enable_stdio_usb(rp2350_miner 1)
 *     pico_add_extra_outputs(rp2350_miner)
 *
 *     mkdir build && cd build
 *     cmake -DPICO_BOARD=pico2 ..        # or pico2_w, and add your Wi-Fi libs
 *     make
 *
 * The demo main() at the end needs no network: it runs self-tests against the
 * TRAP genesis block, replays a recorded ckpool session through the Stratum
 * layer (printing the lines that would be sent) and prints the hash rate.
 * Replace main() and stratum_transport_send() with your own.
 *
 * The same file also builds on a PC: gcc -O2 -DMINER_HOST_TEST rp2350-miner.c
 */

/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

#ifndef POOL_USER
#define POOL_USER "trap1qREPLACE_WITH_YOUR_TRAP_ADDRESS.rp2350"
#endif
#ifndef POOL_PASS
#define POOL_PASS "x"
#endif
#define MINER_AGENT "rp2350-miner/1.0"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef MINER_HOST_TEST
#include <time.h>
#define MINER_HOT(name) name
#else
#include "pico/stdlib.h"
#include "pico/time.h"
/* Run the hash loop from SRAM so its speed does not depend on the XIP cache. */
#define MINER_HOT(name) __not_in_flash_func(name)
#endif

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

/* Strings from mining.notify / mining.subscribe, exactly as received. */
typedef struct {
    const char *prevhash;             /* notify params[1], Stratum word order */
    const char *coinb1;               /* notify params[2] */
    const char *coinb2;               /* notify params[3] */
    const char *const *merkle_branch; /* notify params[4] */
    int merkle_count;
    const char *version;              /* notify params[5], big-endian hex */
    const char *nbits;                /* notify params[6], big-endian hex */
    const char *ntime;                /* notify params[7], big-endian hex */
    const char *extranonce1;          /* mining.subscribe result[1] */
} stratum_job_t;

/* Precomputed state for scanning one header. */
typedef struct {
    uint32_t midstate[8]; /* SHA-256 state after header bytes 0..63 */
    uint32_t tail[3];     /* header bytes 64..75 as big-endian words */
    uint64_t target_top;  /* upper 64 bits of the share target */
} miner_work_t;

int miner_prepare(miner_work_t *work, const stratum_job_t *job,
                  const uint8_t *extranonce2, size_t extranonce2_len, double share_difficulty);
bool miner_scan(const miner_work_t *work, uint32_t start, uint32_t count, uint32_t *nonce_out);
void miner_block_hash(const miner_work_t *work, uint32_t nonce, char out_hex[65]);
void miner_nonce_hex(uint32_t nonce, char out[9]);
void miner_hex(const uint8_t *data, size_t len, char *out);

/* ------------------------------------------------------------------------- */
/* SHA-256                                                                   */
/* ------------------------------------------------------------------------- */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static const uint32_t SHA256_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* One compression of a 16-word block; the message schedule is kept in a
 * rolling 16-word window to save stack and memory traffic. */
static void MINER_HOT(sha256_compress)(uint32_t s[8], const uint32_t block[16])
{
    uint32_t w[16];
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];

    for (int i = 0; i < 64; i++) {
        uint32_t wi;
        if (i < 16) {
            wi = w[i] = block[i];
        } else {
            uint32_t w15 = w[(i + 1) & 15], w2 = w[(i + 14) & 15];
            uint32_t s0 = ROTR(w15, 7) ^ ROTR(w15, 18) ^ (w15 >> 3);
            uint32_t s1 = ROTR(w2, 17) ^ ROTR(w2, 19) ^ (w2 >> 10);
            wi = w[i & 15] = w[i & 15] + s0 + w[(i + 9) & 15] + s1;
        }
        uint32_t t1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + wi;
        uint32_t t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void write_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t bswap32(uint32_t x)
{
    return (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24);
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t s[8], block[16];
    uint8_t tail[128];
    size_t full = len / 64, rest = len % 64, tail_len;

    memcpy(s, SHA256_IV, sizeof(s));
    for (size_t i = 0; i < full; i++) {
        for (int j = 0; j < 16; j++) block[j] = read_be32(data + 64 * i + 4 * j);
        sha256_compress(s, block);
    }
    memset(tail, 0, sizeof(tail));
    memcpy(tail, data + 64 * full, rest);
    tail[rest] = 0x80;
    tail_len = rest < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) tail[tail_len - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < tail_len; off += 64) {
        for (int j = 0; j < 16; j++) block[j] = read_be32(tail + off + 4 * j);
        sha256_compress(s, block);
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s[i] >> 24); out[4 * i + 1] = (uint8_t)(s[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s[i] >> 8); out[4 * i + 3] = (uint8_t)s[i];
    }
}

static void sha256d(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint8_t first[32];
    sha256(data, len, first);
    sha256(first, 32, out);
}

/* ------------------------------------------------------------------------- */
/* Hex helpers                                                               */
/* ------------------------------------------------------------------------- */

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Returns the number of bytes decoded, or -1 on malformed input. */
static int hex_decode(const char *hex, uint8_t *out, size_t max)
{
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_value(hex[2 * i]), lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return (int)(n / 2);
}

static int hex_u32(const char *hex, uint32_t *out)
{
    uint8_t b[4];
    if (hex_decode(hex, b, sizeof(b)) != 4) return -1;
    *out = read_be32(b);
    return 0;
}

void miner_hex(const uint8_t *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 15];
    }
    out[2 * len] = '\0';
}

/* ckpool (like other Stratum pools) expects the nonce as the big-endian hex of
 * its value, although the header stores it little-endian. */
void miner_nonce_hex(uint32_t nonce, char out[9])
{
    uint8_t b[4] = {(uint8_t)(nonce >> 24), (uint8_t)(nonce >> 16), (uint8_t)(nonce >> 8), (uint8_t)nonce};
    miner_hex(b, 4, out);
}

/* ------------------------------------------------------------------------- */
/* Work preparation                                                          */
/* ------------------------------------------------------------------------- */

#define MAX_COINBASE 1024
#define MAX_MERKLE 32

/* Builds the 80-byte header without the nonce from a Stratum job. */
static int build_header(uint8_t header[80], const stratum_job_t *job,
                        const uint8_t *extranonce2, size_t extranonce2_len)
{
    static uint8_t coinbase[MAX_COINBASE];
    uint8_t prev[32], branch[32], node[64];
    uint32_t version, nbits, ntime;
    int n1, n2, e1;
    size_t len;

    if (job->merkle_count < 0 || job->merkle_count > MAX_MERKLE) return -1;
    if (hex_u32(job->version, &version) || hex_u32(job->nbits, &nbits) || hex_u32(job->ntime, &ntime)) return -1;
    if (hex_decode(job->prevhash, prev, sizeof(prev)) != 32) return -1;

    /* coinbase = coinb1 || extranonce1 || extranonce2 || coinb2 */
    n1 = hex_decode(job->coinb1, coinbase, MAX_COINBASE);
    if (n1 < 0) return -1;
    e1 = hex_decode(job->extranonce1, coinbase + n1, MAX_COINBASE - n1);
    if (e1 < 0) return -1;
    len = (size_t)(n1 + e1);
    if (len + extranonce2_len > MAX_COINBASE) return -1;
    memcpy(coinbase + len, extranonce2, extranonce2_len);
    len += extranonce2_len;
    n2 = hex_decode(job->coinb2, coinbase + len, MAX_COINBASE - len);
    if (n2 < 0) return -1;
    len += (size_t)n2;

    /* merkle root = fold the coinbase txid with the branch hashes */
    sha256d(coinbase, len, node);
    for (int i = 0; i < job->merkle_count; i++) {
        if (hex_decode(job->merkle_branch[i], branch, sizeof(branch)) != 32) return -1;
        memcpy(node + 32, branch, 32);
        sha256d(node, 64, node);
    }

    write_le32(header, version);
    /* Stratum sends the previous block hash with each 4-byte word reversed. */
    for (int i = 0; i < 8; i++) {
        header[4 + 4 * i + 0] = prev[4 * i + 3];
        header[4 + 4 * i + 1] = prev[4 * i + 2];
        header[4 + 4 * i + 2] = prev[4 * i + 1];
        header[4 + 4 * i + 3] = prev[4 * i + 0];
    }
    memcpy(header + 36, node, 32);
    write_le32(header + 68, ntime);
    write_le32(header + 72, nbits);
    write_le32(header + 76, 0);
    return 0;
}

int miner_prepare(miner_work_t *work, const stratum_job_t *job,
                  const uint8_t *extranonce2, size_t extranonce2_len, double share_difficulty)
{
    uint8_t header[80];
    uint32_t block[16];

    if (share_difficulty <= 0) return -1;
    if (build_header(header, job, extranonce2, extranonce2_len)) return -1;

    memcpy(work->midstate, SHA256_IV, sizeof(work->midstate));
    for (int i = 0; i < 16; i++) block[i] = read_be32(header + 4 * i);
    sha256_compress(work->midstate, block);
    for (int i = 0; i < 3; i++) work->tail[i] = read_be32(header + 64 + 4 * i);

    /* A share needs hash <= 0xffff * 2^208 / difficulty. Only the upper 64
     * bits are compared; the pool checks the share exactly anyway. */
    double top = (double)0x00000000ffff0000ULL / share_difficulty;
    work->target_top = top >= 18446744073709551615.0 ? UINT64_MAX : (uint64_t)top;
    return 0;
}

/* SHA-256d of the header with the given nonce, as eight big-endian digest
 * words: digest byte i is byte (i % 4) of word i / 4, most significant first. */
static inline void hash_nonce(const miner_work_t *work, uint32_t nonce, uint32_t out[8])
{
    uint32_t s[8], block[16];

    memcpy(s, work->midstate, sizeof(s));
    block[0] = work->tail[0]; block[1] = work->tail[1]; block[2] = work->tail[2];
    block[3] = bswap32(nonce);
    block[4] = 0x80000000;
    for (int i = 5; i < 15; i++) block[i] = 0;
    block[15] = 640;
    sha256_compress(s, block);

    for (int i = 0; i < 8; i++) block[i] = s[i];
    block[8] = 0x80000000;
    for (int i = 9; i < 15; i++) block[i] = 0;
    block[15] = 256;
    memcpy(out, SHA256_IV, 8 * sizeof(uint32_t));
    sha256_compress(out, block);
}

bool MINER_HOT(miner_scan)(const miner_work_t *work, uint32_t start, uint32_t count, uint32_t *nonce_out)
{
    uint32_t h[8];

    for (uint32_t i = 0; i < count; i++) {
        uint32_t nonce = start + i;
        hash_nonce(work, nonce, h);
        /* The hash is compared as a little-endian number: its most
         * significant 64 bits are bswap(h[7]) and bswap(h[6]). */
        uint64_t top = ((uint64_t)bswap32(h[7]) << 32) | bswap32(h[6]);
        if (top <= work->target_top) {
            *nonce_out = nonce;
            return true;
        }
    }
    return false;
}

void miner_block_hash(const miner_work_t *work, uint32_t nonce, char out_hex[65])
{
    uint32_t h[8];
    uint8_t display[32];

    hash_nonce(work, nonce, h);
    /* Block hashes are displayed as the byte-reversed digest. */
    for (int i = 0; i < 8; i++) {
        uint32_t v = bswap32(h[7 - i]);
        display[4 * i] = (uint8_t)(v >> 24); display[4 * i + 1] = (uint8_t)(v >> 16);
        display[4 * i + 2] = (uint8_t)(v >> 8); display[4 * i + 3] = (uint8_t)v;
    }
    miner_hex(display, 32, out_hex);
}

/* ------------------------------------------------------------------------- */
/* Stratum layer                                                             */
/* ------------------------------------------------------------------------- */

/* Implemented by the caller: send one line (already '\n'-terminated). */
void stratum_transport_send(const char *line);

#define MAX_HEX_COINBASE (2 * MAX_COINBASE + 1)

static struct {
    /* session */
    char extranonce1[33];
    int extranonce2_size;
    double difficulty;
    bool subscribed, authorized;
    int next_id;
    unsigned accepted, rejected;

    /* current job, as received */
    bool have_job;
    char job_id[65];
    char prevhash[65];
    char coinb1[MAX_HEX_COINBASE];
    char coinb2[MAX_HEX_COINBASE];
    char merkle[MAX_MERKLE][65];
    const char *merkle_ptr[MAX_MERKLE];
    int merkle_count;
    char version[9], nbits[9], ntime[9];

    /* work in progress */
    bool work_dirty;
    miner_work_t work;
    uint64_t extranonce2;
    uint64_t next_nonce; /* 0 .. 2^32 */

    /* line assembly */
    char rx[4096];
    size_t rx_len;
} st;

static void stratum_reset(void)
{
    memset(&st, 0, sizeof(st));
    st.difficulty = 1.0;
    st.next_id = 3; /* 1 and 2 are subscribe and authorize */
}

/* --- minimal JSON reader, enough for Stratum messages --------------------- */

static const char *json_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

/* Reads a string at p into out (truncating to cap). Returns the position
 * after the closing quote, or NULL. */
static const char *json_string(const char *p, char *out, size_t cap)
{
    size_t n = 0;
    p = json_ws(p);
    if (*p != '"') return NULL;
    for (p++; *p && *p != '"'; p++) {
        char c = *p;
        if (c == '\\' && p[1]) {
            p++;
            c = *p == 'n' ? '\n' : *p == 't' ? '\t' : *p;
            if (*p == 'u') { c = '?'; for (int i = 0; i < 4 && p[1]; i++) p++; }
        }
        if (out && n + 1 < cap) out[n++] = c;
    }
    if (out && cap) out[n] = '\0';
    return *p == '"' ? p + 1 : NULL;
}

/* Skips any value at p. Returns the position after it, or NULL. */
static const char *json_skip(const char *p)
{
    p = json_ws(p);
    if (*p == '"') return json_string(p, NULL, 0);
    if (*p == '[' || *p == '{') {
        char open = *p, close = open == '[' ? ']' : '}';
        p = json_ws(p + 1);
        if (*p == close) return p + 1;
        for (;;) {
            if (open == '{') {
                p = json_string(p, NULL, 0);
                if (!p || *(p = json_ws(p)) != ':') return NULL;
                p++;
            }
            if (!(p = json_skip(p))) return NULL;
            p = json_ws(p);
            if (*p == ',') { p++; continue; }
            return *p == close ? p + 1 : NULL;
        }
    }
    while (*p && *p != ',' && *p != ']' && *p != '}' && *p != ' ') p++; /* number, true, null */
    return p;
}

/* Returns the value of key in the top-level object, or NULL. */
static const char *json_get(const char *obj, const char *key)
{
    char name[32];
    const char *p = json_ws(obj);
    if (*p != '{') return NULL;
    p++;
    for (;;) {
        if (!(p = json_string(p, name, sizeof(name)))) return NULL;
        p = json_ws(p);
        if (*p != ':') return NULL;
        p = json_ws(p + 1);
        if (strcmp(name, key) == 0) return p;
        if (!(p = json_skip(p))) return NULL;
        p = json_ws(p);
        if (*p != ',') return NULL;
        p++;
    }
}

/* Moves p past the next ',' of an array, or returns NULL at its end. */
static const char *json_next(const char *p)
{
    p = json_ws(p);
    return *p == ',' ? p + 1 : NULL;
}

static bool json_is(const char *p, const char *literal)
{
    return p && strncmp(json_ws(p), literal, strlen(literal)) == 0;
}

/* --- outgoing messages ------------------------------------------------------ */

static void send_line(const char *line)
{
    printf("-> %s", line);
    stratum_transport_send(line);
}

void stratum_begin(void)
{
    char line[256];

    stratum_reset(); /* every connection is a new session */
    snprintf(line, sizeof(line), "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"%s\"]}\n", MINER_AGENT);
    send_line(line);
    snprintf(line, sizeof(line), "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}\n",
             POOL_USER, POOL_PASS);
    send_line(line);
}

static void extranonce2_bytes(uint8_t *out)
{
    /* Big-endian counter in extranonce2_size (1..8) bytes. */
    for (int i = 0; i < st.extranonce2_size; i++)
        out[i] = (uint8_t)(st.extranonce2 >> (8 * (st.extranonce2_size - 1 - i)));
}

static void submit_share(uint32_t nonce)
{
    char line[512], en2_hex[17], nonce_hex[9];
    uint8_t en2[8];

    extranonce2_bytes(en2);
    miner_hex(en2, (size_t)st.extranonce2_size, en2_hex);
    miner_nonce_hex(nonce, nonce_hex);
    snprintf(line, sizeof(line),
             "{\"id\":%d,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}\n",
             st.next_id++, POOL_USER, st.job_id, en2_hex, st.ntime, nonce_hex);
    send_line(line);
}

/* --- incoming messages ------------------------------------------------------ */

static void on_notify(const char *params)
{
    const char *p = json_ws(params);
    int count = 0;

    if (*p++ != '[') return;
    if (!(p = json_string(p, st.job_id, sizeof(st.job_id))) || !(p = json_next(p))) return;
    if (!(p = json_string(p, st.prevhash, sizeof(st.prevhash))) || !(p = json_next(p))) return;
    if (!(p = json_string(p, st.coinb1, sizeof(st.coinb1))) || !(p = json_next(p))) return;
    if (!(p = json_string(p, st.coinb2, sizeof(st.coinb2))) || !(p = json_next(p))) return;
    p = json_ws(p);
    if (*p++ != '[') return;
    p = json_ws(p);
    while (*p == '"') {
        if (count == MAX_MERKLE) return;
        if (!(p = json_string(p, st.merkle[count], sizeof(st.merkle[count])))) return;
        st.merkle_ptr[count] = st.merkle[count];
        count++;
        p = json_ws(p);
        if (*p == ',') p = json_ws(p + 1);
    }
    if (*p++ != ']' || !(p = json_next(p))) return;
    if (!(p = json_string(p, st.version, sizeof(st.version))) || !(p = json_next(p))) return;
    if (!(p = json_string(p, st.nbits, sizeof(st.nbits))) || !(p = json_next(p))) return;
    if (!(p = json_string(p, st.ntime, sizeof(st.ntime)))) return;

    /* Always switch to the newest job; its coinbase differs, so the
     * extranonce2 and nonce ranges can start over. */
    st.merkle_count = count;
    st.have_job = true;
    st.work_dirty = true;
    st.extranonce2 = 0;
    st.next_nonce = 0;
    printf("   new job %s (%d merkle branches)\n", st.job_id, count);
}

static void on_response(long id, const char *msg)
{
    const char *result = json_get(msg, "result");
    const char *error = json_get(msg, "error");

    if (id == 1) {
        const char *p = json_ws(result ? result : "");
        if (*p++ != '[' || !(p = json_skip(p)) || !(p = json_next(p))) goto bad;
        if (!(p = json_string(p, st.extranonce1, sizeof(st.extranonce1))) || !(p = json_next(p))) goto bad;
        st.extranonce2_size = (int)strtol(json_ws(p), NULL, 10);
        if (st.extranonce2_size < 1 || st.extranonce2_size > 8) goto bad;
        st.subscribed = true;
        printf("   subscribed: extranonce1 %s, extranonce2 size %d\n", st.extranonce1, st.extranonce2_size);
        return;
    bad:
        printf("   subscribe failed\n");
    } else if (id == 2) {
        st.authorized = json_is(result, "true");
        printf("   authorize %s\n", st.authorized ? "ok" : "REJECTED (check POOL_USER is a valid TRAP address)");
    } else if (id >= 3) {
        if (json_is(result, "true")) {
            st.accepted++;
            printf("   share accepted (%u accepted, %u rejected)\n", st.accepted, st.rejected);
        } else {
            char reason[128] = "unknown";
            const char *e = json_ws(error ? error : "");
            if (*e == '[') { /* [code, "message", ...] */
                const char *m = json_skip(e + 1);
                if (m && (m = json_next(m))) json_string(m, reason, sizeof(reason));
            } else if (*e == '"') {
                json_string(e, reason, sizeof(reason));
            }
            st.rejected++;
            printf("   share rejected: %s\n", reason);
        }
    }
}

static void handle_line(const char *line)
{
    char method[48];
    const char *m = json_get(line, "method");

    printf("<- %s\n", line);
    if (m && json_string(m, method, sizeof(method))) {
        const char *params = json_get(line, "params");
        if (!params) return;
        if (strcmp(method, "mining.notify") == 0) {
            on_notify(params);
        } else if (strcmp(method, "mining.set_difficulty") == 0) {
            const char *p = json_ws(params);
            double d = *p == '[' ? strtod(json_ws(p + 1), NULL) : 0;
            if (d > 0) {
                st.difficulty = d;
                st.work_dirty = true; /* the share target changes */
                printf("   share difficulty %g\n", d);
            }
        } else if (strcmp(method, "mining.set_extranonce") == 0) {
            const char *p = json_ws(params);
            if (*p == '[' && (p = json_string(p + 1, st.extranonce1, sizeof(st.extranonce1))) && (p = json_next(p))) {
                st.extranonce2_size = (int)strtol(json_ws(p), NULL, 10);
                st.work_dirty = true;
            }
        }
        return;
    }
    const char *id = json_get(line, "id");
    if (id && !json_is(id, "null")) on_response(strtol(json_ws(id), NULL, 10), line);
}

void stratum_receive(const char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char c = data[i];
        if (c == '\n') {
            st.rx[st.rx_len] = '\0';
            if (st.rx_len) handle_line(st.rx);
            st.rx_len = 0;
        } else if (c != '\r') {
            if (st.rx_len + 1 < sizeof(st.rx)) st.rx[st.rx_len++] = c;
            else st.rx_len = 0; /* drop an oversized line */
        }
    }
}

/* Hashes up to max_nonces of the current job. Returns true if a share was
 * submitted. */
bool stratum_mine(uint32_t max_nonces)
{
    uint32_t nonce;

    if (!st.subscribed || !st.authorized || !st.have_job) return false;

    if (st.next_nonce > 0xffffffffULL) { /* nonce range done: next extranonce2 */
        st.extranonce2++;
        st.next_nonce = 0;
        st.work_dirty = true;
    }
    if (st.work_dirty) {
        uint8_t en2[8];
        stratum_job_t job = {
            .prevhash = st.prevhash, .coinb1 = st.coinb1, .coinb2 = st.coinb2,
            .merkle_branch = st.merkle_ptr, .merkle_count = st.merkle_count,
            .version = st.version, .nbits = st.nbits, .ntime = st.ntime,
            .extranonce1 = st.extranonce1,
        };
        extranonce2_bytes(en2);
        if (miner_prepare(&st.work, &job, en2, (size_t)st.extranonce2_size, st.difficulty)) {
            printf("   job %s is malformed, waiting for the next one\n", st.job_id);
            st.have_job = false;
            return false;
        }
        st.work_dirty = false;
    }

    uint64_t left = 0x100000000ULL - st.next_nonce;
    uint32_t count = left < max_nonces ? (uint32_t)left : max_nonces;
    bool found = miner_scan(&st.work, (uint32_t)st.next_nonce, count, &nonce);
    if (found) {
        st.next_nonce = (uint64_t)nonce + 1;
        submit_share(nonce);
    } else {
        st.next_nonce += count;
    }
    return found;
}

/* ------------------------------------------------------------------------- */
/* Demo: self-tests, a replayed pool session and the hash rate               */
/* ------------------------------------------------------------------------- */

/* The TRAP genesis block expressed as a Stratum job (the coinbase is split
 * into coinb1 / extranonce1 / extranonce2 / coinb2 at arbitrary points). */
#define GENESIS_COINB1 "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff" \
                       "3c04ffff001d010434545241502032372f5365"
#define GENESIS_COINB2 "68652067656e6573697320626c6f636b206f6620746865205452415020636861696effffffff0100f2" \
                       "052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6" \
                       "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
#define GENESIS_PREVHASH "0000000000000000000000000000000000000000000000000000000000000000"

static const stratum_job_t GENESIS_JOB = {
    .prevhash = GENESIS_PREVHASH,
    .coinb1 = GENESIS_COINB1,
    .coinb2 = GENESIS_COINB2,
    .merkle_branch = NULL,
    .merkle_count = 0,
    .version = "00000001",
    .nbits = "1d00ffff",
    .ntime = "6ab85c82",
    .extranonce1 = "702f3230",
};
static const uint8_t GENESIS_EXTRANONCE2[4] = {0x32, 0x36, 0x20, 0x54};
static const uint32_t GENESIS_NONCE = 1814180057;
static const char GENESIS_HASH[] = "0000000008d755c7bfc3f5c098512b6b459fa1dd0ff7ed91e55e868032d01b2a";

static uint64_t now_us(void)
{
#ifdef MINER_HOST_TEST
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
#else
    return time_us_64();
#endif
}

/* Demo transport: nothing is sent, send_line() already printed the line. */
static char last_sent[512];
void stratum_transport_send(const char *line)
{
    snprintf(last_sent, sizeof(last_sent), "%s", line);
}

static void feed(const char *line)
{
    stratum_receive(line, strlen(line));
    stratum_receive("\n", 1);
}

static bool self_test(void)
{
    miner_work_t work;
    uint8_t digest[32];
    char hex[65], nonce_hex[9];
    uint32_t nonce;
    bool ok = true;

    sha256((const uint8_t *)"abc", 3, digest);
    miner_hex(digest, 32, hex);
    ok &= strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0;
    printf("sha256(\"abc\")          %s\n", ok ? "ok" : "FAILED");

    if (miner_prepare(&work, &GENESIS_JOB, GENESIS_EXTRANONCE2, sizeof(GENESIS_EXTRANONCE2), 1.0)) {
        printf("miner_prepare          FAILED\n");
        return false;
    }
    miner_block_hash(&work, GENESIS_NONCE, hex);
    bool hash_ok = strcmp(hex, GENESIS_HASH) == 0;
    printf("TRAP genesis hash      %s\n", hash_ok ? "ok" : "FAILED");
    ok &= hash_ok;

    /* Scan a window around the known nonce: exactly that nonce must be found. */
    bool found = miner_scan(&work, GENESIS_NONCE - 2000, 4000, &nonce);
    miner_nonce_hex(nonce, nonce_hex);
    bool scan_ok = found && nonce == GENESIS_NONCE && strcmp(nonce_hex, "6c2230d9") == 0;
    printf("scan finds nonce       %s (nonce %lu, submit as \"%s\")\n", scan_ok ? "ok" : "FAILED",
           (unsigned long)(found ? nonce : 0), found ? nonce_hex : "-");
    ok &= scan_ok;
    return ok;
}

/* Replays what ckpool sends, using the genesis block as the job. A very low
 * share difficulty is used so that a share turns up within seconds even on
 * the RP2350; with TRAP's ckpool the difficulty will be 1. */
static bool session_demo(void)
{
    printf("\nreplayed pool session (POOL_USER = %s)\n", POOL_USER);
    stratum_begin();
    feed("{\"id\":1,\"result\":[[[\"mining.set_difficulty\",\"1\"],[\"mining.notify\",\"1\"]],\"702f3230\",4],\"error\":null}");
    feed("{\"id\":2,\"result\":true,\"error\":null}");
    feed("{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[0.0002]}");
    feed("{\"params\":[\"6ab85c8200000001\",\"" GENESIS_PREVHASH "\",\"" GENESIS_COINB1 "\",\""
         GENESIS_COINB2 "\",[],\"00000001\",\"1d00ffff\",\"6ab85c82\",true],\"id\":null,\"method\":\"mining.notify\"}");

    uint64_t t0 = now_us();
    while (!stratum_mine(8192)) {
        if (now_us() - t0 > 600u * 1000000u) {
            printf("   no share within 10 minutes\n");
            return false;
        }
    }

    /* Check the submitted share independently before "the pool" accepts it. */
    char user[128], job[65], en2_hex[17], ntime[9], nonce_hex[9], hash[65];
    const char *p = json_ws(json_get(last_sent, "params")) + 1;
    p = json_string(p, user, sizeof(user)); p = json_next(p);
    p = json_string(p, job, sizeof(job)); p = json_next(p);
    p = json_string(p, en2_hex, sizeof(en2_hex)); p = json_next(p);
    p = json_string(p, ntime, sizeof(ntime)); p = json_next(p);
    json_string(p, nonce_hex, sizeof(nonce_hex));
    uint8_t en2[4];
    uint32_t nonce = 0;
    miner_work_t check;
    if (hex_decode(en2_hex, en2, sizeof(en2)) != 4 || hex_u32(nonce_hex, &nonce)) return false;
    stratum_job_t job_check = GENESIS_JOB;
    uint32_t again;
    miner_prepare(&check, &job_check, en2, sizeof(en2), 0.0002);
    miner_block_hash(&check, nonce, hash);
    printf("   share hash %s\n", hash);
    /* Difficulty 0.0002 means a hash below about 2^173: 20 leading zero bits. */
    bool ok = strcmp(job, "6ab85c8200000001") == 0 && strcmp(user, POOL_USER) == 0 &&
              strncmp(hash, "00000", 5) == 0 && miner_scan(&check, nonce, 1, &again);

    feed("{\"id\":3,\"result\":true,\"error\":null}");
    return ok && st.accepted == 1;
}

static void benchmark(void)
{
    miner_work_t work;
    uint32_t nonce;
    const uint32_t n = 1u << 16;

    /* An unreachable difficulty makes miner_scan() hash all n nonces. */
    miner_prepare(&work, &GENESIS_JOB, GENESIS_EXTRANONCE2, sizeof(GENESIS_EXTRANONCE2), 1e30);
    uint64_t t0 = now_us();
    miner_scan(&work, 0, n, &nonce);
    uint64_t dt = now_us() - t0;
    printf("hash rate              %.1f kH/s (one core)\n", n / (dt / 1e6) / 1000.0);
}

int main(void)
{
#ifndef MINER_HOST_TEST
    stdio_init_all();
    sleep_ms(3000); /* give the USB serial port time to enumerate */
#endif
    printf("\nrp2350-miner self-test\n");
    bool ok = self_test();
    ok &= session_demo();
    benchmark();
    printf("%s\n", ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
#ifdef MINER_HOST_TEST
    return ok ? 0 : 1;
#else
    for (;;) {
        sleep_ms(10000);
        benchmark();
    }
#endif
}
