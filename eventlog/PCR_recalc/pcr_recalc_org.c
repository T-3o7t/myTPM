/*
 * tpm2_pcrextend の動作を再現するプログラム
 *
 * PCR extend の定義:
 *     PCR_new = HASH( PCR_old || value )
 *
 * 本プログラムでは SHA-256 (32バイト) を使用し、
 * A, B, C, D の4つの値(各32バイト=64文字の16進文字列)を
 * この順番で extend していく。
 *
 * SHA-256の実装は外部ライブラリ(OpenSSL等)に依存せず、
 * このファイル単体でコンパイル可能。
 *
 * ビルド:
 *     gcc -O2 -o pcrextend pcrextend.c
 *
 * 実行例:
 *     ./pcrextend <Aの64文字hex> <Bの64文字hex> <Cの64文字hex> <Dの64文字hex>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PCR_SIZE     32   /* SHA-256のダイジェストサイズ (バイト) */
#define HEX_STR_LEN  64   /* 32バイトを16進文字列にした時の長さ */

/* ============================================================
 * SHA-256 実装 (RFC 6234 / FIPS 180-4 準拠、依存ライブラリなし)
 * ============================================================ */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    unsigned char buffer[64];
    size_t buffer_len;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(sha256_ctx *ctx, const unsigned char *data)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[ctx->buffer_len++] = data[i];
        if (ctx->buffer_len == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->bitlen += 512;
            ctx->buffer_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char *out)
{
    size_t i = ctx->buffer_len;

    /* パディング: 0x80 を追加し、長さが 56 (mod 64) になるまで 0 で埋める */
    if (ctx->buffer_len < 56) {
        ctx->buffer[i++] = 0x80;
        while (i < 56) ctx->buffer[i++] = 0x00;
    } else {
        ctx->buffer[i++] = 0x80;
        while (i < 64) ctx->buffer[i++] = 0x00;
        sha256_transform(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->buffer_len * 8;

    /* 末尾8バイトにビット長をビッグエンディアンで格納 */
    for (int j = 0; j < 8; j++) {
        ctx->buffer[63 - j] = (unsigned char)(ctx->bitlen >> (j * 8));
    }
    sha256_transform(ctx, ctx->buffer);

    for (int j = 0; j < 8; j++) {
        out[j * 4]     = (unsigned char)(ctx->state[j] >> 24);
        out[j * 4 + 1] = (unsigned char)(ctx->state[j] >> 16);
        out[j * 4 + 2] = (unsigned char)(ctx->state[j] >> 8);
        out[j * 4 + 3] = (unsigned char)(ctx->state[j]);
    }
}

/* data(len バイト)のSHA-256を計算し、out(32バイト)に書き込む */
static void sha256(const unsigned char *data, size_t len, unsigned char *out)
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* ============================================================
 * ユーティリティ
 * ============================================================ */

/* 16進文字列(64文字)をバイト列(32バイト)に変換する */
static int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len)
{
    if (strlen(hex) != bytes_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }
    return 0;
}

/* バイト列を16進文字列として表示する */
static void print_hex(const unsigned char *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

/*
 * PCR extend 処理本体
 *   pcr   : 現在のPCR値 (32バイト、更新後の値もここに書き戻される)
 *   value : extend する値 (32バイト)
 *
 *   PCR_new = SHA256(PCR_old || value)
 */
static void pcr_extend(unsigned char *pcr, const unsigned char *value)
{
    unsigned char buf[PCR_SIZE * 2];

    memcpy(buf, pcr, PCR_SIZE);
    memcpy(buf + PCR_SIZE, value, PCR_SIZE);

    sha256(buf, sizeof(buf), pcr);
}

/* ============================================================
 * メイン処理
 * ============================================================ */

int main(int argc, char *argv[])
{
	char *bin[4] = {"34bd807d04c406942d2ad129a3b1cbf989f9f7a8b9c010da70a4c781de633279",
	"3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba",
	"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
	"3319f2a64873c0e7e0da3aadb1d8d3add1558be2d99d89c3d8a048986cdbfff7"
	};
/*    if (argc != 5) {
        fprintf(stderr, "使い方: %s <Aのhex> <Bのhex> <Cのhex> <Dのhex>\n", argv[0]);
        return 1;
    }
*/
    /* PCRの初期値は0で初期化 (TPMのリセット直後の状態を想定) */
    unsigned char pcr[PCR_SIZE] = {0};
    unsigned char values[4][PCR_SIZE];
    const char *labels[4] = {"A", "B", "C", "D"};

    /* 入力された4つの16進文字列をバイト列に変換 */
    for (int i = 0; i < 4; i++) {
        if (strlen(bin[i]) != HEX_STR_LEN) {
            fprintf(stderr, "エラー: %s は %d 文字の16進文字列である必要があります (実際: %zu文字)\n",
                    labels[i], HEX_STR_LEN, strlen(bin[i]));
            return 1;
        }
        if (hex_to_bytes(bin[i], values[i], PCR_SIZE) != 0) {
            fprintf(stderr, "エラー: %s の16進文字列が不正です\n", labels[i]);
            return 1;
        }
    }

    printf("初期PCR値       : ");
    print_hex(pcr, PCR_SIZE);

    /* A, B, C, D の順に extend を実行 */
    for (int i = 0; i < 4; i++) {
        pcr_extend(pcr, values[i]);
        printf("%s をextend後     : ", labels[i]);
        print_hex(pcr, PCR_SIZE);
    }

    printf("\n最終PCR値        : ");
    print_hex(pcr, PCR_SIZE);

    return 0;
}
