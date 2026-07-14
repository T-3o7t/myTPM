#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
    size_t   buffer_len;
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)  ((x) >> (n))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define BSIG1(x) (ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define SSIG0(x) (ROTR(x,7)  ^ ROTR(x,18) ^ SHR(x,3))
#define SSIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + BSIG1(e) + CH(e, f, g) + sha256_k[i] + w[i];
        t2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;

    ctx->bitlen += (uint64_t)len * 8;

    if (ctx->buffer_len > 0) {
        size_t need = 64 - ctx->buffer_len;
        size_t take = (len < need) ? len : need;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        i += take;
        if (ctx->buffer_len == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    for (; i + 64 <= len; i += 64) {
        sha256_transform(ctx, data + i);
    }

    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
        ctx->buffer_len = len - i;
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
    uint64_t bitlen = ctx->bitlen; /* パディング処理前の総ビット長を確定・保存 */
    size_t i = ctx->buffer_len;
    int j;

    /* 0x80 を追加 */
    ctx->buffer[i++] = 0x80;

    if (i > 56) {
        /* 56バイトに収まらない場合は0埋めしてこのブロックを処理し、次のブロックへ */
        while (i < 64) {
            ctx->buffer[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->buffer);
        i = 0;
    }

    /* 56バイト目まで0埋め */
    while (i < 56) {
        ctx->buffer[i++] = 0x00;
    }

    /* 末尾8バイトに総ビット長をビッグエンディアンで格納 */
    for (j = 0; j < 8; j++) {
        ctx->buffer[56 + j] = (uint8_t)(bitlen >> (56 - 8 * j));
    }
    sha256_transform(ctx, ctx->buffer);

    for (i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* ========================================================================
 * PE Image Hash 計算ロジック
 * ======================================================================== */

static uint32_t read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/*
 * compute_pe_image_hash:
 *   filepath  - 対象PEファイルのパス
 *   out_hash  - 32バイトのSHA-256結果格納先
 * 戻り値: 0=成功, 負値=失敗
 */
static int compute_pe_image_hash(const char *filepath, uint8_t out_hash[32]) {
    FILE *fp;
    long file_size;
    uint8_t *data;
    uint32_t e_lfanew;
    uint32_t coff_header_offset;
    uint16_t size_of_optional_header;
    uint32_t optional_header_offset;
    uint16_t magic;
    int is_pe32plus;
    uint32_t checksum_offset;
    uint32_t data_dir_offset;
    uint32_t number_of_rva_and_sizes_offset;
    uint32_t number_of_rva_and_sizes;
    uint32_t security_dir_entry_offset;
    uint32_t cert_table_file_offset;
    uint32_t cert_table_size;
    uint32_t size_of_headers_offset;
    uint32_t size_of_headers;
    uint32_t pos, end_of_headers, hash_end;
    sha256_ctx ctx;

    fp = fopen(filepath, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "ファイルサイズの取得に失敗しました\n");
        fclose(fp);
        return -1;
    }

    data = (uint8_t *)malloc((size_t)file_size);
    if (!data) {
        fclose(fp);
        return -1;
    }
    if (fread(data, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "ファイル読み込みに失敗しました\n");
        free(data);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* --- DOSヘッダ検証 --- */
    if (file_size < 0x40 || data[0] != 'M' || data[1] != 'Z') {
        fprintf(stderr, "MZシグネチャがありません(PEファイルではありません)\n");
        free(data);
        return -1;
    }

    e_lfanew = read_u32(data + 0x3C);
    if ((long)e_lfanew + 24 > file_size) {
        fprintf(stderr, "e_lfanewが不正です\n");
        free(data);
        return -1;
    }

    /* --- PEシグネチャ検証 --- */
    if (memcmp(data + e_lfanew, "PE\0\0", 4) != 0) {
        fprintf(stderr, "PEシグネチャがありません\n");
        free(data);
        return -1;
    }

    coff_header_offset = e_lfanew + 4;
    size_of_optional_header = read_u16(data + coff_header_offset + 16);
    optional_header_offset = coff_header_offset + 20;

    if ((long)optional_header_offset + size_of_optional_header > file_size) {
        fprintf(stderr, "Optional Headerのサイズが不正です\n");
        free(data);
        return -1;
    }

    magic = read_u16(data + optional_header_offset);
    if (magic == 0x20b) {
        is_pe32plus = 1;       /* PE32+ (64bit) */
    } else if (magic == 0x10b) {
        is_pe32plus = 0;       /* PE32 (32bit) */
    } else {
        fprintf(stderr, "未知のOptional Header Magic値です: 0x%04x\n", magic);
        free(data);
        return -1;
    }

    /* CheckSumフィールドはPE32/PE32+共通でOptional Header先頭+64 */
    checksum_offset = optional_header_offset + 64;

    /* SizeOfHeadersはPE32/PE32+共通でOptional Header先頭+60 */
    size_of_headers_offset = optional_header_offset + 60;
    size_of_headers = read_u32(data + size_of_headers_offset);

    /* NumberOfRvaAndSizes / DataDirectory の位置は形式により異なる */
    if (!is_pe32plus) {
        number_of_rva_and_sizes_offset = optional_header_offset + 92;
        data_dir_offset = optional_header_offset + 96;
    } else {
        number_of_rva_and_sizes_offset = optional_header_offset + 108;
        data_dir_offset = optional_header_offset + 112;
    }
    number_of_rva_and_sizes = read_u32(data + number_of_rva_and_sizes_offset);

    /* IMAGE_DIRECTORY_ENTRY_SECURITY = index 4 */
    if (number_of_rva_and_sizes < 5) {
        /* Certificate Table用のディレクトリエントリ自体が存在しない */
        security_dir_entry_offset = 0;
        cert_table_file_offset = 0;
        cert_table_size = 0;
    } else {
        security_dir_entry_offset = data_dir_offset + 4 * 8;
        cert_table_file_offset = read_u32(data + security_dir_entry_offset);
        cert_table_size = read_u32(data + security_dir_entry_offset + 4);
    }

    /* --- ハッシュ計算開始 --- */
    sha256_init(&ctx);
    pos = 0;

    /* 1. 先頭からCheckSumフィールド直前まで */
    sha256_update(&ctx, data + pos, checksum_offset - pos);
    pos = checksum_offset + 4; /* CheckSum(4バイト)を読み飛ばす */

    /* 2. CheckSum直後からSecurityディレクトリエントリ直前まで */
    if (security_dir_entry_offset != 0) {
        sha256_update(&ctx, data + pos, security_dir_entry_offset - pos);
        pos = security_dir_entry_offset + 8; /* エントリ(8バイト)を読み飛ばす */
    } else {
        /* Securityディレクトリエントリが存在しない場合はヘッダ末尾まで進める */
        sha256_update(&ctx, data + pos, size_of_headers - pos);
        pos = size_of_headers;
    }

    /* 3. 残りのヘッダ部分(SizeOfHeadersまで)をハッシュ */
    end_of_headers = size_of_headers;
    if (end_of_headers > pos) {
        sha256_update(&ctx, data + pos, end_of_headers - pos);
        pos = end_of_headers;
    }

    /* 4. ヘッダ以降、Certificate Table開始位置(なければファイル末尾)まで */
    if (cert_table_file_offset != 0 && cert_table_size != 0) {
        hash_end = cert_table_file_offset;
    } else {
        hash_end = (uint32_t)file_size;
    }

    if (hash_end > pos) {
        sha256_update(&ctx, data + pos, hash_end - pos);
    }

    /* 5. Certificate Table以降に追加データがあればそれも含める */
    if (cert_table_file_offset != 0 && cert_table_size != 0) {
        uint32_t after_cert = cert_table_file_offset + cert_table_size;
        if ((long)after_cert < file_size) {
            sha256_update(&ctx, data + after_cert, (size_t)(file_size - after_cert));
        }
    }

    sha256_final(&ctx, out_hash);

    free(data);
    return 0;
}

int main(int argc, char *argv[]) {
    uint8_t hash[32];
    int i;

    if (argc != 2) {
        fprintf(stderr, "使い方: %s <PEファイルパス>\n", argv[0]);
        return 1;
    }

    if (compute_pe_image_hash(argv[1], hash) != 0) {
        fprintf(stderr, "PE Image Hashの計算に失敗しました\n");
        return 1;
    }

    printf("PE Image Hash (SHA-256): ");
    for (i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
