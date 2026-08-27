#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

static uint32_t read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/*
 *   filepath  - 対象PEファイルのパス
 *   out_hash  - 32バイトのSHA-256結果格納先
 */
static int compute_pe_image_hash(const char *filepath, uint8_t out_hash[32]) {
    FILE *fp;
    long file_size;
    int is_pe32plus;
    uint8_t *data;
    uint16_t magic;
    uint16_t size_of_optional_header;
    uint32_t e_lfanew;
    uint32_t coff_header_offset;
    uint32_t optional_header_offset;
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
    EVP_MD_CTX *ctx;
    unsigned int out_len = 0;

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

    /* SizeOfHeadersがファイルサイズを超えている場合は壊れたPEファイル。
     * 検証しないままハッシュ計算範囲の終端として使うとヒープ範囲外読み出しになる。 */
    if ((long)size_of_headers > file_size) {
        fprintf(stderr, "SizeOfHeadersがファイルサイズを超えています\n");
        free(data);
        return -1;
    }

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

    /* --- ハッシュ計算開始 (OpenSSL EVP API) --- */
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_MD_CTX_newに失敗しました\n");
        free(data);
        return -1;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_exに失敗しました\n");
        EVP_MD_CTX_free(ctx);
        free(data);
        return -1;
    }

    pos = 0;

    /* 1. 先頭からCheckSumフィールド直前まで */
    EVP_DigestUpdate(ctx, data + pos, checksum_offset - pos);
    pos = checksum_offset + 4; /* CheckSum(4バイト)を読み飛ばす */

    /* 2. CheckSum直後からSecurityディレクトリエントリ直前まで */
    if (security_dir_entry_offset != 0) {
        EVP_DigestUpdate(ctx, data + pos, security_dir_entry_offset - pos);
        pos = security_dir_entry_offset + 8; /* エントリ(8バイト)を読み飛ばす */
    } else {
        /* Securityディレクトリエントリが存在しない場合はヘッダ末尾まで進める */
        EVP_DigestUpdate(ctx, data + pos, size_of_headers - pos);
        pos = size_of_headers;
    }

    /* 3. 残りのヘッダ部分(SizeOfHeadersまで)をハッシュ */
    end_of_headers = size_of_headers;
    if (end_of_headers > pos) {
        EVP_DigestUpdate(ctx, data + pos, end_of_headers - pos);
        pos = end_of_headers;
    }

    /* 4. ヘッダ以降、Certificate Table開始位置(なければファイル末尾)まで */
    if (cert_table_file_offset != 0 && cert_table_size != 0) {
        hash_end = cert_table_file_offset;
    } else {
        hash_end = (uint32_t)file_size;
    }

    if (hash_end > pos) {
        EVP_DigestUpdate(ctx, data + pos, hash_end - pos);
    }

    /* 5. Certificate Table以降に追加データがあればそれも含める */
    if (cert_table_file_offset != 0 && cert_table_size != 0) {
        uint32_t after_cert = cert_table_file_offset + cert_table_size;
        if ((long)after_cert < file_size) {
            EVP_DigestUpdate(ctx, data + after_cert, (size_t)(file_size - after_cert));
        }
    }

    if (EVP_DigestFinal_ex(ctx, out_hash, &out_len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_exに失敗しました\n");
        EVP_MD_CTX_free(ctx);
        free(data);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    free(data);
    return 0;
}

int main(int argc, char *argv[]) {
    uint8_t hash[EVP_MAX_MD_SIZE];
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
