/*
 * tpm2_pcrextend の動作を再現するプログラム (OpenSSL版)
 *
 * PCR extend の定義:
 *     PCR_new = HASH( PCR_old || value )
 *
 * 本プログラムでは SHA-256 (32バイト) を使用し、
 * A, B, C, D の4つの値(各32バイト=64文字の16進文字列)を
 * この順番で extend していく。
 *
 * SHA-256の計算には OpenSSL の libcrypto を使用する。
 *
 * 必要パッケージ (Ubuntu/Debianの場合):
 *     sudo apt-get install libssl-dev
 *
 * ビルド:
 *     gcc -O2 -o pcrextend_ssl pcrextend_ssl.c -lcrypto
 *
 * ※ OpenSSL 3.0系では SHA256() 関数はレガシー扱いですが、
 *    引き続き提供されており警告なく使用できます。
 *    (deprecated警告が出る環境では EVP_Digest 系APIへの
 *     置き換えも可能です。必要であればお知らせください)
 *
 * 実行例:
 *     ./pcrextend_ssl <Aの64文字hex> <Bの64文字hex> <Cの64文字hex> <Dの64文字hex>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define PCR_SIZE     32   /* SHA-256のダイジェストサイズ (バイト) */
#define HEX_STR_LEN  64   /* 32バイトを16進文字列にした時の長さ */

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

    /* OpenSSLのSHA256()関数でハッシュ計算し、結果をpcrに書き戻す */
    SHA256(buf, sizeof(buf), pcr);
}

int main(int argc, char *argv[])
{
	char *bin[4] = {
			"34bd807d04c406942d2ad129a3b1cbf989f9f7a8b9c010da70a4c781de633279", //EventNum9  Digest
			"3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba", //EventNum13 Digest
			"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119", //EventNum20 Digest
//			"3319f2a64873c0e7e0da3aadb1d8d3add1558be2d99d89c3d8a048986cdbfff7"  //EventNum23 Digest
			argv[1]
			};

	if (argc != 2) {
        fprintf(stderr, "使い方: %s 'PE_IMAGE_HASH'\n", argv[0]);
        return 1;
    }
    /* PCRの初期値は0で初期化 (TPMのリセット直後の状態を想定) */
    unsigned char pcr[PCR_SIZE] = {0};
    unsigned char values[4][PCR_SIZE];
    const char *labels[4] = {"EventNum 9", "EventNum 13", "EventNum 20", "EventNum 23"};

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

    printf("PCR[4]       : ");
    print_hex(pcr, PCR_SIZE);

    /* A, B, C, D の順に extend を実行 */
    for (int i = 0; i < 4; i++) {
        pcr_extend(pcr, values[i]);
        printf("%s をextend後     : ", labels[i]);
        print_hex(pcr, PCR_SIZE);
    }

    printf("\nPCR[4]        : ");
    print_hex(pcr, PCR_SIZE);

    return 0;
}
