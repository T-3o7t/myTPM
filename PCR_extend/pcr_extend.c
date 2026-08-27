#include <stdio.h>

#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

//#include <tss2/tss2_mu.h>

#define DIGEST_SIZE  32   /* SHA-256のダイジェストサイズ (バイト) */
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

/* tcti/esys は呼び出し元の変数そのもの(ダブルポインタ)を受け取り、
 * Finalize後に呼び出し元のポインタもNULLへ戻す。値渡しだと
 * ここでNULL化されるのはローカルコピーだけになり、呼び出し元には
 * 解放済みポインタが残ってしまう(ダングリングポインタ)。 */
static void ctx_finalize(TSS2_TCTI_CONTEXT **tcti, ESYS_CONTEXT **esys){
    if (esys && *esys) {
        Esys_Finalize(esys);
    }
    if (tcti && *tcti) {
        Tss2_TctiLdr_Finalize(tcti);
    }
}

static void rc_check(TSS2_RC rc, TSS2_TCTI_CONTEXT **tcti, ESYS_CONTEXT **esys){
    if (rc != TSS2_RC_SUCCESS) {
        printf("Failed:0x%x\n", rc);
        printf("%s\n", Tss2_RC_Decode(rc));
        ctx_finalize(tcti, esys);
        exit(1);
    }
}

//int test_quote(QuoteResult *result){
int main(void){
    TSS2_RC rc;
    ESYS_CONTEXT *es_ctx = NULL;
    TSS2_TCTI_CONTEXT *t_ctx = NULL;
    TSS2_ABI_VERSION *CURRENT = NULL;

    /* extendするダイジェスト値(SHA-256, 32バイト=64文字の16進文字列) */
    const char *digest_hex = "8bfaa4c860bb16caf44d91961617944a0ae82c8e9b484f16cf04770c433021a4";
    unsigned char digest_bytes[DIGEST_SIZE];

    if (strlen(digest_hex) != HEX_STR_LEN) {
        fprintf(stderr, "エラー: extend値は %d 文字の16進文字列である必要があります (実際: %zu文字)\n",
                HEX_STR_LEN, strlen(digest_hex));
        return 1;
    }
    if (hex_to_bytes(digest_hex, digest_bytes, DIGEST_SIZE) != 0) {
        fprintf(stderr, "エラー: extend値の16進文字列が不正です\n");
        return 1;
    }

    rc = Tss2_TctiLdr_Initialize(NULL, &t_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tctildr initialize failed\n");
        return 1;
    }
    printf("tctildr initialize success\n");

    rc = Esys_Initialize(&es_ctx, t_ctx, CURRENT);
    if (rc != TSS2_RC_SUCCESS) {
        printf("esys initialize failed:0x%x\n",rc);
        ctx_finalize(&t_ctx, &es_ctx);
        return 1;
    }

    printf("Initialize success\n");
/*
    TPM2B_DATA qualifyingData;
    qualifyingData.size = 20;
    TPM2B_DIGEST *nonce;

    rc = Esys_GetRandom(
            es_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            qualifyingData.size,
            &nonce
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("nonce OK\n");

    memcpy(qualifyingData.buffer, nonce->buffer, qualifyingData.size);
*/
    TPML_DIGEST_VALUES ex_value = {0};
    ex_value.count = 1;
    ex_value.digests[0].hashAlg = TPM2_ALG_SHA256;
    memcpy(ex_value.digests[0].digest.sha256, digest_bytes, DIGEST_SIZE);

    rc = Esys_PCR_Extend(
            es_ctx,
            ESYS_TR_PCR16,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &ex_value
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("extend OK\n");

    ctx_finalize(&t_ctx, &es_ctx);
    return 0;
}
