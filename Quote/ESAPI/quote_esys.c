#include <stdio.h>

#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

//#include <tss2/tss2_mu.h>

static char *data_read(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    char *buf;
    long sz;

    if(!fp){
        perror("fopen");
        exit(1);
    }
    if(fseek(fp, 0, SEEK_END) != 0){
        fclose(fp);
        exit(1);
    }
    sz = ftell(fp);
    if(sz < 0){
        fclose(fp);
        exit(1);
    }
    rewind(fp);

    buf = malloc((size_t)sz);

    if(!buf){
        fclose(fp);
        exit(1);
    }

    if(fread(buf, 1, (size_t)sz, fp) != (size_t)sz){
        free(buf);
        fclose(fp);
        exit(1);
    }
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
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

	TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {.size = 0},
            .data     = {.size = 0},
        }
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_RESTRICTED |
                TPMA_OBJECT_DECRYPT,
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits   = {.aes = 128},
                    .mode      = {.aes = TPM2_ALG_CFB}
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0},
        }
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

	ESYS_TR primary_handle =ESYS_TR_NONE;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *primary_Data = NULL;
    TPM2B_DIGEST *primary_Hash = NULL;
	TPMT_TK_CREATION *primary_Ticket = NULL;

    rc = Esys_CreatePrimary(
            es_ctx,
            ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &inSensitive,
            &inPublic,
            &outsideInfo,
            &creationPCR,
            &primary_handle,
            &outPublic,
            &primary_Data,
            &primary_Hash,
            &primary_Ticket
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("Primary key created. Handle: 0x%x\n", primary_handle);

    TPM2B_PUBLIC ak_inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,

            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_SIGN_ENCRYPT |
                TPMA_OBJECT_RESTRICTED,

            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme = {
                    .scheme = TPM2_ALG_RSASSA,
                    .details.rsassa.hashAlg = TPM2_ALG_SHA256
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0},
        }
    };

	TPM2B_PUBLIC *ak_pub = NULL;
    TPM2B_PRIVATE *ak_priv = NULL;
    TPM2B_CREATION_DATA *ak_Data = NULL;
    TPM2B_DIGEST *ak_Hash = NULL;
    TPMT_TK_CREATION *ak_Ticket = NULL;

    rc = Esys_Create(
            es_ctx,
            primary_handle,
	        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &inSensitive,
            &ak_inPublic,
            &outsideInfo,
            &creationPCR,
            &ak_priv,
            &ak_pub,
            &ak_Data,
            &ak_Hash,
            &ak_Ticket
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("create ak OK\n");

    TPM2_HANDLE handle = ESYS_TR_NONE;

    rc = Esys_Load(
            es_ctx,
            primary_handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            ak_priv,
            ak_pub,
            &handle
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("load OK\n");
/*
    uint8_t ak_pub_buf[1024];
    size_t ak_offset = 0;

    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(
            ak_pub,
            ak_pub_buf,
            sizeof(ak_pub_buf),
            &ak_offset
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("Marshal OK\n");
    printf("Marshal size = %zu\n", ak_offset);
*/
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

    /* PCR16へextendする値はSHA-256の32バイトダイジェストである必要があるが、
     * nonceは20バイトしかない。不足分を未初期化のまま使うとextend結果が
     * 実行のたびに変わってしまうため、nonceをTPMでSHA-256ハッシュしてから
     * その32バイトのダイジェストをextendする。 */
    TPM2B_MAX_BUFFER nonce_buf;
    nonce_buf.size = nonce->size;
    memcpy(nonce_buf.buffer, nonce->buffer, nonce->size);

    TPM2B_DIGEST *nonce_digest = NULL;
    TPMT_TK_HASHCHECK *nonce_validation = NULL;

    rc = Esys_Hash(
            es_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            &nonce_buf,
            TPM2_ALG_SHA256,
            ESYS_TR_RH_NULL,
            &nonce_digest,
            &nonce_validation
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("nonce hash OK\n");

    TPML_DIGEST_VALUES ex_value = {0};
    ex_value.count = 1;
    ex_value.digests[0].hashAlg = TPM2_ALG_SHA256;
    memcpy(ex_value.digests[0].digest.sha256, nonce_digest->buffer, nonce_digest->size);

    rc = Esys_PCR_Extend(
            es_ctx,
            ESYS_TR_PCR16,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &ex_value
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("extend OK\n");

    TPM2B_ATTEST *quote;
    TPMT_SIGNATURE *signature;

    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

    /*
    pcrSelect[0] →   PCR 0 ～ 7
    pcrSelect[1] →   PCR 8 ～ 15
    pcrSelect[2] →   PCR 16 ～ 23
    */
    TPML_PCR_SELECTION Select_PCR = {0};
    Select_PCR.count = 1;
    Select_PCR.pcrSelections[0].hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections[0].sizeofSelect = 3;
    Select_PCR.pcrSelections[0].pcrSelect[0] = 0xFE;
    Select_PCR.pcrSelections[0].pcrSelect[1] = 0x03;
    /* PCR16(bit0)を選択に含める。直前でnonceのダイジェストをPCR16へ
     * extendしているため、quoteの対象に含めないとfreshness確認の
     * 意味がなくなってしまう。 */
    Select_PCR.pcrSelections[0].pcrSelect[2] = 0x01;

    rc = Esys_Quote(
            es_ctx,
            handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &qualifyingData,
            &scheme,
            &Select_PCR,
            &quote,
            &signature
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("quote OK\n");

	size_t check_size = quote->size;
/*
	FILE *fp = fopen("quote.bin", "wb");
	fwrite(quote->attestationData, 1, quote->size, fp);
	fclose(fp);
*/
	char *message = data_read("quote.bin", &check_size);
	if(memcmp(quote->attestationData, message, quote->size))printf("quote check OK\n");


    TPM2B_MAX_BUFFER data;
    data.size = quote->size;
    memcpy(data.buffer, quote->attestationData, quote->size);

    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    rc = Esys_Hash(
        es_ctx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &data,
        TPM2_ALG_SHA256,
        ESYS_TR_RH_NULL,
        &digest,
        &validation
    );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("hash OK\n");


    TPMT_TK_VERIFIED *valid;

    rc = Esys_VerifySignature(
            es_ctx,
            handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            digest,
            signature,
            &valid
            );
    rc_check(rc, &t_ctx, &es_ctx);
    printf("verify OK\n");

	free(message);

	Esys_Free(outPublic);
    Esys_Free(primary_Data);
    Esys_Free(primary_Hash);
    Esys_Free(primary_Ticket);
    Esys_Free(ak_priv);
    Esys_Free(ak_pub);
    Esys_Free(ak_Data);
    Esys_Free(ak_Hash);
    Esys_Free(ak_Ticket);
    Esys_Free(nonce);
    Esys_Free(nonce_digest);
    Esys_Free(nonce_validation);
    Esys_Free(quote);
    Esys_Free(signature);
    Esys_Free(digest);
    Esys_Free(validation);
    Esys_Free(valid);

    Esys_FlushContext(es_ctx, handle);
    Esys_FlushContext(es_ctx, primary_handle);

    ctx_finalize(&t_ctx, &es_ctx);
    return 0;
}
