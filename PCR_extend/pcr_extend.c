#include <stdio.h>

#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

//#include <tss2/tss2_mu.h>

static void ctx_finalize(TSS2_TCTI_CONTEXT *tcti, ESYS_CONTEXT *esys){
    if(esys){
        Esys_Finalize(&esys);
        free(esys);
    }
    if(tcti){
        Tss2_TctiLdr_Finalize(&tcti);
        free(tcti);
    }
}

static void rc_check(TSS2_RC rc, TSS2_TCTI_CONTEXT *tcti, ESYS_CONTEXT *esys){
    if(rc != TSS2_RC_SUCCESS){
        printf("Failed:0x%x\n", rc);
        printf("%s\n", Tss2_RC_Decode(rc));
        ctx_finalize(tcti, esys);
        exit(1);
    }
}

//int test_quote(QuoteResult *result){
int main(void){
    TSS2_RC rc;
    static ESYS_CONTEXT *es_ctx = NULL;
    static TSS2_TCTI_CONTEXT *t_ctx = NULL;
    TSS2_ABI_VERSION *CURRENT = NULL;

    rc = Tss2_TctiLdr_Initialize(NULL, &t_ctx);
    if(rc != TSS2_RC_SUCCESS){
        printf("tctildr initialize failed\n");
        free(es_ctx);
        return 1;
    }
    printf("tctildr initialize success\n");

    rc = Esys_Initialize(&es_ctx, t_ctx, CURRENT);
    if(rc != TSS2_RC_SUCCESS){
        printf("esys initialize failed:0x%x\n",rc);
        free(t_ctx);
        free(es_ctx);
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
    rc_check(rc, t_ctx, es_ctx);
    printf("nonce OK\n");

    memcpy(qualifyingData.buffer, nonce->buffer, qualifyingData.size);
*/
    TPML_DIGEST_VALUES ex_value;
    ex_value.count = 1;
    ex_value.digests -> hashAlg = TPM2_ALG_SHA256;
    memcpy(ex_value.digests -> digest.sha256, "8bfaa4c860bb16caf44d91961617944a0ae82c8e9b484f16cf04770c433021a4", 32);

    rc = Esys_PCR_Extend(
            es_ctx,
            ESYS_TR_PCR16,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &ex_value
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("extend OK\n");

    ctx_finalize(t_ctx, es_ctx);	
    return 0;
}
