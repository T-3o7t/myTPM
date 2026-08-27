#include <stdio.h>

#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

//#include <tss2/tss2_mu.h>

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

/* select_Out(実際に読み出せたPCRの選択)とpcrValues(そのダイジェスト列)を
 * 突き合わせて "PCR[n]: <hex>" の形式で表示する。
 * pcrValues->digests[] は select_Out 内で選択ビットが立っている順
 * (バンク→バイト→ビットの昇順)に並んでいる。 */
static void print_pcr_values(const TPML_PCR_SELECTION *select_Out, const TPML_DIGEST *pcrValues){
    size_t value_idx = 0;

    for (UINT32 b = 0; b < select_Out->count; b++) {
        const TPMS_PCR_SELECTION *sel = &select_Out->pcrSelections[b];

        for (UINT32 byte = 0; byte < sel->sizeofSelect; byte++) {
            for (int bit = 0; bit < 8; bit++) {
                if (!(sel->pcrSelect[byte] & (1 << bit))) {
                    continue;
                }

                UINT32 pcr_index = byte * 8 + bit;

                if (value_idx >= pcrValues->count) {
                    fprintf(stderr, "PCR[%u]: 対応するダイジェストがありません\n", pcr_index);
                    continue;
                }

                const TPM2B_DIGEST *digest = &pcrValues->digests[value_idx++];
                printf("PCR[%2u]: ", pcr_index);
                for (UINT16 i = 0; i < digest->size; i++) {
                    printf("%02x", digest->buffer[i]);
                }
                printf("\n");
            }
        }
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

/*
    pcrSelect[0] →   PCR 0 ～ 7
    pcrSelect[1] →   PCR 8 ～ 15
    pcrSelect[2] →   PCR 16 ～ 23
*/
    TPML_PCR_SELECTION Select_PCR = {0};
    Select_PCR.count = 1;
    Select_PCR.pcrSelections[0].hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections[0].sizeofSelect = 3;
    Select_PCR.pcrSelections[0].pcrSelect[0] = 0xFF;
    Select_PCR.pcrSelections[0].pcrSelect[1] = 0x00;
    Select_PCR.pcrSelections[0].pcrSelect[2] = 0x00;

	UINT32 counter;
	TPML_PCR_SELECTION *select_Out = NULL;
	TPML_DIGEST *pcrValues = NULL;

	rc = Esys_PCR_Read(
		es_ctx,
		ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
		&Select_PCR,
		&counter,
		&select_Out,
		&pcrValues
		);
	rc_check(rc, &t_ctx, &es_ctx);

	printf("pcrUpdateCounter = %u\n", counter);
	print_pcr_values(select_Out, pcrValues);

	Esys_Free(select_Out);
	Esys_Free(pcrValues);

    ctx_finalize(&t_ctx, &es_ctx);
    return 0;
}
