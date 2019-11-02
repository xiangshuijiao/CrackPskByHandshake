#include "wpa2break.h"
#include "fastpbkdf2.h"
#include "hmac.h"
#include <string.h>

#include <stdio.h>

static void mem_min_max(uint8_t** p_min,uint8_t** p_max,uint8_t p_len)
{
    int t_cmp=memcmp(*p_min,*p_max,p_len);
    if(t_cmp>0)
    {
        uint8_t* p_temp=*p_min;
        *p_min=*p_max;
        *p_max=p_temp;
    }
}

void wpa2break_init_mid_value(wpa2_handshake_t* p_handshake)
{
    uint8_t* t_ptk_data=p_handshake->mid_value.ptk_data;
    memcpy(t_ptk_data,WPA2_WORD,WPA2_WORD_LEN);
    uint8_t* t_min=p_handshake->ap_mac;
    uint8_t* t_max=p_handshake->sta_mac;
    mem_min_max(&t_min,&t_max,WPA2_MAC_LEN);
    memcpy(t_ptk_data+WPA2_WORD_LEN,t_min,WPA2_MAC_LEN);
    memcpy(t_ptk_data+WPA2_WORD_LEN+WPA2_MAC_LEN,t_max,WPA2_MAC_LEN);
    t_min=p_handshake->ap_nonce;
    t_max=p_handshake->sta_nonce;
    mem_min_max(&t_min,&t_max,WPA2_NONCE_LEN);
    memcpy(t_ptk_data+WPA2_WORD_LEN+2*WPA2_MAC_LEN,t_min,WPA2_NONCE_LEN);
    memcpy(t_ptk_data+WPA2_WORD_LEN+2*WPA2_MAC_LEN+WPA2_NONCE_LEN,t_max,WPA2_NONCE_LEN);
    t_ptk_data[WPA2_PTK_DATA_LEN-1]=0;
    memset(p_handshake->step2_data+WPA2_MIC_OFFSET,0,WPA2_MIC_LEN);
}

int wpa2break_is_password(wpa2_handshake_t* p_handshake,uint8_t* p_password,uint8_t p_len)
{
    uint8_t t_psk[WPA2_PSK_LEN];
    fastpbkdf2_hmac_sha1(p_password,p_len,p_handshake->ssid,p_handshake->ssid_len,WPA2_PBKDF2_LOOP,t_psk,WPA2_PSK_LEN);
    //******************************************8
    int i;
    printf("p_password = ");
    for (i = 0; i < p_len; i++)
    {
        printf("%x", p_password[i]);
    }
    printf("\n");
    printf("ssid = ");
    for (i = 0; i < p_handshake->ssid_len; i++)
    {
        printf("%x", p_handshake->ssid[i]);
    }
    printf("\n");
    printf("PMK = ");
    for (i = 0; i < WPA2_PSK_LEN; i++)
    {
        printf("%x", t_psk[i]);
    }
    printf("\n");


    uint8_t t_ptk[WPA2_PTK_LEN];
    uint32_t t_ptk_len=WPA2_PTK_LEN;
    hmac_sha1(t_psk,WPA2_PSK_LEN,p_handshake->mid_value.ptk_data,WPA2_PTK_DATA_LEN,t_ptk,&t_ptk_len);
    //******************************************8
    
    printf("PTK = ");
    for (i = 0; i < WPA2_PTK_LEN; i++)
    {
        printf("%x", t_ptk[i]);
    }
    printf("\n");

    uint8_t t_mic[WPA2_MIC_LEN];
    uint32_t t_mic_len=WPA2_MIC_LEN;
    hmac_sha1(t_ptk,WPA2_PTK_LEN,p_handshake->step2_data,WPA2_STEP2_DATA_LEN,t_mic,&t_mic_len);
    //******************************************8
    
    printf("MIC = ");
    for (i = 0; i < t_mic_len; i++)
    {
        printf("%x", t_mic[i]);
    }
    printf("\n");
    return memcmp(p_handshake->step2_mic,t_mic,WPA2_MIC_LEN)==0;
}
