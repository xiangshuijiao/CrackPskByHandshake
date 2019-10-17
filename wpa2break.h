#ifndef WPA2BREAK_H
#define WPA2BREAK_H

#include <stdint.h>

#define WPA2_SSID_MAX_LEN                   32
#define WPA2_MAC_LEN                         6
#define WPA2_NONCE_LEN                      32
#define WPA2_STEP2_DATA_LEN                121

#define WPA2_MIC_OFFSET                     81
#define WPA2_PSK_LEN                        32
#define WPA2_PBKDF2_LOOP                  4096
#define WPA2_WORD                             "Pairwise key expansion\0"
#define WPA2_WORD_LEN                       23
#define WPA2_PTK_LEN                        16
#define WPA2_PTK_DATA_LEN                     (WPA2_WORD_LEN+2*WPA2_MAC_LEN+2*WPA2_NONCE_LEN+1)
#define WPA2_MIC_LEN                        16

typedef struct
{
    uint8_t ssid[WPA2_SSID_MAX_LEN];
    uint8_t ssid_len;
    uint8_t ap_mac[WPA2_MAC_LEN];
    uint8_t sta_mac[WPA2_MAC_LEN];
    uint8_t ap_nonce[WPA2_NONCE_LEN];
    uint8_t sta_nonce[WPA2_NONCE_LEN];
    uint8_t step2_data[WPA2_STEP2_DATA_LEN];
    uint8_t step2_mic[WPA2_MIC_LEN];
    struct
    {
        uint8_t ptk_data[WPA2_PTK_DATA_LEN];
    }
    mid_value;
}
wpa2_handshake_t;

void wpa2break_init_mid_value(wpa2_handshake_t* p_handshake);
int wpa2break_is_password(wpa2_handshake_t* p_handshake,uint8_t* p_password,uint8_t p_len);

#endif
