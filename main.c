#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "wpa2break.h"

static int hex2dig(char p_hex)
{
    if('0'<=p_hex&&p_hex<='9')
        return p_hex-'0';
    if('a'<=p_hex&&p_hex<='f')
        return p_hex-'a'+10;
    return 0;
}

static void hex2bin(char* p_hex,uint8_t* p_bin)
{
    int t_len=strlen(p_hex)/2;
    int t_i;
    for(t_i=0;t_i<t_len;t_i++)
        p_bin[t_i]=hex2dig(p_hex[2*t_i])*16+hex2dig(p_hex[2*t_i+1]);
}

int main(char argc, char** argv)
{
    if(argc < 2)
    {
        fprintf(stderr, "please input dictionary file!!!\n");
        return -1;
    }
    


    wpa2_handshake_t t_handshake;
    FILE* t_file=fopen("handshake.txt","r");
    char t_buffer[1024];
    fgets(t_buffer,sizeof(t_buffer),t_file);
    hex2bin(t_buffer,t_handshake.ssid);
    t_handshake.ssid_len=strlen((char*)t_handshake.ssid);
    fgets(t_buffer,sizeof(t_buffer),t_file);
    hex2bin(t_buffer,t_handshake.ap_mac);
    fgets(t_buffer,sizeof(t_buffer),t_file);
    hex2bin(t_buffer,t_handshake.sta_mac);
    fgets(t_buffer,sizeof(t_buffer),t_file);
    hex2bin(t_buffer,t_handshake.ap_nonce);
    fgets(t_buffer,sizeof(t_buffer),t_file);
    hex2bin(t_buffer,t_handshake.sta_nonce);
    fgets(t_buffer,sizeof(t_buffer),t_file);
    hex2bin(t_buffer,t_handshake.step2_data);
    fgets(t_buffer,sizeof(t_buffer),t_file);
    hex2bin(t_buffer,t_handshake.step2_mic);
    fclose(t_file);
    wpa2break_init_mid_value(&t_handshake);



	FILE *fp;
	char str[256];
	long count = 0;
	if((fp=fopen(argv[1], "r")) == NULL){
		printf("cannot open file %s\n", argv[1]);
		exit(1);
	}
	while(!feof(fp)){
		if(fgets(str, sizeof(str), fp) != NULL){
			count++;
			str[strlen(str)-2] = '\0';
			if (1 == wpa2break_is_password(&t_handshake,(uint8_t*)str, strlen(str))){
				printf("count = %ld\n", count);

				printf("KEY FOUND! [ %s ]\n", str);
				return 0;	
			}
			

		}
			
	}
    printf("count = %ld\n", count);
	printf("KEY NOT FOUND!\n");
    return 0;
}
