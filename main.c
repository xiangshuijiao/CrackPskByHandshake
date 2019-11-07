#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
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

int test()
{
    return 213;
}
int break_main(char* argv);
// int main()
// {

//     break_main("/root/桌面/jkn/wificrack/wpa-dictionary/common.txt");
//     return  0;
// }

int main(int argc, char* argv[])// argv 指向字典文件
{
    if(argc < 2)
    {
        fprintf(stderr, "please input dictionary file!!!\n");
        return -1;
    }
    // return 7777;
    
    bool find_passwd = false;
    long count = 0;
    
    FILE* t_file=fopen("libhandshake.so.1","r");
    while(!feof(t_file))
    {   


                    
                    find_passwd = false;
                    time_t time_start = clock();
                    wpa2_handshake_t t_handshake;
                    
                    char t_buffer[1024];
                    char ssid[1024];
                    memset(t_buffer, 0, sizeof(t_buffer));
                    int i;

                    fgets(t_buffer,sizeof(t_buffer),t_file);                    
                    if(strlen(t_buffer) < 3) break;// 只有回车换行则退出                    
                    hex2bin(t_buffer,t_handshake.ssid);
                    t_handshake.ssid_len=strlen(t_buffer)/2;
                    // test======================================================
                    printf("fgets(t_buffer,sizeof(t_buffer),t_file) = ");
                    printf("%s", t_buffer);
                    printf("strlen(t_buffer)/2 = %d\n", strlen(t_buffer)/2);
                    printf("t_handshake.ssid_len = %d", t_handshake.ssid_len);
                    printf("\n");

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

                    fgets(t_buffer,sizeof(t_buffer),t_file);
                    memcpy(ssid, t_buffer, sizeof(ssid));
                    if (ssid[strlen(ssid)-1] == '\n')
                        ssid[strlen(ssid)-1] = '\0';// 去掉回车换行
                    if (ssid[strlen(ssid)] == '\n')
                        ssid[strlen(ssid)] = '\0';// 去掉回车换行
                    wpa2break_init_mid_value(&t_handshake);

                    // 打印读取的握手数据
                    printf("t_handshake.ssid = ");
                    for (i = 0; i < t_handshake.ssid_len; i++)
                    {
                        printf("%x", t_handshake.ssid[i]);
                    }
                    printf("\n");

                    printf("t_handshake.ap_mac = ");
                    for (i = 0; i < 6; i++)
                    {
                        printf("%x", t_handshake.ap_mac[i]);
                    }
                    printf("\n");

                    printf("t_handshake.sta_mac = ");
                    for (i = 0; i < 6; i++)
                    {
                        printf("%x", t_handshake.sta_mac[i]);
                    }
                    printf("\n");

                    printf("t_handshake.ap_nonce = ");
                    for (i = 0; i < 32; i++)
                    {
                        printf("%x", t_handshake.ap_nonce[i]);
                    }
                    printf("\n");

                    printf("t_handshake.sta_nonce = ");
                    for (i = 0; i < 32; i++)
                    {
                        printf("%x", t_handshake.sta_nonce[i]);
                    }
                    printf("\n");

                    printf("t_handshake.step2_mic = ");
                    for (i = 0; i < 16; i++)
                    {
                        printf("%x", t_handshake.step2_mic[i]);
                    }
                    printf("\n");



                    FILE *fp;
                    FILE *key_file;
                    char str[256];
                    
                    if((fp=fopen(argv[1], "r")) == NULL){
                        printf("cannot open file %s\n", argv[1]);
                        exit(1);
                    }


                    

                    while(!feof(fp))
                    {
                        if(fgets(str, sizeof(str), fp) != NULL)
                        {
                            count++;

                                                                                            // open file
                                                                                            if(count % 200 == 0){
                                                                                                while(1){
                                                                                                    if ((key_file = fopen("./libshow2.so.1", "w+")) == NULL){
                                                                                                        printf("error open libshow2.so.1\n");
                                                                                                        fclose(key_file);
                                                                                                        continue;
                                                                                                    }
                                                                                                    break;
                                                                                                }
                                                                                                fprintf(key_file, "%ld\n", count);
                                                                                                fflush(key_file);
                                                                                                fclose(key_file);
                                                                                            }

                            str[strlen(str)-2] = '\0';// 去掉回车换行
                            if (1 == wpa2break_is_password(&t_handshake,(uint8_t*)str, strlen(str)))
                            {
                                printf("破解 [ %s ] 使用的密码次数 [ %ld ]\n", ssid,  count);
                                printf("KEY FOUND! [ %s ]\n", str);

                                                                                        // open file
                                                                                        while(1){
                                                                                            if ((key_file = fopen("./libkey.so.0", "w+")) == NULL){
                                                                                                printf("error open libkey.so.0\n");
                                                                                                fclose(key_file);
                                                                                                continue;
                                                                                            }
                                                                                            break;
                                                                                        }
                                                                                        fprintf(key_file, "%s %ld\n", ssid, count);
                                                                                        fprintf(key_file, "success %s\n", str);                                                                                
                                                                                        fflush(key_file);
                                                                                        fclose(key_file);	
                                                                                        

                                                                                        
                                                                                        // open file
                                                                                        while(1){
                                                                                            if ((key_file = fopen("./libshow2.so.1", "w+")) == NULL){
                                                                                                printf("error open libshow2.so.1\n");
                                                                                                fclose(key_file);
                                                                                                continue;
                                                                                            }
                                                                                            break;
                                                                                        }
                                                                                        fprintf(key_file, "%ld\n", count);
                                                                                        fflush(key_file);
                                                                                        fclose(key_file);                           
                               
                                find_passwd = true;  
                                break;  
                                	
                            }
                        }
                    }
                    if (!find_passwd)
                    {
                        printf("破解 [ %s ] 使用的密码次数 [ %ld ]\n", ssid, count);
                        printf("KEY NOT FOUND!\n");

                                                                                        // open file
                                                                                        while(1){
                                                                                            if ((key_file = fopen("./libkey.so.0", "w+")) == NULL){
                                                                                                printf("error open libkey.so.0\n");
                                                                                                fclose(key_file);
                                                                                                continue;
                                                                                            }
                                                                                            break;
                                                                                        }
                                                                                        fprintf(key_file, "%s %ld\n", ssid, count);
                                                                                        fprintf(key_file, "failed\n");
                                                                                        fflush(key_file);
                                                                                        fclose(key_file);	 
                                                                                         

                                                                                        // open file
                                                                                        while(1){
                                                                                            if ((key_file = fopen("./libshow2.so.1", "w+")) == NULL){
                                                                                                printf("error open libshow2.so.1\n");
                                                                                                fclose(key_file);
                                                                                                continue;
                                                                                            }
                                                                                            break;
                                                                                        }
                                                                                        fprintf(key_file, "%ld\n", count);
                                                                                        fflush(key_file);
                                                                                        fclose(key_file);   
                    }
                    
                    printf("\n%lf second\n", (clock() - time_start) * 1.0 / CLOCKS_PER_SEC);  
                    
    }
    fclose(t_file);
    return count;
}
