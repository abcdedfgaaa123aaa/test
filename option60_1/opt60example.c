/* common
 * O = 1
 * R = random
 * TS = timestamp
 * KEY = md5(R + passwd + TS)
 * context = 3des_enrypt(R + user + TS)
 * option60 = O + R + TS + KEY + context
 */
#define LOG_DEBUG "ok:"
#define STB_DIGEST_MD5 1
#define NULL 0

typedef struct option60_input 
{
	char str1[64];
	char str2[64];	
};
void printhx(int len,unsigned char* chartemp)
{
	printf("\n");
	int i =0;
	
	printf("\n");
	for (i =0; i<len ;i++ )
	{
		printf(" %2x",chartemp[i]);
	}
	printf("\n");

}
int generate_option60_common(void* arg, char* outbuf)
{
	#if 0
	//struct option60_input* opi = (struct option60_input*) arg;
	const char *user = "aaa";
	const char *passwd = "bbb";
	#else 
	struct option60_input* opi = (struct option60_input*)arg;
	const char *user = opi->str1;
	const char *passwd = opi->str2;	
	printf("\n\n [%s]_[%d] user = %s\n",__FUNCTION__,__LINE__,user);
	printf("\n\n [%s]_[%d] passwd = %s\n",__FUNCTION__,__LINE__,passwd);
	#endif 
	int i;
	//use O=1 to describe this algorithms.
	int _O = 1;
	unsigned char timestamp[9] = {0};
	unsigned char random_number[9] = {0};
	long long ts = 0;
	long long rd = 0;
	unsigned char context[128] = {0};
	unsigned char *ptr;
	char ciphertext[24] = {0};
	unsigned char md5text[129] = {0};
	unsigned char md5out[17]={0};
	int len;
	int md5len = 0;
	int handle;
	int outbuf_len = 0;

	syslog(LOG_DEBUG, "generate option60 method: %s", __FUNCTION__);
	//syslog(LOG_DEBUG, "user:%s,passwd:%s\n",user,passwd);
	if((NULL == user)||(NULL == passwd))
	{
		strncpy(outbuf,"iTV",3);
		return strlen(outbuf);
	}
	rd = 1254324197; //(long long)random();
	ptr = (unsigned char *)&rd;
	for(i=0;i<8;i++)
	{
		random_number[7-i] = *ptr;
		ptr++;
	}
	ts = 1575257743; //(long long)time(NULL);
	ptr = (unsigned char *)&ts;
	for(i=0;i<8;i++)
	{
		timestamp[7-i] = *ptr;
		ptr++;
	}

	//context = 3des_enrypt(R + user + TS)
	memset(ciphertext,0,sizeof(ciphertext));
	memcpy(ciphertext,random_number,8);

	//printhx(8,ciphertext);
	memcpy(ciphertext+8,timestamp,8);
	//printhx(16,ciphertext);

	len = HS_3des_encrypt(ciphertext,(unsigned char*)user,context);
    printf("after HS_3des_encrypt\n\n");
	printhx(len,ciphertext);

	//KEY = md5(R + passwd + TS)
	memset(md5text,0,sizeof(md5text));
	memcpy(md5text,random_number,8);
	md5len = 8;
	memcpy(md5text+md5len,passwd,strlen(passwd));
	md5len +=strlen(passwd);
	memcpy(md5text+md5len,timestamp,8);
	md5len += 8;
    printf("before md5text, md5len=%d\n\n",md5len);
	printhx(md5len, md5text);
	handle = STB_digest_init(STB_DIGEST_MD5);
	STB_digest_update(handle,md5text,md5len);
	STB_digest_final(handle, md5out, 16);
	
    printf("after md5\n\n");
	printhx(md5len,md5out);
	
	//opption60 = O + R + TS + KEY + context
	memset(outbuf,_O,1);
	outbuf_len +=1;
	memcpy(outbuf+outbuf_len,random_number,8);

	outbuf_len +=8;
	memcpy(outbuf+outbuf_len,timestamp,8);

	
	outbuf_len += 8;
	memcpy(outbuf+outbuf_len,md5out,16);

	outbuf_len += 16;
	memcpy(outbuf+outbuf_len,context,len);

	outbuf_len += len;

    printf("print outbuf\n\n");
	printhx(outbuf_len,outbuf);
	return outbuf_len;
}
#if 1
int main(int argc,char **argv)
{

	char out_str[100]="";	
	struct option60_input tempinput;
	char *user = "hbltiptv@iptv";
	char *pwd = "By1sgT2s";
	int outlen = 0;
	memset(tempinput.str1,0,64);
	memset(tempinput.str2,0,64);
		
	memcpy(tempinput.str1,user,strlen(user));
	memcpy(tempinput.str2,pwd,strlen(pwd));
	printf("\n\n [%s]_[%d] user = %s pwd = %s\n",__FUNCTION__,__LINE__,user,pwd);
	outlen=generate_option60_common(&tempinput,out_str);
	
	printf("\n\n [%s]_[%d] outlen = %d\n",__FUNCTION__,__LINE__,outlen);
	printhx(outlen,out_str);
	
}
#endif 

