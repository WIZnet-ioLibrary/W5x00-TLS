/*
 * file: SSLInterface.c
 * description: mbedtls callback functions
 * author: peter
 * company: wiznet
 * data: 2015.11.26
 */

#include "SSLInterface.h"
#include "SSL_Random.h"
#include "socket.h"
#include "certificate.h"
#include "mbedtls/debug.h"
#include <stdio.h>
#include <string.h>
#include "HexTrans.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

#define CERTIFICATE	self_signed_certificate

unsigned char sslHostName[] = "mqtt.wiznet.io";
//unsigned char sslHostName[] = "mqtt.example.net";

unsigned char tempBuf[DEBUG_BUFFER_SIZE] = {0,};


//todo Add udp functions, ex) sendto recvfrom

/*Shell for mbedtls recv function*/
int WIZnetRecv(void *ctx, unsigned char *buf, unsigned int len )
{
	int32_t ret;
	ret = recv(*((int *)ctx),buf,len);
	printf("Port:[%d]/Recv(%d)[%d]: \r\n",*((int *)ctx) ,len, (unsigned int)ret);
	string_print_Hex(buf, len);
    //return (recv(*((int *)ctx),buf,len));
	return ret;
}

/*Shell for mbedtls send function*/
int WIZnetSend(void *ctx, const unsigned char *buf, unsigned int len )
{
	printf("Port:[%d]/Send(%d) : \r\n",*((int *)ctx) ,len);
	string_print_Hex(buf, len);
    return (send(*((int *)ctx),buf,len));
}

/*Shell for mbedtls debug function.
 *DEBUG_LEBEL can be changed from 0 to 3*/
#ifdef MBEDTLS_DEBUG_C
void WIZnetDebugCB(void *ctx, int level, const char *file, int line, const char *str)
{
    if(level <= DEBUG_LEVEL)
    {
       printf("%s\r\n",str);
    }
}
#endif

/* SSL context intialization
 * */
unsigned int wiz_tls_init(wiz_tls_context* tlsContext, int* socket_fd)
{
	int ret = 1;
#if defined (MBEDTLS_ERROR_C)
	char error_buf[100];
#endif


#if defined (MBEDTLS_DEBUG_C)
	debug_set_threshold(DEBUG_LEVEL);
#endif

	/*
		Initialize session data
	*/
#if defined (MBEDTLS_ENTROPY_C)
	tlsContext->entropy = malloc(sizeof(mbedtls_entropy_context));
	mbedtls_entropy_init( tlsContext->entropy);
#endif

	tlsContext->ctr_drbg = malloc(sizeof(mbedtls_ctr_drbg_context));
	tlsContext->ssl = malloc(sizeof(mbedtls_ssl_context));
	tlsContext->conf = malloc(sizeof(mbedtls_ssl_config));
	tlsContext->cacert = malloc(sizeof(mbedtls_x509_crt));

	mbedtls_ctr_drbg_init(tlsContext->ctr_drbg);
	mbedtls_x509_crt_init(tlsContext->cacert);
	mbedtls_ssl_init(tlsContext->ssl);
	mbedtls_ssl_config_init(tlsContext->conf);
	/*
		Initialize certificates
	*/

#if defined (MBEDTLS_X509_CRT_PARSE_C)

#if defined (MBEDTLS_DEBUG_C)
	printf(" Loading the CA root certificate \r\n");
#endif
	mbedtls_ssl_config_defaults((tlsContext->conf),
								MBEDTLS_SSL_IS_CLIENT,
								MBEDTLS_SSL_TRANSPORT_STREAM,
								MBEDTLS_SSL_PRESET_DEFAULT);
	ret=mbedtls_ssl_setup(tlsContext->ssl, tlsContext->conf);
	printf("mbedtls_ssl_setup : %d\r\n", ret);
	mbedtls_ssl_set_hostname(tlsContext->ssl, sslHostName);

#if defined (MBEDTLS_CERTS_C)
	printf("cert size[%d] = [%s]\r\n", strlen(CERTIFICATE), CERTIFICATE);
	ret = mbedtls_x509_crt_parse((tlsContext->cacert),(unsigned char *)CERTIFICATE, strlen(CERTIFICATE));
#else
	ret = 1;
#if defined (MBEDTLS_DEBUG_C)
	printf("SSL_CERTS_C not define .\r\n");
#endif
#endif
#endif
	if(ret < 0)
	{
#if defined (MBEDTLS_CERTS_C)
		printf("x509_crt_parse failed.%x \r\n",ret);
#endif
		//return 0;
	}
	/*
		set ssl session param
	*/

	mbedtls_ssl_conf_ca_chain(tlsContext->conf, tlsContext->cacert, NULL);
	//mbedtls_ssl_conf_authmode(tlsContext->conf, MBEDTLS_SSL_VERIFY_REQUIRED);//This option is for server certificate verification
	mbedtls_ssl_conf_authmode(tlsContext->conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(tlsContext->conf,SSLRandomCB,tlsContext->ctr_drbg);
#if defined (MBEDTLS_DEBUG_C)
	mbedtls_ssl_conf_dbg(tlsContext->conf, WIZnetDebugCB, stdout);
#endif
	mbedtls_ssl_set_bio(tlsContext->ssl, socket_fd, SSLSendCB, SSLRecvCB, SSLRecvTimeOutCB);		 //set client's socket send and receive functions

	return 1;
}

/*Free the memory for ssl context*/
void wiz_tls_deinit(wiz_tls_context* tlsContext)
{
	/*  free SSL context memory  */
	mbedtls_ssl_free( tlsContext->ssl );
	mbedtls_ssl_config_free( tlsContext->conf );
#if defined (MBEDTLS_DEBUG_C)
	mbedtls_ctr_drbg_free( tlsContext->ctr_drbg );
#endif
	//mbedtls_entropy_free( tlsContext->entropy );
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_free( tlsContext->cacert );
#endif
	free(tlsContext->ctr_drbg);
	free(tlsContext->ssl);
	free(tlsContext->conf);
	free(tlsContext->cacert);
}

/* SSL handshake */
unsigned int wiz_tls_connect(wiz_tls_context* tlsContext, unsigned short port, uint8_t * addr)
{
    int ret;

    memset(tempBuf,0,1024);

	/*socket open*/
    printf("socket open port : %d \r\n",*((uint8_t*)(tlsContext->ssl->p_bio)));
	ret = socket(*((uint8_t*)(tlsContext->ssl->p_bio)), Sn_MR_TCP, 0, 0x00);
	printf("socket[%d] \r\n", ret);
	if(ret != *((uint8_t*)(tlsContext->ssl->p_bio)))
		return ret;

	/*Connect to the target*/
	printf("server ip : %d.%d.%d.%d port : %d \r\n", addr[0], addr[1], addr[2], addr[3], port);
	ret = connect(*((uint8_t*)tlsContext->ssl->p_bio), addr, port);
	printf("init connect[%d] \r\n", ret);
	if(ret != SOCK_OK)
		return ret;

#if defined(MBEDTLS_DEBUG_C)
    printf( "  . Performing the SSL/TLS handshake..." );
#endif

    while( ( ret = mbedtls_ssl_handshake( tlsContext->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
#if defined(MBEDTLS_ERROR_C)
            mbedtls_strerror( ret, (char *) tempBuf, DEBUG_BUFFER_SIZE );
            printf( " failed\n\r  ! mbedtls_ssl_handshake returned %d: %s\n\r", ret, tempBuf );
#endif
            return( -1 );
        }
    }

#if defined(MBEDTLS_DEBUG_C)
    printf( "ok\n\r    [ Ciphersuite is %s ]\n\r",
            mbedtls_ssl_get_ciphersuite( tlsContext->ssl ) );
#endif

    return( 0 );
}

unsigned int wiz_tls_read(wiz_tls_context* tlsContext, unsigned char* readbuf, unsigned int len)
{
	return mbedtls_ssl_read( tlsContext->ssl, readbuf, len );
}

unsigned int wiz_tls_write(wiz_tls_context* tlsContext, unsigned char* writebuf, unsigned int len)
{
	return mbedtls_ssl_write( tlsContext->ssl, writebuf, len );
}

/* SSL X509 verify */
unsigned int wiz_tls_x509_verify(wiz_tls_context* tlsContext)
{
	uint32_t flags;

	memset(tempBuf,0,1024);

#if defined(MBEDTLS_DEBUG_C)
	printf( "Verifying peer X.509 certificate..." );
#endif
	/* In real life, we probably want to bail out when ret != 0 */
	if( ( flags = mbedtls_ssl_get_verify_result( tlsContext->ssl ) ) != 0 )
	{
		mbedtls_x509_crt_verify_info( tempBuf, DEBUG_BUFFER_SIZE, "  ! ", flags );
#if defined(MBEDTLS_DEBUG_C)
		printf( "failed.\n\r" );
		printf( "%s\n\r", tempBuf );
#endif
		return flags;
	}
	else
	{
#if defined(MBEDTLS_DEBUG_C)
		printf( "ok\n\r" );
#endif
		return 0;
	}
}

/* ssl Close notify */
unsigned int wiz_tls_close_notify(wiz_tls_context* tlsContext)
{
	uint32_t rc;
	do rc = mbedtls_ssl_close_notify( tlsContext->ssl );
	while( rc == MBEDTLS_ERR_SSL_WANT_WRITE );
	//SSLDeinit(tlsContext);
	return rc;
}

//todo seperate verify function
