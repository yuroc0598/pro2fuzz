
/*

Let OpenSSL talk to itself
code CC0 by Hanno Böck

To create self signed cert use:
  openssl req -x509 -newkey rsa:512 -keyout server.key -out server.pem -days 9999 -nodes -subj /CN=a/

*/

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdint.h>
#define MAP_SIZE 1 << 16
typedef uint8_t u8;
void err()
{
	ERR_print_errors_fp(stderr);
    exit(-1);
}

int main(int argc, char **argv)
{
	int r;
	u8 c, step;
	unsigned char buf[4096];
	const char ifi[]="/home/yuroc/workspace/protocol/tools/pro2fuzz/testcases/openssl/input";
	const char f_p1[]="/home/yuroc/workspace/protocol/tools/pro2fuzz/testcases/openssl/in/p1/packet";
	const char f_p2[]="/home/yuroc/workspace/protocol/tools/pro2fuzz/testcases/openssl/in/p2/packet";
	FILE *f;
	char fn[15];
	SSL_CTX *sctx, *cctx;
	SSL *server, *client;
	BIO *sinbio, *soutbio, *cinbio, *coutbio;
    
	/*check syntax*/
	if (argc!=1){
		printf("don't need any argv now\n");
		return -1;
	}

	step = 0; // this is fake, since step will be overwriten using AFL anyway, make sure it still works when running without AFL
#ifdef __AFL_HAVE_MANUAL_CONTROL
    int shmid = atoi(getenv("__AFL_SHM_ID"));
    u8* shmptr = shmat(shmid,NULL,0);
    step = shmptr[MAP_SIZE];
#endif

	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

    printf("at least we are here\n");
	if (!(sctx = SSL_CTX_new(TLSv1_method())))
		err();
    

	if (!SSL_CTX_use_certificate_file(sctx, "/home/yuroc/workspace/protocol/tools/pro2fuzz/testcases/openssl/server.pem", SSL_FILETYPE_PEM))
		err();

	if (!SSL_CTX_use_PrivateKey_file(sctx, "/home/yuroc/workspace/protocol/tools/pro2fuzz/testcases/openssl/server.key", SSL_FILETYPE_PEM))
		err();

	if (!(server = SSL_new(sctx)))
		err();


	sinbio = BIO_new(BIO_s_mem());
	soutbio = BIO_new(BIO_s_mem());
	SSL_set_bio(server, sinbio, soutbio);
	SSL_set_accept_state(server);

	if (!(cctx = SSL_CTX_new(TLSv1_method())))
		err();
	if (!(client = SSL_new(cctx)))
		err();

	cinbio = BIO_new(BIO_s_mem());
	coutbio = BIO_new(BIO_s_mem());
	SSL_set_bio(client, cinbio, coutbio);
	SSL_set_connect_state(client);


	c = 0;
	do {

		printf("current c is %d\n",c);
		r = SSL_do_handshake(client);
		if (r == -1) {
			if ((SSL_get_error(client, r) != SSL_ERROR_WANT_WRITE)
			    && (SSL_get_error(client, r) !=
				SSL_ERROR_WANT_READ)){
	            ERR_print_errors_fp(stderr);
                break;
            }
		}

		r = BIO_read(coutbio, buf, 4096);
		if (r == -1){
            ERR_print_errors_fp(stderr);
            break;
        }
		c++;
        if(c==1){
            f = fopen(f_p1,"wb");
    		fwrite(buf,1,r,f);
	    	fclose(f);
        }
		if (c == step) {
        /*
        printf("we found step at client\n");
		f = fopen(f_p1,"wb");
		fwrite(buf,1,r,f);
		fclose(f);
        */

#ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
#endif
	    f = fopen(ifi, "rb");
    	r = fread(buf, 1, 4096, f);
    	fclose(f);

		} else if (step == 0) {
			sprintf(fn, "packet-%i", c);
			f = fopen(fn, "wb");
			fwrite(buf, 1, r, f);
            fclose(f);
		}
		BIO_write(sinbio, buf, r);

		r = SSL_do_handshake(server);
		if (r == -1) {
			if ((SSL_get_error(server, r) != SSL_ERROR_WANT_WRITE)
			    && (SSL_get_error(server, r) !=
				SSL_ERROR_WANT_READ)){
				ERR_print_errors_fp(stderr);
                break;
            }

		}

		r = BIO_read(soutbio, buf, 4096);
		if (r == -1){
		    ERR_print_errors_fp(stderr);
            break;
        }
		c++;
        if(c==2){
       	    f = fopen(f_p2,"wb");
    		fwrite(buf,1,r,f);
	    	fclose(f);
        }
		if (c == step) {
        printf("we found step at server\n");
#ifdef __AFL_HAVE_MANUAL_CONTROL
			__AFL_INIT();
#endif
			f = fopen(ifi, "rb");
			r = fread(buf, 1, 4096, f);
			fclose(f);
		} else if (step == 0) {
			sprintf(fn, "packet-%i", c);
			f = fopen(fn, "wb");
			fwrite(buf, 1, r, f);
            fclose(f);
		}
		BIO_write(cinbio, buf, r);
	
		printf("server state: %s / %s\n", SSL_state_string(server),
		       SSL_state_string_long(server));
		printf("client state: %s / %s\n", SSL_state_string(client),
		       SSL_state_string_long(client));
	} while ((!SSL_is_init_finished(server)
		  || !SSL_is_init_finished(client)) && c < 10);
    
#ifdef __AFL_HAVE_MANUAL_CONTROL
    printf("handshake finished, done or fail, the value of c is %d\n",c);
    shmptr[MAP_SIZE] = c;
    shmdt(shmptr);
#endif
	return 0;
}
