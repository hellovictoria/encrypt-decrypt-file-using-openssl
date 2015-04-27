#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int encrylen;

int encryptf(FILE * fp)
{
        //read file to str pointer
        char * plain;
//        plain=readf2str(fp);

        int fsize;
        fseek(fp,0,SEEK_END);
        fsize=ftell(fp);
        fseek(fp,0,SEEK_SET);
        plain=(char *)malloc(fsize * sizeof(char));
        fread(plain,sizeof(char),fsize,fp);
        printf("file size is:\n%d\n",fsize);
        printf("Source is:\n%s\n",plain);
        printf("strlen is: \n%d\n",strlen(plain));
        fclose(fp);

        // used to store encrypted file
        char encrypted[1024];

        // public key file & private key file
        const char* pub_key="public.pem";

        // -------------------------------------------------------
        // use public key to encrypt plain text
        // -------------------------------------------------------

        // open public key file
        FILE* pub_fp=fopen(pub_key,"r");
        if(pub_fp==NULL){
                printf("failed to open pub_key file %s!\n", pub_key);
                return -1;
         }

        // read public key from file
        RSA* rsa1=PEM_read_RSA_PUBKEY(pub_fp, NULL, NULL, NULL);
        if(rsa1==NULL){
                printf("unable to read public key!\n");
                return -1;
        }

        if(strlen(plain)>=RSA_size(rsa1)-41){
                printf("failed to encrypt\n");
                return -1;
        }
        fclose(pub_fp);

        // use public key to encrypt 
        encrylen=RSA_public_encrypt(fsize, plain, encrypted, rsa1, RSA_PKCS1_PADDING);
        if(encrylen==-1 ){
                printf("failed to encrypt\n");
                return -1;
        }

        printf("in encryptf func, encrylen is:\n%d\n",encrylen);

        // output encrypted data to original file
        FILE* ffp=fopen("midata","w");
        if(ffp){
             fwrite(encrypted,encrylen,1,ffp);
             fclose(ffp);
        }

        printf("in encryptf func, encrypted in hexadecimal\n%x\n\n",encrypted);
}

int decryptf(FILE * fp)
{
        //read file to str pointer
	    char * encrypted;
//        encrypted=readf2str(fp);

        encrypted=(char *)malloc(encrylen * sizeof(char));
        fread(encrypted,encrylen,1,fp);
	    printf("in decryptf func, read encrypted file in hexadecimal:\n%x\n",encrypted);
        fclose(fp);

        char decrypted[1024];

        // public key file & private key file
        const char* priv_key="private.pem";

    	// -------------------------------------------------------
    	// use private key to decrypt the encrypted file
    	// -------------------------------------------------------
    	// out private key file 
    	FILE* priv_fp=fopen(priv_key,"r");
    	if(priv_fp==NULL){
        	printf("failed to open priv_key file %s!\n", priv_key);
        	return -1;
    	}
   

    	// read private key from private key file
    	RSA *rsa2 = PEM_read_RSAPrivateKey(priv_fp, NULL, NULL, NULL);
    	if(rsa2==NULL){
        	printf("unable to read private key!\n");
        	return -1; 
    	}
    
    	// use private key to decrypt encrypted data
    	int decrylen=RSA_private_decrypt(encrylen, encrypted, decrypted, rsa2, RSA_PKCS1_PADDING);
    	if(decrylen==-1){
        	printf("failed to decrypt!\n");
        	return -1;
    	}

    	fclose(priv_fp);
        
        printf("in decryptf func, decrylen is:\n%d\n",decrylen);

    	// output decrypted plain text
    	printf("in decryptf func, decrypted in hexadecimal \n%x\n",decrypted);
        printf("in decryptf func, decrypted string is \n%s\n",decrypted);

        // output decrypted data to a new file
        FILE* ffp=fopen("a_decrypted","w");
        if(ffp){
             fwrite(decrypted,decrylen,1,ffp);
             fclose(ffp);
        }
}

int main()
{
        FILE * encry_fp;
        FILE * decry_fp;

        encry_fp=fopen("a","r");
        encryptf(encry_fp);

        decry_fp=fopen("midata","r");
        decryptf(decry_fp);
        return 1;
}


char * readf2str(FILE * fp)
{
        int fsize;
        char * fstr;

        //get file size
        fseek(fp,0,SEEK_END);
        fsize=ftell(fp);
        printf("file size\n %d\n",fsize);

        fstr=(char *)malloc(fsize * sizeof(char));
        // read file to string pointer
        fseek(fp,0,SEEK_SET);
        fread(fstr,sizeof(char),fsize,fp);
        fclose(fp);
        printf("file content\n %s\n",fstr);
        return fstr;
}
