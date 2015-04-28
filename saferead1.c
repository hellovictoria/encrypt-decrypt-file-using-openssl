#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
// encrypted & decrypted codes length 
int encrylen;
int decrylen;
// encrypt file path & decrypt file path
char * encry_path="encrydata";
char * decry_path="decrydata";
// public key file & private key file
char * pub_key="public.pem";
char * priv_key="private.pem";
// encrypt & decrypt file function
int encryptf(FILE * fp,char * pub_key,char * encry_path);
int decryptf(FILE * fp,char * priv_key,char * decry_path);
FILE * ecyfopen(const char * path, const char * mode);
FILE * dcyfopen(const char * path, const char * mode);
// print decrypted codes
int myprint(char * path,char * mode);

FILE * ecyfopen(const char * path, const char * mode)
{
        FILE * fp_src;
        fp_src=fopen(path,"r");
        // encrypt source file & store the encrypted codes into a new file
        encryptf(fp_src,pub_key,encry_path);
        // open encrypted file, & return the file pointer
        FILE* encyfp=fopen(encry_path,mode);
        return encyfp;
}

FILE * dcyfopen(const char * path, const char * mode)
{
        FILE * fp_encry;
        fp_encry=fopen(encry_path,"r");
        // decrypt encrypted file & store the decrypted file into a new file
        decryptf(fp_encry,priv_key,decry_path);
        //open decrypted file, & return the file pointer
        FILE* decryfp=fopen(decry_path,mode);
        return decryfp;
}

int encryptf(FILE * fp,char * pub_key,char * encry_path)
{
        //read file to str pointer
        char * plain;
        int fsize;
        fseek(fp,0,SEEK_END);
        fsize=ftell(fp);
        fseek(fp,0,SEEK_SET);
        plain=(char *)malloc(fsize * sizeof(char));
        fread(plain,sizeof(char),fsize,fp);
//        printf("file size is:\n%d\n",fsize);
//        printf("Source is:\n%s\n",plain);
//        printf("strlen is: \n%d\n",strlen(plain));
        fclose(fp);

        // used to store encrypted file
        char encrypted[1024];

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

//        printf("in encryptf func, encrylen is:\n%d\n",encrylen);

        // output encrypted data to original file
        FILE* ffp=fopen(encry_path,"w");
        if(ffp){
             fwrite(encrypted,encrylen,1,ffp);
             fclose(ffp);
        }
}

int decryptf(FILE * fp,char * priv_key,char * decry_path)
{
        //read file to str pointer
	    char * encrypted;
        encrypted=(char *)malloc(encrylen * sizeof(char));
        fread(encrypted,encrylen,1,fp);
        fclose(fp);

        char decrypted[1024];

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
    	decrylen=RSA_private_decrypt(encrylen, encrypted, decrypted, rsa2, RSA_PKCS1_PADDING);
    	if(decrylen==-1){
        	printf("failed to decrypt!\n");
        	return -1;
    	}

    	fclose(priv_fp);
        
//        printf("in decryptf func, decrylen is:\n%d\n",decrylen);

    	// output decrypted plain text
//        printf("in decryptf func, decrypted string is \n%s\n",decrypted);

        // output decrypted data to a new file
        FILE* ffp=fopen(decry_path,"w");
        if(ffp){
             fwrite(decrypted,decrylen,1,ffp);
             fclose(ffp);
        }
}

int myprint(char * path,char * mode)
{
        FILE * decry_fp;
        char * dcypted_code;
        decry_fp=dcyfopen(path,mode);
        dcypted_code=(char *)malloc(decrylen * sizeof(char));
        fread(dcypted_code,decrylen,1,decry_fp);
        printf("output decrypted code:\n%s\n",dcypted_code);
        return 1;
}

int main()
{
        FILE * encry_fp;
        FILE * decry_fp;
        char * ecypted_code;
        char * dcypted_code;

        encry_fp=ecyfopen("a","r");
        ecypted_code=(char *)malloc(encrylen * sizeof(char));
        fread(ecypted_code,encrylen,1,encry_fp);
        printf("output encrypted code:\n%s\n",ecypted_code);

        myprint("a","r");
        return 1;
}


