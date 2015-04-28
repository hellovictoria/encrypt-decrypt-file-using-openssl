#ifndef SAFEOPTS_H
#define SAFEOPTS_H

// encrypted & decrypted codes length 
extern int encrylen;
extern int decrylen;
// encrypt file path & decrypt file path
extern char * encry_path;
extern char * decry_path;
// public key file & private key file
extern char * pub_key;
extern char * priv_key;
// encrypt & decrypt file function
int encryptf(FILE * fp,char * pub_key,char * encry_path);
int decryptf(FILE * fp,char * priv_key,char * decry_path);
FILE * ecyfopen(const char * path, const char * mode);
FILE * dcyfopen(const char * path, const char * mode);
// print decrypted codes
int dcyprint(char * path,char * mode);

#endif
