# encrypt-decrypt-file-using-openssl
encrypt &amp; decrypt file using openssl

生成私钥：
openssl genrsa -out private.pem 2048

生成公钥：
openssl rsa -in private.pem -pubout > public.pem

在Linux下的编译：gcc saferead.c -lcrypto -o saferead.o
