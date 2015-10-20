#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>


#define GENERATE 2
#define ENCRYPT 1
#define DECRYPT 0

#define MAXBUFLEN 8


void showUsage(void);


char *encrypt(char *keyfileName, char *plaintextFileName);
char *decrypt(char *keyfileName, char *ciphertextFileName);

//Get the data from a file
void getData(char * filename, char *buffer);

//Get a single number from a file
unsigned long long getNumber(char * filename);

//Given 2 prime numbers generate keys
void generateKeys(unsigned long long p1, unsigned long long p2);

int main(int argc, char *argv[]){
    if (argc < 4){
        showUsage();
        return EXIT_FAILURE;
    }

    int isEncrypt = ENCRYPT; 

    if (strncmp("-d", argv[1], 2) == 0){
        printf("Decrypting\n");
        isEncrypt = DECRYPT;
    } else if (strncmp("-e", argv[1], 2) == 0){
        printf("Encrypting\n");
        isEncrypt = ENCRYPT;
    } else if (strncmp("-g", argv[1], 2) == 0){
        printf("Generating\n");
        isEncrypt = GENERATE;
    } else {
        showUsage();
        return EXIT_FAILURE;
    }

    char *msg;
     switch(isEncrypt){
        case ENCRYPT : 
            msg = encrypt(argv[2], argv[3]);
            break;
        case DECRYPT :
            msg = decrypt(argv[2], argv[3]);
            break;
        case GENERATE :{
                unsigned long long p1 = atoi(argv[2]);
                unsigned long long p2 = atoi(argv[3]);
                printf("Generating keys with %llu, %llu\n", p1, p2);
                generateKeys(atoi(argv[2]), atoi(argv[3])); //give the two numbers to the function
            }
            break;
        default :
            showUsage();
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


void showUsage(void){
        printf("Usage: -[de] keyfile [cipher|plain].txt\n");
}


//returns a pointer to a buffer that holds the file.
void getData(char * filename, char *buffer){
    FILE *file;
    file = fopen(filename, "r");
    if (!file){
        printf("error opening File %s\n", filename);
        fclose(file);
        exit(1);
    }

    unsigned long len = 0;
    if (fseek(file, 0L, SEEK_END) == 0) {
        /* Get the size of the file. */
        len = ftell(file);
    }else{
        printf("error seeking in File %s\n", filename);
        fclose(file);
        exit(1);
    }

    if (fseek(file, 0L, SEEK_SET) != 0) {
        printf("error seeking back in File %s\n", filename);
        fclose(file);
        exit(1);
    }

    printf("len == %lu\n", len);
    size_t newLen = fread(buffer, sizeof(char), MAXBUFLEN, file);
    len = (len < newLen) ? len : newLen;
    if (newLen == 0) {
        fputs("Error reading file", stderr);
        fclose(file);
        exit(1);
    } else{
        int i = 0;
        for (i = len; i < MAXBUFLEN; i ++){
            buffer[i] = '\0';
        }
    }
    fclose(file);
}

unsigned long long getNumber(char * filename){
    FILE *file;
    file = fopen(filename, "r");
    if (!file){
        printf("error opening File %s\n", filename);
        exit(1);
    }
    unsigned long long ret = 0;
    fscanf(file, "%llu", &ret);
    fclose(file);
    return ret;
}

void generateKeys(unsigned long long p1, unsigned long long p2){
    unsigned long long n = p1*p2;
    unsigned long long phiN = (p1-1)*(p2-1);
    unsigned long long publicExponent = 3;

    //Make sure the the public Exponent does not share a common factor with phi(n)
    while (phiN%publicExponent == 0) publicExponent += 2;

    unsigned long long privateKey = 0;
    unsigned long long k = 1;
    while ((k*phiN + 1)%publicExponent != 0){
        k++;
    }
    printf("found k == %llu\n", k);
    printf("found e == %llu\n", publicExponent);

    privateKey = (k*phiN + 1)/publicExponent;

    printf("Public Exponent == %llu\n", publicExponent);
    printf("Public Key == %llu\n", n);
    printf("Private Key == %llu\n", privateKey);

}

char *encrypt(char *keyfileName, char *plaintextFileName){

   
    FILE *keyfile; //Open the file with the keys
    unsigned long long plainfile = getNumber(plaintextFileName); //this is the plain text to be encoded
    printf("plain text as number == %llu\n", plainfile);
    unsigned long long publicExponent;
    unsigned long long publicKey;
    unsigned long long m;
    keyfile = fopen(keyfileName, "r");
    if (!keyfile){
        //Error
        printf("error opening keyFile %s\n", keyfileName);
        exit(1);
    }
    //Grab the exponent
    fscanf(keyfile, "%llu", &publicExponent);
    printf("Public Exponent is %llu\n", publicExponent);
    //Grab the public Key
    fscanf(keyfile, "%llu", &publicKey);
    printf("Public Key is %llu\n", publicKey);
    printf("plain text as number == %llu\n", plainfile%publicKey);

    m = plainfile%publicKey;
    for (int i = 1; i < publicExponent; ++i){
        m = (m*plainfile)%publicKey;
    }
    printf("cipher text is %llu\n", m);

    return NULL;
}
char *decrypt(char *keyfileName, char *ciphertextFileName){
    FILE *keyfile; //Open the file with the keys
    unsigned long long cipherfile = getNumber(ciphertextFileName); //this is the plain text to be encoded
    printf("text as number == %llu\n", cipherfile);
    unsigned long long publicKey;
    unsigned long long privateKey;
    unsigned long long m;
    keyfile = fopen(keyfileName, "r");
    if (!keyfile){
        //Error
        printf("error opening keyFile %s\n", keyfileName);
        exit(1);
    }
    //Grab the exponent
    fscanf(keyfile, "%llu", &publicKey);
    printf("Public Exponent is %llu\n", publicKey);
    //Grab the public Key
    fscanf(keyfile, "%llu", &privateKey);
    printf("Private Key is %llu\n", privateKey);
    printf("plain text as number == %llu\n", cipherfile%publicKey);

    m = cipherfile%publicKey;
    for (int i = 1; i < privateKey; ++i){
        m = (m*cipherfile)%publicKey;
    }
    printf("plain text is %llu\n", m);

    return NULL;
}



