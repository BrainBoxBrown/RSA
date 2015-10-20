#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#define TEST_LIMIT 10000

void showUsage(void);

typedef struct _keys{

    unsigned long long publicExponent;
    unsigned long long publicKey;
    unsigned long long privateKey;
}keySet;



//This is the same for encrypting and decrypting
//the difference is the exponent
unsigned long long crypt(unsigned long long exponent,
    unsigned long long publicKey,
    unsigned long long plaintext);

unsigned long long hack(unsigned long long exponent,
    unsigned long long publicKey,
    unsigned long long ciphertext);



//This calls generateKeysWithExponent with a default exp of 3
keySet generateKeys(unsigned long long p1,
    unsigned long long p2);

//Given 2 prime numbers and an exponent generate the keys
//if the exponent is shit it will make a better one 
keySet generateKeysWithExponent(unsigned long long p1,
    unsigned long long p2,
    unsigned long long exponent);

void test(unsigned long long p1, unsigned long long p2);

int main(int argc, char *argv[]){
    if (argc < 4 || strlen(argv[1]) < 2 || argv[1][0] != '-'){
        showUsage();
        return EXIT_FAILURE;
    }
    switch(argv[1][1]){
        case 'c' : {
                // ./rsa -e exponent pubKey plaintext
                if (argc < 5){
                    showUsage();
                    return EXIT_FAILURE;
                }
                unsigned long long msg = 0;
                unsigned long long exponent = atoi(argv[2]);
                unsigned long long publicKey = atoi(argv[3]);
                unsigned long long plaintext = atoi(argv[4]);
                msg = crypt(exponent, publicKey, plaintext); 
                printf("Result: %llu\n", msg);
            }
            break;

        case 'h' : {
                // ./rsa -e exponent pubKey plaintext
                if (argc < 5){
                    showUsage();
                    return EXIT_FAILURE;
                }
                unsigned long long msg = 0;
                unsigned long long exponent = atoi(argv[2]);
                unsigned long long publicKey = atoi(argv[3]);
                unsigned long long plaintext = atoi(argv[4]);
                msg = hack(exponent, publicKey, plaintext); 
                printf("Result: %llu\n", msg);
            }
            break;


        case 't' : {
                // ./rsa -g  p1 p2
                unsigned long long p1 = atoi(argv[2]);
                unsigned long long p2 = atoi(argv[3]);
                test(atoi(argv[2]), atoi(argv[3])); //give the two numbers to the function
            }
            break;
        case 'g' :{
                // ./rsa -g  p1 p2
                unsigned long long p1 = atoi(argv[2]);
                unsigned long long p2 = atoi(argv[3]);
                printf("Generating keys with %llu, %llu\n", p1, p2);
                keySet keys = generateKeys(atoi(argv[2]), atoi(argv[3])); //give the two numbers to the function

                printf("Public Exponent == %llu\n", keys.publicExponent);
                printf("Public Key == %llu\n", keys.publicKey);
                printf("Private Key == %llu\n", keys.privateKey);
            }
            break;
        default :
            showUsage();
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
Generating keys with 571, 577
Public Exponent == 7
Public Key == 329467
Private Key == 46903
*/
void test(unsigned long long p1, unsigned long long p2){
    // unsigned long long publicExponent = 5;
    // unsigned long long publicKey = 10972771937;
    // unsigned long long privateKey = 8778049949;
    keySet testSet = generateKeys(p1, p2);

    printf("Non-Hacks\n");
    // fflush(stdout);
    for (int i = 10; i < TEST_LIMIT; ++i)
    {
        //encode and then decode i and check it's the same
        // printf("doing %d\n", i);
        unsigned long long v1 = crypt(testSet.publicExponent, testSet.publicKey, i);
        // printf("decry %d\n", i);
        assert(crypt(testSet.privateKey, testSet.publicKey, v1) == i);
    }
    printf("Hacks\n");
    for (int i = 10; i < TEST_LIMIT; ++i)
    {
        //encode and then decode i and check it's the same
        // printf("Hdoing %d\n", i);
        unsigned long long v1 = crypt(testSet.publicExponent, testSet.publicKey, i);
        // printf("Hdecry %d\n", i);
        assert(hack(testSet.publicExponent, testSet.publicKey, v1) == i);
    }

 

    printf("All tests passed\n");

}


void showUsage(void){
        printf("Usage: -c [exp|privKey] publicKey [plain|cipher]\n");
        printf("Usage: -h exp publicKey cipher\n");
        printf("Usage: -g p1 p2\n");
}

keySet generateKeysWithExponent(unsigned long long p1,
    unsigned long long p2,
    unsigned long long exponent){

    unsigned long long n = p1*p2;
    unsigned long long phiN = (p1-1)*(p2-1);
    unsigned long long publicExponent = exponent;

    //Make sure the the public Exponent does not share a common factor with phi(n)
    while (phiN%publicExponent == 0) publicExponent += 2;

    unsigned long long privateKey = 0;
    unsigned long long k = 1;

    //find a value of k that works
    while ((k*phiN + 1)%publicExponent != 0){
        k++;
        //in case we get stuck with at bad pubExp
        if (k > 100){
            k = 1;
            publicExponent += 2;
            while (phiN%publicExponent == 0) publicExponent += 2;
        }
    }

    privateKey = (k*phiN + 1)/publicExponent;

    keySet ret;
    ret.publicExponent = publicExponent;
    ret.publicKey = n;
    ret.privateKey = privateKey;

    return ret;
}

//We only want to pass in an exponent when cracking
keySet generateKeys(unsigned long long p1, unsigned long long p2){
    return generateKeysWithExponent(p1, p2, 3);
}


unsigned long long crypt(unsigned long long exponent,
    unsigned long long mod,
    unsigned long long input){

    unsigned long long c = 1;

    //It's time for some maths
    //fast modular exponentiation

    //make an array with the values of m^x for x = powers of 2
    unsigned long long powMods[64];
    powMods[0] = input%mod;

    if ((exponent & (1)) != 0){
        c *= powMods[0];
    }

    for (int i = 1; i < 64; i++){

        //if 000100000...00 is greater than exponent then stop
        if (exponent < (1 << i)){
            break;
        }
        //This is m^(2^i)
        powMods[i] = (powMods[i-1]*powMods[i-1])%mod;
        //if the exponent is divisable by 2^i
        if ((exponent & (1 << i)) != 0){
            c = (c*powMods[i])%mod;
        }
    }

    return c;
}

unsigned long long hack(unsigned long long exponent,
    unsigned long long publicKey,
    unsigned long long ciphertext){

    unsigned long long p1;
    unsigned long long p2;
    unsigned long long msg;

    //First crack the public Key
    unsigned long long i;
    for (i = 2; i < sqrtl(publicKey) + 1; i++){
        if ((publicKey%i) == 0){
            p1 = i;
            p2 = publicKey/p1;
            break;
        }
    }

    keySet hackedKeys = generateKeysWithExponent(p1, p2, exponent);

    msg = crypt(hackedKeys.privateKey, hackedKeys.publicKey, ciphertext);

    return msg;

}




