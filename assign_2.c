#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, size_t, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, size_t, unsigned char *, size_t *, int);
int verify_cmac(unsigned char *, unsigned char *);

/* TODO Declare your function prototypes here... */
void err(void);
int readFromFile(char *input_file, unsigned char **plaintext);
void writeToFile(char *out_file, unsigned char *buffer, int length);
int concat_CMAC_cipher(unsigned char *ciphertext, int ciphertext_len, 
					unsigned char *cmac, int cmac_len, unsigned char *conctext);
/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;
	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}

/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;
	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * [Task A] Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, size_t key_len, unsigned char *iv,
    int bit_mode)
{
	/* first, need to initialize: cipher, md, salt, password_length
	* to call the EVP_BytesToKey function */

	// set cipher for both 128 and 256 bit_modes 
	const EVP_CIPHER *cipher;
	if (bit_mode == 128){
		cipher = EVP_get_cipherbyname("aes-128-ecb");	
	}else if (bit_mode == 256){
		cipher = EVP_get_cipherbyname("aes-256-ecb");	
	}
	// set message digest method 
	const EVP_MD *md = EVP_get_digestbyname("SHA1");
	// set password_length 
	int pw_len = strlen((const char *) password);
	// set counts equal to 1 and derive key
	if(!EVP_BytesToKey(cipher,md,NULL,(const unsigned char*)password,pw_len,1,key,iv)){
		printf("The key was not derived.\n");
	}
	printf("Key:\n");
	print_hex(key, key_len);
}


/*
 * [Task B] Encrypts the data
 */
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *ciphertext, int bit_mode)
{
	// declare ECB mode for 128 or 256 bit
	const EVP_CIPHER *mode;
	if (bit_mode == 128){
		mode = EVP_aes_128_ecb();
	}else if (bit_mode == 256){
		mode = EVP_aes_256_ecb();
	}
	EVP_CIPHER_CTX *ctx;
    //length of encrypted msg provided by the EVP_EncryptUpdate
    int len;

	int ciphertext_len = 0;

	// Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        err();
	}
	// Initialise the encryption operation
	if (EVP_EncryptInit_ex(ctx, mode,NULL, key, NULL) != 1)
		err();
	// Message to be encrypted
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
		err();
	ciphertext_len = len; 	//init ciphertext length
	// Further ciphertext bytes may be written - add padding
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
		err();
	// Update ciphertext length
	ciphertext_len += len;

	// Clean up
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/*
 * [Task C] Decrypts the data and returns the plaintext size
 * -reverse of Task B-
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *plaintext, int bit_mode)
{
	int plaintext_len;
	plaintext_len = 0;

	// declare ECB mode for 128 or 256 bit
	const EVP_CIPHER *mode;
	if (bit_mode == 128){
		mode = EVP_aes_128_ecb();
	}else if (bit_mode == 256){
		mode = EVP_aes_256_ecb();
	}
	EVP_CIPHER_CTX *ctx;
    int len;		//length of encrypted msg provided by the EVP_EncryptUpdate

	// Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        err();
	}
	// Initialise the encryption operation
	if (EVP_DecryptInit_ex(ctx, mode,NULL, key, NULL) != 1)
		err();
	// Message to be encrypted
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
		err();
	plaintext_len = len; 	//init ciphertext length
	// Further ciphertext bytes may be written - add padding
	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
		err();
	// Update ciphertext length
	plaintext_len += len;

	// Clean up
    EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}


/*
 * [Task D] Generates a CMAC 
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, size_t key_len,
    	unsigned char *cmac, size_t *cmac_len, int bit_mode)
{
	// declare ECB mode for 128 or 256 bit
	const EVP_CIPHER *cipher_mode;
	if (bit_mode == 128){
		cipher_mode = EVP_aes_128_ecb();
	}else if (bit_mode == 256){
		cipher_mode = EVP_aes_256_ecb();
	}

	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, key, key_len, cipher_mode, NULL);
	CMAC_Update(ctx, data, data_len);
	CMAC_Final(ctx, cmac, cmac_len);
	
	// Clean up
	CMAC_CTX_free(ctx);
}

/*
 * [Task E] Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;
	verify = 0;
	if (strcmp((const char*)cmac1, (const char *)cmac2) == 0){
		verify = 1;	
	}
	return verify;
}

/* TODO Develop your functions here... */

/* Error handling */
void
err(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}
/* reads data from file, 
* stores them in a buffer and returns it's length
* ! memory allocation of buffer is declared here 
*  	because here we have access to the desired sizeofbuffer
* 	which is the filesize obtained by ftell()
*	in main() we can not know that length
*/
int 
readFromFile(char *in_file, unsigned char **buffer)
{
	int fsize = 0;
	FILE *fptr = fopen((const char *)in_file, "r");
	if (fptr == NULL)
		printf("NULL data in file: %s", in_file);

	// access the EOF to declare the size of the file
	fseek(fptr, 0, SEEK_END);
	fsize = ftell(fptr);
	// +1 for \0
	*buffer =(unsigned char *) malloc(sizeof(int)*(fsize + 1)); 
	//return at the begining of the file
	fseek(fptr, 0, SEEK_SET); 
	fread(*buffer, fsize, 1, fptr);
	fclose(fptr);

	/* if buffer not freed, it keeps it's values
	* so we can "return" both the buffer and it's length !
	*/
	return fsize;
}
/* 
* writes data from the given buffer[length] to the given output file 
*/
void 
writeToFile(char *out_file, unsigned char *buffer, int length)
{
	FILE *fptr = fopen((const char *)out_file, "w");
	if (fptr == NULL){
		printf("Error opening file");
		err();
	}
	// if (fwrite(buffer, length, 1, fptr) !=1)
	// 	err()	;
	
	fprintf(fptr, "%s", buffer);
	fclose(fptr);
}
/* Concatenates two buffers into one.
* Used to concatenate CMAC and ciphertext for CMAC signing
*/
int 
concat_CMAC_cipher(unsigned char *ciphertext, int ciphertext_len,
	 unsigned char *cmac, int cmac_len, unsigned char *conctext)
{
	memcpy(conctext, ciphertext, ciphertext_len);		//first copy ciphertext
	memcpy(conctext + ciphertext_len, cmac, cmac_len);	// then add cmac
	int conctext_len = strlen((const char *)conctext);
	return conctext_len;
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;

	/* Init my arguments */
	unsigned char *plaintext = NULL;
	unsigned char *ciphertext = NULL;
	unsigned char *conctext = NULL;
	int plaintext_len = -1;
	int ciphertext_len = -1;
	int conctext_len = -1;

	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	/* TODO Develop the logic of your tool here... */

	/* Initialize the library */

	/* Keygen from password */
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	size_t key_len = bit_mode/8; // 128bits-> 16Bytes, 256bits->32Bytes
	keygen(password, key, key_len, iv, bit_mode);

	/* Operate on the data according to the mode */
	
	/* encrypt */
	if (op_mode == 0)
	{
		/* read input file for encryption and store it in plaintext */
		plaintext_len = readFromFile(input_file, &plaintext);
		// having the plaintext length, allocate memory for ciphertext
		ciphertext = (unsigned char *)malloc(sizeof(int)*(plaintext_len + 1));
		// encrypt the plaintext
		ciphertext_len = encrypt(plaintext, plaintext_len, key, ciphertext, bit_mode);
		// print plaintext and ciphertext
		printf("Message to encrypt (plaintext): \n");
		print_string(plaintext, plaintext_len);
		printf("Encrypted message (ciphertext): \n");
		print_hex(ciphertext, ciphertext_len);
		// store ciphertext to an output file
		writeToFile(output_file, ciphertext, ciphertext_len);
		// free buffers here and not inside the functions in order to use them above 
		free(plaintext);
		free(ciphertext);
	}
		/* decrypt */
	else if (op_mode == 1)
	{
		// read input file that needs to be decryptedCMAC and  and store it in ciphertext 
		ciphertext_len = readFromFile(input_file, &ciphertext);
		// having the ciphertext length, allocate memory for plaintext
		plaintext = (unsigned char *)malloc(sizeof(int)*(ciphertext_len + 1));
		// decrypt the ciphertext
		plaintext_len = decrypt(ciphertext, ciphertext_len, key, plaintext, bit_mode);
		// print ciphertext and plaintext
		printf("Message to decrypt (ciphertext): \n");
		print_hex(ciphertext, ciphertext_len);
		printf("Decrypted message (plaintext): \n");
		print_string(plaintext, plaintext_len);
		// store ciphertext to an output file
		writeToFile(output_file, plaintext, plaintext_len);
		// free buffers
		free(plaintext);
		free(ciphertext);
	}
		/* sign */
	else if (op_mode == 2)
	{
		/* read input file for encryption and store it in plaintext */
		plaintext_len = readFromFile(input_file, &plaintext);
		// having the plaintext length, allocate memory for ciphertext
		ciphertext = (unsigned char *)malloc(sizeof(int)*(plaintext_len + 1));
		// encrypt the plaintext
		ciphertext_len = encrypt(plaintext, plaintext_len, key, ciphertext, bit_mode);
		// cmac and cmac_len declared in main so they can be used later for the concat
		unsigned char cmac[BLOCK_SIZE] = {0};
		size_t cmac_len ; // 128bits-> 16Bytes, 256bits->32Bytes
		gen_cmac(plaintext, plaintext_len, key, key_len, cmac, &cmac_len, bit_mode);
		printf("CMAC: \n");
		print_hex(cmac, cmac_len);
		// concatenate ciphertext and CMAC and store it to ouput file
		conctext = (unsigned char *)malloc(sizeof(int)*(ciphertext_len + cmac_len));
		conctext_len = concat_CMAC_cipher(ciphertext, ciphertext_len, cmac, cmac_len, conctext);
		writeToFile(output_file, conctext, conctext_len);
		// free buffers
		free(plaintext);
		free(ciphertext);
		free(conctext);
	}
		/* verify */
	else if (op_mode == 3)
	{
		//read file and obtain concatenated text
		conctext_len = readFromFile(input_file, &conctext);
		//separate ciphertext from cmac1
		unsigned char cmac1[BLOCK_SIZE] = {0};
		size_t cmac1_len = bit_mode/8 ; // 128bits-> 16Bytes, 256bits->32Bytes
		//cmac length is known, so sub it from the input to get the cipher_length
		ciphertext_len = conctext_len - cmac1_len;
		ciphertext = (unsigned char *)malloc(sizeof(int)*ciphertext_len);
		memcpy(ciphertext, conctext, ciphertext_len);
		memcpy(cmac1,conctext + ciphertext_len, cmac1_len);
		//decrypt ciphertext and obtain plaitext
		plaintext = (unsigned char *)malloc(sizeof(int)*(ciphertext_len + 1));
		plaintext_len = decrypt(ciphertext, ciphertext_len, key, plaintext, bit_mode);
		//generate cmac2 using the plaintext decrypted above
		unsigned char cmac2[BLOCK_SIZE] = {0};
		size_t cmac2_len;
		gen_cmac(plaintext, plaintext_len, key, key_len, cmac2, &cmac2_len, bit_mode);
		//print cmac1 and cmac 2
		printf("CMAC1: \n");
		print_hex(cmac1, cmac1_len);
		printf("CMAC2: \n");
		print_hex(cmac2, cmac2_len);
		// compare cmac1 and cmac2 for verification
		if(verify_cmac(cmac1, cmac2) == 1)
		{
			//if true -> store plaintext to output_file
			printf("[TRUE] Verification succed.\n");
			writeToFile(output_file, plaintext, plaintext_len);
		}else
		{
			//if false-> return false
			printf("[FALSE] Verification failed. CMACs do not match.\n");
		}
		//free buffers
		free(plaintext);
		free(ciphertext);
		free(conctext);		
	}
	
	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	/* END */
	return 0;
}
