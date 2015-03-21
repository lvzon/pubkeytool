/* pubkeytool.c */
/* (c)2013-2014, Levien van Zon (levien@zonnetjes.net) */
/* This software is public domain. */

#include <tomcrypt.h>
#include <tfm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>

#ifndef TRUE
	#define TRUE 1
	#define FALSE 0
#endif


#define VL_FATAL		1
#define VL_ERROR		2
#define VL_WARNING		3
#define VL_NORMAL		4
#define VL_VERBOSE		5
#define VL_DEBUG		6


#ifdef DEBUG
	#define VERBOSITY_LEVEL	VL_DEBUG
#else
	#define VERBOSITY_LEVEL	VL_NORMAL
#endif

#define report_output stderr

int report_verbosity = VERBOSITY_LEVEL;

#define report(level, format, args...) { \
	if (level <= report_verbosity && report_output) { \
		if (level == VL_WARNING) \
			fprintf(report_output, "WARNING "); \
		else if (level == VL_ERROR) \
			fprintf(report_output, "ERROR "); \
		else if (level == VL_FATAL) \
			fprintf(report_output, "FATAL ERROR "); \
		fprintf(report_output, format, ##args); \
		fflush(report_output); \
	} \
}

typedef struct state_struct {
	
	FILE	*input, 
			*output,
			*keyfile,
			*sigfile,
			*hashfile;
	
	int		algorithm;
	
	unsigned long 	keybits,
					keybytes,
					hashbytes;
	
	int		in_keyformat,
			out_keyformat,
			in_pem,
			out_pem,
			in_encoding,
			out_encoding;
	
	char	*hash_name,
			*prng_name;
			
	prng_state	*prng_state,
				prng_state_instance;
	
	int		hash_idx,
			prng_idx;
			
	rsa_key	*rsa_key,
			rsa_key_instance;
	int		rsa_saltlen;
	
	ecc_key	*ecc_key,
			ecc_key_instance;
	
	dsa_key	*dsa_key,
			dsa_key_instance;
	int		dsa_group_size,
			dsa_modulus_size;
			
	unsigned char hashbuf[MAXBLOCKSIZE];
	unsigned char sigbuf[1024];
	unsigned char keybuf[2400];
	
	unsigned long hashlen, siglen, keylen;
		
} pkt_state;

// Prototypes

void pkt_usage ();
int pkt_match_tail (char *string, char *match);
FILE * pkt_open_input (char **argv, int argc, int idx);
FILE * pkt_open_infile (char *infile);
FILE * pkt_open_output (char **argv, int argc, int idx);
FILE * pkt_open_outfile (char *outfile);
void pkt_close_input (FILE *input);
void pkt_close_output (FILE *output);
int pkt_register_hashes ();
int pkt_register_prngs ();
void pkt_register_maths ();
long pkt_base64_encode (unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen);
long pkt_base64_decode (unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen);
long pkt_gen_key (pkt_state *state);
long pkt_sign_hash (pkt_state *state, FILE *hash_in, FILE *sig_out);
long pkt_verify_hash (pkt_state *state, FILE *file_in, FILE *sig_in);
long pkt_read_keyfile (pkt_state *state, FILE *keyfile);
long pkt_write_key (pkt_state *state, char *keyfile, int keytype);
long pkt_read_buffer (pkt_state *state, FILE *in, unsigned char *buf, unsigned long *len, int encoding);
long pkt_write_buffer (pkt_state *state, FILE *out, unsigned char *buf, unsigned long len, int encoding);
long pkt_hash_buffer (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen);
long pkt_hash_file (pkt_state *state, char *file, unsigned char *outbuf, unsigned long *outlen);
long pkt_hash_filehandle (pkt_state *state, FILE *file, unsigned char *outbuf, unsigned long *outlen);
int pkt_rsa_key_gen (pkt_state *state);
int pkt_rsa_import_key (pkt_state *state, unsigned char *inbuf, unsigned long inlen);
long pkt_rsa_export_public_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen);
long pkt_rsa_export_private_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen);
int pkt_rsa_encrypt_buffer (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen);
int pkt_rsa_decrypt_buffer (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen);
int pkt_rsa_sign_hash (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen);
int pkt_rsa_verify_hash (pkt_state *state, unsigned char *signature, unsigned long siglen, unsigned char *hash, unsigned long hashlen);
int pkt_ecc_key_gen (pkt_state *state);
int pkt_ecc_import_key (pkt_state *state, unsigned char *inbuf, unsigned long inlen);
long pkt_ecc_export_public_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen);
long pkt_ecc_export_private_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen);
int pkt_ecc_sign_hash (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen);
int pkt_ecc_verify_hash (pkt_state *state, unsigned char *signature, unsigned long siglen, unsigned char *hash, unsigned long hashlen);
int pkt_dsa_key_gen (pkt_state *state);
int pkt_dsa_import_key (pkt_state *state, unsigned char *inbuf, unsigned long inlen);
long pkt_dsa_export_public_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen);
long pkt_dsa_export_private_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen);
int pkt_dsa_sign_hash (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen);
int pkt_dsa_verify_hash (pkt_state *state, unsigned char *signature, unsigned long siglen, unsigned char *hash, unsigned long hashlen);


// Global state

pkt_state state;

// Defines

#define PKT_FORMAT_BINARY 	1
#define PKT_FORMAT_HEX 		2
#define PKT_FORMAT_BASE64 	3

#define PKT_ALGORITHM_RSA 	1
#define PKT_ALGORITHM_ECC 	2
#define PKT_ALGORITHM_DSA 	3

#define PKT_KEY_PRIVATE 	1
#define PKT_KEY_PUBLIC 		2

#define PKT_RSA_KEY_PCKS1		1
#define PKT_ECC_KEY_TOMCRYPT	2
#define PKT_ECC_KEY_ANSI_X963	3
#define PKT_DSA_KEY_TOMCRYPT	4



int main(int argc, char ** argv) 
{
	int		args, arg, arg_start = 1, file_arg_start = -1;
	char 	*operation = NULL,
			*infile = NULL,
			*outfile = NULL,
			*privkey = NULL,
			*pubkey = NULL,
			*algorithm = NULL,
			*keyformat = NULL,
			*bits = NULL,
			*bytes = NULL,
			*salt = NULL,
			*argstr;
	long	result;
	char 	strbuf1[16], strbuf2[16];		// Buffers for parsing strings.
	
	
	memset(&state, 0, sizeof(pkt_state));
	state.hash_name = "sha1";
	state.prng_name = "sprng";
	state.prng_state = NULL;
	state.out_encoding = PKT_FORMAT_BINARY;
	state.rsa_key = &(state.rsa_key_instance);
	state.ecc_key = &(state.ecc_key_instance);
	state.dsa_key = &(state.dsa_key_instance);
	state.rsa_saltlen = 8;
	state.algorithm = PKT_ALGORITHM_RSA;
	
	report(VL_DEBUG, "MAXBLOCKSIZE = %d, bufsize = %lu\n", MAXBLOCKSIZE, sizeof(state));
	
	if (pkt_match_tail(argv[0], "pubkeytool") || pkt_match_tail(argv[0], "pkt")) {		
		operation = argv[1];
		arg_start = 2;
	} else {
		operation = argv[0];
	}

	if (argc < arg_start + 1) {
		pkt_usage();
		exit(0);
	}

	
	if (strcmp(argv[arg_start], "-h") == 0 && argc == arg_start + 1) { 
		pkt_usage();
		exit(0);
	}

	if (pkt_match_tail(operation, "hash")) {
		state.in_encoding = PKT_FORMAT_BINARY;
		state.out_encoding = PKT_FORMAT_HEX;
	}
	
	for (arg = arg_start ; arg < argc ; arg++) {
		
		argstr = argv[arg];
		
		report(VL_DEBUG, "Matching argument %d (%s)\n", arg, argv[arg]);
		
		if (strncmp(argstr, "--private=", 10) == 0) {
			privkey = argv[arg] + 10;
		} else if (strncmp(argstr, "--public=", 9) == 0) {
			pubkey = argv[arg] + 9;
		} else if (strncmp(argstr, "--algorithm=", 13) == 0) {
			algorithm = argv[arg] + 13; 
		} else if (strncmp(argstr, "--format=", 9) == 0) {
			keyformat = argv[arg] + 9;
		} else if (strncmp(argstr, "--hash=", 7) == 0) {
			state.hash_name = argv[arg] + 7;
		} else if (strncmp(argstr, "--prng=", 7) == 0) {
			state.prng_name = argv[arg] + 7;
		} else if (strncmp(argstr, "--keybytes=", 11) == 0) {
			bytes = argv[arg] + 11;
		} else if (strncmp(argstr, "--keybits=", 10) == 0) {
			bits = argv[arg] + 10;
		} else if (strncmp(argstr, "--size=", 7) == 0) {
			bits = argv[arg] + 7;
		} else if (strncmp(argstr, "--salt=", 7) == 0) {
			salt = argv[arg] + 7;
		} else if (strcmp(argstr, "-k") == 0 || strncmp(argstr, "--pri", 5) == 0) {
			privkey = argv[arg++ + 1];
		} else if (strcmp(argstr, "-p") == 0 || strncmp(argstr, "--pu", 4) == 0) {
			pubkey = argv[arg++ + 1];
		} else if (strcmp(argstr, "-a") == 0 || strncmp(argstr, "--al", 4) == 0) {
			algorithm = argv[arg++ + 1];
		} else if (strcmp(argstr, "-f") == 0 || strncmp(argstr, "--fo", 4) == 0) {
			keyformat = argv[arg++ + 1];
		} else if (strcmp(argstr, "-h") == 0 || strncmp(argstr, "--ha", 4) == 0) {
			state.hash_name = argv[arg++ + 1];
		} else if (strcmp(argstr, "-r") == 0 || strncmp(argstr, "--prn", 5) == 0) {
			state.prng_name = argv[arg++ + 1];
		} else if (strncmp(argstr, "--keyby", 7) == 0) {
			bytes = argv[arg++ + 1];
		} else if (strcmp(argstr, "-s") == 0 || strncmp(argstr, "--si", 4) == 0 || strncmp(argstr, "--keybi", 7) == 0) {
			bits = argv[arg++ + 1];
		} else if (strncmp(argstr, "--sa", 4) == 0) {
			salt = argv[arg++ + 1];
		} else if (strcmp(argstr, "-b") == 0 || strncmp(argstr, "--bi", 4) == 0) {
			state.in_encoding = PKT_FORMAT_BINARY;
			state.out_encoding = PKT_FORMAT_BINARY;
		} else if (strcmp(argstr, "-x") == 0 || strncmp(argstr, "--hex", 5) == 0) {
			state.in_encoding = PKT_FORMAT_HEX;
			state.out_encoding = PKT_FORMAT_HEX;
		} else if (strcmp(argstr, "-7") == 0 || strncmp(argstr, "--ba", 4) == 0) {
			state.in_encoding = PKT_FORMAT_BASE64;
			state.out_encoding = PKT_FORMAT_BASE64;
		} else if (strcmp(argstr, "-v") == 0 || strncmp(argstr, "--verb", 6) == 0) {
			if (report_verbosity < VL_VERBOSE)
				report_verbosity = VL_VERBOSE;
		} else if (strcmp(argstr, "-V") == 0 || strncmp(argstr, "--vers", 6) == 0) {
		} else if (strcmp(argstr, "--help") == 0) {
			pkt_usage();
		} else if (argstr[0] == '-' && strlen(argstr) > 1) {
			report(VL_VERBOSE, "Unknown argument: %s\n", argstr);
		} else if (file_arg_start < 0) {
			file_arg_start = arg;
		}
		
		if (arg >= argc) {
			report(VL_FATAL, "- Argument list is truncated, expecting at least %d arguments!\n", arg + 1);
			exit(-1);
		}
	}
	
	if (bits) {
		state.keybits = strtoul(bits, NULL, 0);
		state.keybytes = ceil((double)(state.keybits) / 8.0);
		report(VL_VERBOSE, "Keysize set to %lu bits / %lu bytes\n", state.keybits, state.keybytes);
	}
	
	if (bytes) {
		state.keybytes = strtoul(bytes, NULL, 0);
		state.keybits = state.keybytes * 8;
		report(VL_VERBOSE, "Keysize set to %lu bits / %lu bytes\n", state.keybits, state.keybytes);
	}
	
	if (salt) {
		state.rsa_saltlen = strtoul(salt, NULL, 0);
		report(VL_VERBOSE, "Using %d bytes of salt for RSA signatures\n", state.rsa_saltlen);
	}
	
	/* TODO: match hash/algorithm from first part of operation */
	
	pkt_register_hashes();
	pkt_register_prngs();
	pkt_register_maths();
	
	if (algorithm) {
		if (strcmp(algorithm, "ecc") == 0) {
			state.algorithm = PKT_ALGORITHM_ECC;
			report(VL_VERBOSE, "Using ECC\n");
		} else if (strcmp(algorithm, "dsa") == 0) {
			state.algorithm = PKT_ALGORITHM_DSA;
			report(VL_VERBOSE, "Using DSA\n");
		} else {
			report(VL_VERBOSE, "Using RSA\n");
		}
	} else {
		report(VL_VERBOSE, "Using RSA\n");
	}
	
	state.hash_idx = find_hash(state.hash_name);
	if (state.hash_idx == -1) {
		report(VL_ERROR, "- Invalid hash name: %s\n", state.hash_name);
		return -1;
	} else {
		report(VL_VERBOSE, "Using hash-function %s (index = %d)\n", state.hash_name, state.hash_idx);
	}
	state.hashbytes = hash_descriptor[state.hash_idx].hashsize;
	
	state.prng_idx = find_prng(state.prng_name);
	if (state.prng_idx == -1) {
		report(VL_ERROR, "- Invalid PRNG name: %s\n", state.prng_name);
		return -1;
	} else {
		report(VL_VERBOSE, "Using PRNG %s (index = %d)\n", state.prng_name, state.prng_idx);
	}
	
	if (keyformat) {	/* Determine key-format */
		args = sscanf(keyformat, "%15[^,^\n],%15s", strbuf1, strbuf2);
		if (args == 1) {
			if (pkt_match_tail(operation, "keygen")) {
				state.out_keyformat = pkt_parse_keyformat(strbuf1);
				state.out_pem = pkt_match_tail(strbuf1, "pem");
				report(VL_VERBOSE, "Output key-format requested: %s\n", strbuf1);
			} else {
				state.in_keyformat = pkt_parse_keyformat(strbuf1);
				state.in_pem = pkt_match_tail(strbuf1, "pem");
				report(VL_VERBOSE, "Input key-format requested: %s\n", strbuf1);
			}
		} else if (args == 2) {
				state.in_keyformat = pkt_parse_keyformat(strbuf1);
				state.out_keyformat = pkt_parse_keyformat(strbuf2);			
				state.in_pem = pkt_match_tail(strbuf1, "pem");
				state.out_pem = pkt_match_tail(strbuf2, "pem");
				report(VL_VERBOSE, "Input key-format requested: %s\n", strbuf1);
				report(VL_VERBOSE, "Output key-format requested: %s\n", strbuf2);
		} else {
			report(VL_WARNING, "- Could not parse key-format specification.\n");
		}
		
	}
	
	report(VL_VERBOSE, "Operation requested: %s\n", operation);
	
	if (pkt_match_tail(operation, "hash")) {
		
		/* Hash an input file */
		
		report(VL_VERBOSE, "Generate %s hash\n", state.hash_name);
		
		state.input = pkt_open_input(argv, argc, file_arg_start);
		state.output = pkt_open_output(argv, argc, file_arg_start + 1);
		state.hashlen = sizeof(state.hashbuf);
		result = pkt_hash_filehandle(&state, state.input, state.hashbuf, &state.hashlen);
		if (result > 0)
			result = pkt_write_buffer(&state, state.output, state.hashbuf, state.hashlen, 0);
		pkt_close_input(state.input);
		pkt_close_output(state.output);
		
		if (result < 0) {
			report(VL_FATAL, "- problem generating or writing hash!\n");
			exit(-1);
		}
		
	} else if (pkt_match_tail(operation, "keygen")) {
		
		if (file_arg_start > 0) {
			
			/* Generate public/private keyfiles from input keyfile */
			
			state.keyfile = pkt_open_input(argv, argc, file_arg_start);
			result = pkt_read_keyfile(&state, state.keyfile);
			pkt_close_input(state.keyfile);
			
		} else {
			
			/* Generate fresh key */
			
			result = pkt_gen_key(&state);
		}
		
		if (result < 0) {
			report(VL_FATAL, "- failed to read or generate a key, giving up.\n");
			exit(-1);
		}
		
		if (privkey) {
			result = pkt_write_key(&state, privkey, PKT_KEY_PRIVATE);
		}
		
		if (pubkey) {
			result = pkt_write_key(&state, pubkey, PKT_KEY_PUBLIC);
		}
		
	} else if (pkt_match_tail(operation, "sign")) {
		
		/* Hash and sign an input file using our private key */
		
		if (privkey) {
			report(VL_VERBOSE, "Using private key from %s\n", privkey);
			state.keyfile = pkt_open_infile(privkey);
			result = pkt_read_keyfile(&state, state.keyfile);
			pkt_close_input(state.keyfile);
			
		} else {
			
			report(VL_FATAL, "- private key not specified!\n");
			exit(-1);			
		}
		
		state.hashfile = pkt_open_input(argv, argc, file_arg_start);		
		state.sigfile = pkt_open_output(argv, argc, file_arg_start + 1);
		
		result = pkt_sign_hash(&state, state.hashfile, state.sigfile);
		
		pkt_close_input(state.hashfile);
		pkt_close_output(state.sigfile);
		
		if (result < 0) {
			report(VL_FATAL, "- failed to generate signature, giving up.\n");
			exit(-1);
		}
		
	} else if (pkt_match_tail(operation, "verify")) {
		
		/* Verify an input file against a signature + public key */
		
		if (pubkey || privkey) {
			if (pubkey) {
				report(VL_VERBOSE, "Using public key from %s\n", pubkey);
				state.keyfile = pkt_open_infile(pubkey);
			} else {
				report(VL_VERBOSE, "Using private key from %s\n", privkey);
				state.keyfile = pkt_open_infile(privkey);
			}
			result = pkt_read_keyfile(&state, state.keyfile);
			pkt_close_input(state.keyfile);
			
		} else {
			
			report(VL_FATAL, "- public or private key not specified!\n");
			exit(-1);			
		}
		
		state.input = pkt_open_input(argv, argc, file_arg_start);		
		state.sigfile = pkt_open_input(argv, argc, file_arg_start + 1);		
		
		result = pkt_verify_hash(&state, state.input, state.sigfile);
		
		pkt_close_input(state.sigfile);
		pkt_close_input(state.input);		
		
		if (result < 0) {
			report(VL_FATAL, "- failed to verify signature, giving up.\n");
			exit(-1);
		} else if (result == 0) {
			report(VL_VERBOSE, "Verification failed, input file does not match signature.\n");				
			return 1;				/* Verification failed */
		} else if (result == 1) {
			report(VL_VERBOSE, "Verification successful, input file matches signature.\n");				
			return 0;				/* Verification OK */
		}
				
	}	
	
	return 0;
}


void pkt_usage ()
{
	
	printf( \
    "\n"
    "   Usage:                                                                     \n"
    "                                                                              \n"
    "   pubkeytool [<operation>] [<options>] [<infile> [<outfile> [<outfile>]]]    \n"
    "                                                                              \n"
    "   Operations:                                                                \n"
    "   hash/sha1hash/sha265hash/md5hash/etc.                                      \n"
    "   keygen/sign/verify/encrypt/decrypt                                         \n"
    "   rsakeygen/rsasign/rsaverify/rsaencrypt/rsadecrypt                          \n"
    "   ecckeygen/eccsign/eccverify/eccencrypt/eccdecrypt                          \n"
    "   dsakeygen/dsasign/dsaverify/dsaencrypt/dsadecrypt                          \n"
    "   transcode/base64encode/base64decode/hexencode/hexdecode                    \n"
    "                                                                              \n"
    "   Options:                                                                   \n"
    "                                                                              \n"
    "   -k/--private    Private key file                                           \n"
    "                                                                              \n"
    "   -p/--public     Public key file                                            \n"
    "                                                                              \n"
    "   -a/--algorithm  Asymmetric key algorithm:                                  \n"
    "                                                                              \n"
    "                   rsa - RSA (default)                                        \n"
    "                   ecc - Ellyptic Curve Cryptography                          \n"
    "                   dsa - Digital Signature Algorithm                          \n"
    "                                                                              \n"
    "   -f/--format     Key file format for input and/or output:                   \n"
    "                                                                              \n"
    "                   auto - Try to detect input format, use sane output format  \n"
    "                   pem - Same as auto, but use BASE64 encoding (PEM-format)   \n"
    "                   tomcrypt - LibTomCrypt DER ASN.1 (default for ECC and DSA) \n"
    "                   pkcs1 - PKCS #1 RSA keys (DER-format, default for RSA)     \n"
    "                   pkcs1pem - PKCS #1 RSA keys (PEM-format)                   \n"
    "                   ansi - ANSI X9.63 ECC public-keys (default for ECC pubkey) \n"
    "                   ansipem - ANSI X9.63 ECC public-keys (PEM-format)          \n"
    "                                                                              \n"
    "                   To specify both input and output key-formats,              \n"
    "                   give two keywords seperated by a comma.                    \n"
    "                                                                              \n"
    "   -h/--hash       Hash function                                              \n"
    "                                                                              \n"
    "                   sha1 - SHA1 (160 bits, default)                            \n"
    "                   sha256 - SHA256 (256 bits)                                 \n"
    "                   sha384 - SHA384 (384 bits)                                 \n"
    "                   sha512 - SHA512 (512 bits)                                 \n"
    "                   md5 - MD5 (128 bits)                                       \n"
    "                   others may also be available                               \n"
    "                                                                              \n"
    "   -r/--prng       Pseudo Random Number Generator                             \n"
    "                                                                              \n"
    "                   sprng - system PRNG (default)                              \n"
    "                   other may also be available                                \n"
    "                                                                              \n"
    "   -s/--size/      Size of the key in bits                                    \n"
    "   --keybits                                                                  \n"
    "                                                                              \n"
    "   --keybytes      Size of the key in bytes                                   \n"
    "                                                                              \n"
    "   -e/--encoding   Encoding of input and/or output files:                     \n"
    "                                                                              \n"
    "                   binary - Raw binary format (default except for hashes)\n"
    "                   hex - Hexadecimal format (default for hashes)\n"
    "                   base64 - BASE64 encoded 7-bit ASCII                        \n"
    "                                                                              \n"
    "                   To specify both input and output encoding,                 \n"
    "                   give two keywords seperated by a comma.                    \n"
    "                                                                              \n"
    "   -b/--binary     Shortcut to specify binary encoding                        \n"
    "                                                                              \n"
    "   -x/--hex        Shortcut to specify hexadecimal encoding                   \n"
    "                                                                              \n"
    "   -7/--base64     Shortcut to specify BASE64 encoding                        \n"
    "                                                                              \n"
    "   -c/--compat     Compatibility settings:\n"
    "\n"
    "                   openssl - Maximise compatibility with OpenSSL\n");

}


int pkt_match_tail (char *string, char *match)
{
	int matchlen, stringlen, idx = 0;
	
	stringlen = strlen(string);
	matchlen = strlen(match);
	if (matchlen < stringlen)
		idx = stringlen - matchlen;
	
	
	if (strcmp(string + idx, match) == 0) {
		report(VL_DEBUG, "Matched substring %s of %s with %s\n", string + idx, string, match);
		return idx + 1;
	} else {
		report(VL_DEBUG, "Substring %s of %s did not match %s\n", string + idx, string, match);
		return 0;
	}
}


int pkt_parse_keyformat(char *format)
{
	/* TODO: Parse key-format strings */
}


FILE * pkt_open_input (char **argv, int argc, int idx)
{
	char *infile;
	FILE *input = NULL;
	
	if (!argv)
		return NULL;

	report(VL_DEBUG, "pkt_open_input: argc=%d, idx=%d\n", argc, idx);
	
	if (idx > 0 && idx < argc) {
		
		infile = argv[idx];
		
		report(VL_DEBUG, "Attempting to open input %s\n", infile);
		
		if (strcmp(infile, "-") == 0) {
			input = stdin;
		} else { 
			input = fopen(infile, "r");
			if (input == NULL) {
				report(VL_FATAL, "opening input file %s\n", infile);
				exit(-1);
			}
		}
	} else 
		input = stdin;

	report(VL_DEBUG, "input stream: 0x%lx (stdin = 0x%lx)\n", input, stdin);
	
	return input;
}


FILE * pkt_open_infile (char *infile)
{
	FILE *input = NULL;

	report(VL_DEBUG, "pkt_open_infile: %s\n", infile);
	
	if (!infile)
		return stdin;
	
	if (strcmp(infile, "-") == 0) {
		input = stdin;
	} else { 
		input = fopen(infile, "r");
		if (input == NULL) {
			report(VL_FATAL, "opening input file %s\n", infile);
			exit(-1);
		}
	}
	
	report(VL_DEBUG, "input stream: 0x%lx (stdin = 0x%lx)\n", input, stdin);
	
	return input;
}


FILE * pkt_open_output (char **argv, int argc, int idx)
{
	char *outfile;
	FILE *output = NULL;
	
	if (!argv)
		return NULL;
	
	if (idx > 0 && idx < argc) {
		outfile = argv[idx];
		if (strcmp(outfile, "-") == 0) {
			output = stdout;
		} else { 
			output = fopen(outfile, "w");
			if (output == NULL) {
				report(VL_FATAL, "opening output file %s\n", outfile);
				exit(-1);
			}
		}
	} else {
		output = stdout;
		report(VL_DEBUG, "Output to stdout\n");
	}
	
	report(VL_DEBUG, "output stream: 0x%lx (stdout = 0x%lx)\n", output, stdout);
	
	return output;
}


FILE * pkt_open_outfile (char *outfile)
{
	FILE *output = NULL;
	
	if (!outfile)
		return stdout;
	
	if (strcmp(outfile, "-") == 0) {
		output = stdout;
	} else { 
		output = fopen(outfile, "w");
		if (output == NULL) {
			report(VL_FATAL, "opening output file %s\n", outfile);
			exit(-1);
		}
	}
	
	return output;
}


void pkt_close_input (FILE *input)
{
	if (input && input != stdin)
		fclose(input);
}


void pkt_close_output (FILE *output)
{
	if (output && output != stdout)
		fclose(output);
}


int pkt_register_hashes ()
{
	int error = 0;
	
	if (register_hash(&sha1_desc) == -1) {
		report(VL_ERROR, "registering hash-function SHA1.\n");
		error = -1;
	}	

	if (register_hash(&sha256_desc) == -1) {
		report(VL_ERROR, "registering hash-function SHA256.\n");
		error = -2;
	}	

	if (register_hash(&sha384_desc) == -1) {
		report(VL_ERROR, "registering hash-function SHA384.\n");
		error = -3;
	}	
	
	if (register_hash(&sha512_desc) == -1) {
		report(VL_ERROR, "registering hash-function SHA512.\n");
		error = -4;
	}	
	
	if (register_hash(&md5_desc) == -1) {
		report(VL_ERROR, "registering hash-function MD5.\n");
		error = -5;
	}
	
	return error;
}


int pkt_register_prngs ()
{
	int error = 0;
	
	if (register_prng(&sprng_desc) == -1) {
		report(VL_ERROR, "registering system PRNG.\n");
		error = -1;
	}	
	
	return error;
}


void pkt_register_maths ()
{
	/* register a math library (in this case TomsFastMath) */

	ltc_mp = tfm_desc;	
}



long pkt_base64_encode (unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen)
{
	int err;
	
	if (!inbuf || !outbuf)
		return -1;
	
	if ((err = base64_encode(inbuf, inlen, outbuf, outlen)) != CRYPT_OK) {
		report(VL_ERROR, "during BASE64 encoding: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return *outlen;	
}


long pkt_base64_decode (unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen)
{
	int err;
	
	if (!inbuf || !outbuf)
		return -1;
	
	if ((err = base64_decode(inbuf, inlen, outbuf, outlen)) != CRYPT_OK) {
		report(VL_ERROR, "during BASE64 decoding: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return *outlen;	
}





long pkt_gen_key (pkt_state *state)
{
	long result = 0;
	
	if (!state)
		return -1;
	
	#if 0
	if (!state->keybits) {
		report(VL_ERROR, "- key-size is missing!\n");
		return -2;
	}
	#endif
	
	switch (state->algorithm) {
		case PKT_ALGORITHM_RSA:
			result = pkt_rsa_key_gen(state);
			break;
		case PKT_ALGORITHM_ECC:
			result = pkt_ecc_key_gen(state);
			break;
		case PKT_ALGORITHM_DSA:
			result = pkt_dsa_key_gen(state);
			break;
		default:
			report(VL_ERROR, "- key algorithm not specified or not supported!\n");
			return -3;
	}

	if (result != CRYPT_OK && result > 0)
		return -1 * result;
	
	return result;
}


long pkt_sign_hash (pkt_state *state, FILE *hash_in, FILE *sig_out)
{
	long result = 0;
	
	if (!state || !hash_in || !sig_out)
		return -1;
	
	state->hashlen = sizeof(state->hashbuf);
	result = pkt_hash_filehandle(state, hash_in, state->hashbuf, &state->hashlen);
	
	if (result > 0) {
	
		state->siglen = sizeof(state->sigbuf);
			
		switch (state->algorithm) {
			case PKT_ALGORITHM_RSA:
				result = pkt_rsa_sign_hash(state, state->hashbuf, state->hashlen, state->sigbuf, &state->siglen);
				break;
			case PKT_ALGORITHM_ECC:
				result = pkt_ecc_sign_hash(state, state->hashbuf, state->hashlen, state->sigbuf, &state->siglen);
				break;
			case PKT_ALGORITHM_DSA:
				result = pkt_dsa_sign_hash(state, state->hashbuf, state->hashlen, state->sigbuf, &state->siglen);
				break;
			default:
				report(VL_ERROR, "- key algorithm not specified or not supported!\n");
				return -2;
		}
	}
	
	if (result != CRYPT_OK && result > 0)
		return -1 * result;

	if (result >= 0) {
		report(VL_VERBOSE, "Writing %lu byte signature to output.\n", state->siglen);
		result = pkt_write_buffer(state, sig_out, state->sigbuf, state->siglen, 0);
	} else {
		report(VL_ERROR, "generating signature (%ld)\n", result);		
	}
	
	return result;
	
}


long pkt_verify_hash (pkt_state *state, FILE *file_in, FILE *sig_in)
{
	long result = 0;
	
	if (!state || !file_in || !sig_in)
		return -1;

	state->siglen = sizeof(state->sigbuf);
	result = pkt_read_buffer(state, sig_in, state->sigbuf, &state->siglen, 0);

	if (result < 0) {
		report(VL_ERROR, "- could not read signature!\n");
		return result;
	}
	
	state->hashlen = sizeof(state->hashbuf);
	result = pkt_hash_filehandle(state, file_in, state->hashbuf, &state->hashlen);
			
	if (result > 0) {
	
		switch (state->algorithm) {
			case PKT_ALGORITHM_RSA:
				result = pkt_rsa_verify_hash(state, state->sigbuf, state->siglen, state->hashbuf, state->hashlen);
				break;
			case PKT_ALGORITHM_ECC:
				result = pkt_ecc_verify_hash(state, state->sigbuf, state->siglen, state->hashbuf, state->hashlen);
				break;
			case PKT_ALGORITHM_DSA:
				result = pkt_dsa_verify_hash(state, state->sigbuf, state->siglen, state->hashbuf, state->hashlen);
				break;
			default:
				report(VL_ERROR, "- key algorithm not specified or not supported!\n");
				return -2;
		}
	}

	return result;	
}


long pkt_read_keyfile (pkt_state *state, FILE *keyfile)
{
	/* Read keyfile in the configured format */
	
	long result;
	unsigned long len;
	int encoding;
	
	if (!state || !keyfile)
		return -1;
	

	if (state->in_pem) {
		encoding = PKT_FORMAT_BASE64;
	} else {
		encoding = PKT_FORMAT_BINARY;
	}
	
	len = sizeof(state->keybuf);

	result = pkt_read_buffer(state, keyfile, state->keybuf, &len, encoding);
	
	report(VL_DEBUG, "Read %lu bytes from keyfile\n", len);
	
	if (result > 0) {
		
		switch (state->algorithm) {
			case PKT_ALGORITHM_RSA:
				result = pkt_rsa_import_key(state, state->keybuf, len);
				break;
			case PKT_ALGORITHM_ECC:
				result = pkt_ecc_import_key(state, state->keybuf, len);
				break;
			case PKT_ALGORITHM_DSA:
				result = pkt_dsa_import_key(state, state->keybuf, len);
				break;
			default:
				report(VL_ERROR, "- key algorithm not specified or not supported!\n");
				return -3;
		}	
		
	}
	
	if (result < 0) {
		report(VL_ERROR, "- problem importing key\n");
	}
	
	return result;
}


long pkt_write_key (pkt_state *state, char *keyfile, int keytype)
{
	/* Write keyfile in the configured format and type (public/private) */
	
	long result;
	FILE *out;
	unsigned long len;
	char *startstr, *endstr;
	int encoding;
	
	if (!state || !keyfile)
		return -1;
	
	encoding = state->out_encoding;
	
	out = pkt_open_outfile(keyfile);

	len = sizeof(state->keybuf);
	
	if (keytype == PKT_KEY_PUBLIC) {
		
		startstr = "-----BEGIN PUBLIC KEY-----";
		endstr = "-----END PUBLIC KEY-----";

		switch (state->algorithm) {
			case PKT_ALGORITHM_RSA:
				result = pkt_rsa_export_public_key (state, state->keybuf, &len);
				break;
			case PKT_ALGORITHM_ECC:
				result = pkt_ecc_export_public_key (state, state->keybuf, &len);
				break;
			case PKT_ALGORITHM_DSA:
				result = pkt_dsa_export_public_key (state, state->keybuf, &len);
				break;
			default:
				report(VL_ERROR, "- key algorithm not specified or not supported!\n");
				return -3;
		}	
		
	} else if (keytype == PKT_KEY_PRIVATE) {
		
		switch (state->algorithm) {
			case PKT_ALGORITHM_RSA:
				startstr = "-----BEGIN RSA PRIVATE KEY-----";
				endstr = "-----END RSA PRIVATE KEY-----";
				result = pkt_rsa_export_private_key (state, state->keybuf, &len);
				break;
			case PKT_ALGORITHM_ECC:
				//-----BEGIN EC PARAMETERS-----
				//-----END EC PARAMETERS-----
				startstr = "-----BEGIN EC PRIVATE KEY-----";
				endstr = "-----END EC PRIVATE KEY-----";
				result = pkt_ecc_export_private_key (state, state->keybuf, &len);
				break;
			case PKT_ALGORITHM_DSA:
				startstr = "-----BEGIN DSA PRIVATE KEY-----";
				endstr = "-----END DSA PRIVATE KEY-----";
				result = pkt_dsa_export_private_key (state, state->keybuf, &len);
				break;
			default:
				report(VL_ERROR, "- key algorithm not specified or not supported!\n");
				return -3;
		}	

	}
	
	result = 0;
	
	if (state->out_pem) {
		encoding = PKT_FORMAT_BASE64;
		result = fprintf(out, "%s\n", startstr);
	}
	
	if (result >= 0)
		result += pkt_write_buffer(state, out, state->keybuf, len, encoding);
	
	if (state->out_pem && result > 0)
		result += fprintf(out, "%s\n", endstr);
	
	pkt_close_output(out);
	
	return result;
}


long pkt_read_buffer (pkt_state *state, FILE *in, unsigned char *buf, unsigned long *len, int encoding)
	{
	/* Read buffer using the configured input encoding */
	
	long result;
	unsigned long idx, bytecount = 0, base64len = 0;
	unsigned char *tmpbuf;
	char strbuf[50];
	int header = FALSE;
	
	if (!state || !in)
		return -1;
	
	if (!encoding) {
		encoding = state->in_encoding;
	}
	
	report(VL_DEBUG, "pkt_read_buffer: buflen %lu, encoding %d\n", *len, encoding);
	
	if (encoding == PKT_FORMAT_BASE64) {
			
		/* BASE64 input */

		report(VL_DEBUG, "pkt_read_buffer: reading BASE64\n");
					
		tmpbuf = malloc(*len);

		if (tmpbuf == NULL) {
			report(VL_ERROR, "allocating %lu byte read buffer for BASE64 decoding\n", *len);
			return -2;
		}
		
	} else {
		
		tmpbuf = buf;
	}
	
	
	if (encoding == PKT_FORMAT_HEX) {
		
		/* HEX input */
		
		report(VL_DEBUG, "pkt_read_buffer: reading hexadecimal\n");
		
		while (bytecount < *len && (result = fscanf(in, "%02hhx", &(buf[bytecount]))) == 1)
			bytecount++;

		report(VL_DEBUG, "pkt_read_buffer: %lu bytes read\n", bytecount);
		
		//if (result < 0) {
		//	report(VL_WARNING, "Error (%ld) after reading %lu bytes.\n", result, *len);
		//}		
		
	} else {
		
		report(VL_DEBUG, "pkt_read_buffer: reading binary data\n");
		
		bytecount = fread(tmpbuf + bytecount, 1, *len, in);
		
		report(VL_DEBUG, "pkt_read_buffer: %lu bytes read\n", bytecount);
	}
	
	if (bytecount >= *len) {
		report(VL_WARNING, "Buffer overflow after reading %lu bytes.\n", *len);
	}
	
				
	if (encoding == PKT_FORMAT_BASE64) {
		
		/* BASE64 input */

		for (idx = 0 ; idx < bytecount - 64 ; idx++) {
			if (sscanf(tmpbuf + idx, "-----BEGIN %49[^-^\n]-----", strbuf) == 1) {
				while (tmpbuf[idx] && idx < bytecount && tmpbuf[idx++] != '\n');
				while (tmpbuf[idx + base64len] && idx + base64len < bytecount && tmpbuf[idx + base64len++] != '-');
				if (base64len > 0) base64len -= 1;
				report(VL_VERBOSE, "Found BASE64-encoded %s at byte-index %lu, %lu bytes in length.\n", strbuf, idx, base64len);
				report(VL_DEBUG, "First 16 bytes %16s, start of footer %16s.\n", tmpbuf + idx, tmpbuf + idx + base64len);				
				header = TRUE;
				break;
			}
		}
		
		if (!header)
			idx = 0;
		if (base64len <= 0) 
			base64len = bytecount - idx;
		
		report(VL_DEBUG, "Calling base64_decode with index %lu and length %lu, outbuflen = %lu\n", idx, base64len, *len);
		
		result = pkt_base64_decode (tmpbuf + idx, base64len, buf, len);
		free(tmpbuf);
		
		if (result <= 0) {
			report(VL_ERROR, "decoding BASE64 data\n");
			return result;
		}
		
		bytecount = *len;
		
	} else
		*len = bytecount;
	
	return bytecount;
}


long pkt_write_buffer (pkt_state *state, FILE *out, unsigned char *buf, unsigned long len, int encoding)
{
	/* Write buffer using the configured output encoding */
	
	long result;
	unsigned long idx = 0, tmpbuflen;
	unsigned char *tmpbuf;
	
	report(VL_DEBUG, "Writing %lu bytes to file-handle 0x%lx (encoding = %d)\n", len, out, encoding);
	
	if (!state || !out)
		return -1;
	
	if (!encoding) {
		encoding = state->out_encoding;
	}
	
	if (encoding == PKT_FORMAT_HEX) {
		
		/* HEX output */
		
		for (idx = 0; idx < len; idx++) {
			result = fprintf(out, "%02x", buf[idx]);
		}
		
		return result;
		
	} else if (encoding == PKT_FORMAT_BASE64) {
		
		/* BASE64 output */
		
		tmpbuflen = (ceil((double)len / 3.0) * 4) + 64;
		tmpbuf = malloc(tmpbuflen);

		report(VL_DEBUG, "Allocating %lu byte buffer for BASE64 encoding\n", tmpbuflen);

		if (tmpbuf == NULL) {
			report(VL_ERROR, "allocating %lu byte buffer for BASE64 encoding\n", tmpbuflen);
			return -2;
		}

		result = pkt_base64_encode (buf, len, tmpbuf, &tmpbuflen);
		
		#ifdef DEBUG
		result = pkt_base64_decode (tmpbuf, tmpbuflen, buf, &len);
		if (result <= 0) {
			report(VL_DEBUG, "ERROR base64_decode test failed, returned %ld\n", result);
		} else {
			report(VL_DEBUG, "CHECK base64_decode test OK, returned %ld, %lu bytes decoded, result length %lu\n", result, tmpbuflen, len);
		}
		#endif

		if (result > 0) {
			do {
				result = fwrite(tmpbuf + idx, 1, (tmpbuflen - idx < 64) ? tmpbuflen - idx : 64, out);
				fprintf(out, "\n");
				idx += result;
			} while (result == 64 && idx < tmpbuflen);
		}
		
		free(tmpbuf);
		return tmpbuflen;
			
	} else {		/* Binary output */

		return fwrite(buf, len, 1, out);
	}
}


#if 0
int pkt_hash_partial (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf)
{
	hash_state state;
	
	if (!state || !inbuf || !outbuf || state->hash_idx < 0)
		return -1;
	
	hash_descriptor[state->hash_idx].init(&state);
	hash_descriptor[state->hash_idx].process(&state, inbuf, inlen);
	hash_descriptor[state->hash_idx].done(&state, outbuf);
	
	return 0;	
}
#endif



long pkt_hash_buffer (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen)
{
	int err;
	
	if (!state || !inbuf || !outbuf || state->hash_idx < 0)
		return -1;
	
	if ((err = hash_memory(state->hash_idx, inbuf, inlen, outbuf, outlen)) != CRYPT_OK) {
		report(VL_ERROR, "hashing data: %s\n", error_to_string(err));
		return err;
	}
	
	return *outlen;	
}


long pkt_hash_file (pkt_state *state, char *file, unsigned char *outbuf, unsigned long *outlen)
{
	int err;
	
	if (!state || !file || !outbuf || state->hash_idx < 0)
		return -1;
	
	if ((err = hash_file(state->hash_idx, file, outbuf, outlen)) != CRYPT_OK) {
		report(VL_ERROR, "hashing file %s: %s\n", file, error_to_string(err));
		return err;
	}
	
	return *outlen;	
}


long pkt_hash_filehandle (pkt_state *state, FILE *file, unsigned char *outbuf, unsigned long *outlen)
{
	int err;
	
	report(VL_DEBUG, "Hashing filehandle 0x%lx, using hash-index %d, buflen = %lu\n", file, state->hash_idx, *outlen);
	
	if (!state || !file || !outbuf || state->hash_idx < 0)
		return -1;
	
	if ((err = hash_filehandle(state->hash_idx, file, outbuf, outlen)) != CRYPT_OK) {
		report(VL_ERROR, "hashing file: %s\n", error_to_string(err));
		return err;
	}
	
	report(VL_DEBUG, "Hash length = %lu\n", *outlen);
	
	return *outlen;	
}


int pkt_rsa_key_gen (pkt_state *state)
{
	int err;

	if (!state || !state->rsa_key || state->prng_idx < 0)
		return -1;
	
	if (state->keybytes < 128) {
		report(VL_WARNING, "- RSA key must be at least 1024 bits in size, setting keysize to 1024.\n");		
		state->keybits = 1024;
		state->keybytes = 128;
	} else if (state->keybytes > 512) {
		report(VL_WARNING, "- RSA key can be at most 4096 bits in size, setting keysize to 4096.\n");		
		state->keybits = 4096;
		state->keybytes = 512;
	}
	
	if ((err = rsa_make_key(state->prng_state, state->prng_idx, state->keybytes, 65537, state->rsa_key))
			!= CRYPT_OK) {
		report(VL_ERROR, "generating RSA key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	} else {
		report(VL_VERBOSE, "RSA key generated\n");
	}
	
	return 0;
}


int pkt_rsa_import_key (pkt_state *state, unsigned char *inbuf, unsigned long inlen)
{
	int err;

	if (!state || !state->rsa_key || !inbuf)
		return -1;
	
	if ((err = rsa_import(inbuf, inlen, state->rsa_key))
			!= CRYPT_OK) {
		report(VL_ERROR, "parsing RSA key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return 0;
}


long pkt_rsa_export_public_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->rsa_key || !outbuf)
		return -1;
		
	if ((err = rsa_export(outbuf, outlen, PK_PUBLIC, state->rsa_key)) != CRYPT_OK) {
		report(VL_ERROR, "exporting public RSA key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}

	return *outlen;
}



long pkt_rsa_export_private_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->rsa_key || !outbuf)
		return -1;
		
	if ((err = rsa_export(outbuf, outlen, PK_PRIVATE, state->rsa_key)) != CRYPT_OK) {
		report(VL_ERROR, "exporting private RSA >key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}

	return *outlen;
}



int pkt_rsa_encrypt_buffer (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->rsa_key || state->prng_idx < 0 || state->hash_idx < 0)
		return -1;
	
	if ((err = rsa_encrypt_key(inbuf, /* data we wish to encrypt */
					inlen, /* data length */
					outbuf, /* where to store ciphertext */
					outlen, /* length of ciphertext */
					"pubkeytool", /* our lparam for this program */
					10, /* lparam is 7 bytes long */
					state->prng_state, /* PRNG state */
					state->prng_idx, /* prng idx */
					state->hash_idx, /* hash idx */
					state->rsa_key) /* our RSA key */
					) != CRYPT_OK) {
	
		report(VL_ERROR, "encrypting buffer with RSA: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return 0;
}


int pkt_rsa_decrypt_buffer (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen)
{
	int err, result;

	if (!state || !state->rsa_key || state->prng_idx < 0 || state->hash_idx < 0)
		return -1;
	
	if ((err = rsa_decrypt_key(inbuf, /* data we wish to decrypt */
					inlen, /* ciphertext length */
					outbuf, /* where to store plaintext */
					outlen, /* length of plaintext */
					"pubkeytool", /* lparam for this program */
					10, /* lparam is 7 bytes long */
					state->hash_idx, /* hash idx */
					&result, /* validity of data */
					state->rsa_key) /* our RSA key */
					) != CRYPT_OK) {
	
		report(VL_ERROR, "decrypting buffer with RSA: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return result;
}


int pkt_rsa_sign_hash (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->rsa_key || state->prng_idx < 0 || state->hash_idx < 0)
		return -1;
	
	if ((err = rsa_sign_hash(inbuf, /* hash we wish to sign */
					inlen, /* hash length */
					outbuf, /* where to store signature */
					outlen, /* length of signature */
					state->prng_state, /* PRNG state */
					state->prng_idx, /* prng idx */
					state->hash_idx, /* hash idx */
					state->rsa_saltlen, /* salt length */
					state->rsa_key) /* our RSA key */
					) != CRYPT_OK) {
	
		report(VL_ERROR, "creating RSA signature: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return 0;
}


int pkt_rsa_verify_hash (pkt_state *state, unsigned char *signature, unsigned long siglen, unsigned char *hash, unsigned long hashlen)
{
	int err, status;

	if (!state || !state->rsa_key || !signature || !hash || state->hash_idx < 0)
		return -1;
	
	report(VL_DEBUG, "pkt_rsa_verify_hash: siglen %lu, hashlen %lu, saltlen %u\n", siglen, hashlen, state->rsa_saltlen)
	
	if ((err = rsa_verify_hash(signature, /* signature we wish to use */
					siglen, /* signature length */
					hash, /* hash we wish to verify */
					hashlen, /* hash length */
					state->hash_idx, /* hash idx */
					state->rsa_saltlen, /* salt length */
					&status, /* status */
					state->rsa_key) /* our RSA key */
					) != CRYPT_OK) {
	
		report(VL_ERROR, "verifying RSA signature: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return status;
}


int pkt_ecc_key_gen (pkt_state *state)
{
	int err;

	if (!state || !state->ecc_key || state->prng_idx < 0)
		return -1;
	
	if (state->keybytes < 12) {
		report(VL_WARNING, "- ECC key must be at least 112 bits in size, setting keysize to 112.\n");		
		state->keybits = 112;
		state->keybytes = 12;
	} else if (state->keybytes > 65) {
		report(VL_WARNING, "- ECC key can be at most 521 bits in size, setting keysize to 521.\n");		
		state->keybits = 521;
		state->keybytes = 65;
	}
	
	if ((err = ecc_make_key(state->prng_state, state->prng_idx, state->keybytes, state->ecc_key))
			!= CRYPT_OK) {
		report(VL_ERROR, "generating ECC key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	} else {
		report(VL_VERBOSE, "ECC key generated\n");
	}
	
	return 0;
}


int pkt_ecc_import_key (pkt_state *state, unsigned char *inbuf, unsigned long inlen)
{
	int err;

	if (!state || !state->ecc_key || !inbuf)
		return -1;
	
	if (state->in_keyformat == PKT_ECC_KEY_ANSI_X963) {
		if ((err = ecc_ansi_x963_import(inbuf, inlen, state->ecc_key))
				!= CRYPT_OK) {
			report(VL_ERROR, "parsing ANSI X9.63 ECC key: %s\n", error_to_string(err));
			return (err < 0) ? err : err * -1;
		}
	} else if (state->in_keyformat == PKT_ECC_KEY_TOMCRYPT) {
		if ((err = ecc_import(inbuf, inlen, state->ecc_key))
				!= CRYPT_OK) {
			report(VL_ERROR, "parsing LibTomCrypt ECC key: %s\n", error_to_string(err));
			return (err < 0) ? err : err * -1;
		}			
	} else {
		if ((err = ecc_ansi_x963_import(inbuf, inlen, state->ecc_key)) == CRYPT_OK) {
			report(VL_VERBOSE, "Imported ANSI X9.63 public ECC key.\n");
		} else if ((err = ecc_import(inbuf, inlen, state->ecc_key)) == CRYPT_OK) {
			report(VL_VERBOSE, "Imported LibTomCrypt ECC key.\n");
		} else {
			report(VL_ERROR, "- Unable to determine or parse ECC key format.\n");
			return (err < 0) ? err : err * -1;
		}
	}
	
	return 0;
}


long pkt_ecc_export_public_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->ecc_key || !outbuf)
		return -1;
		
	if (state->out_keyformat == PKT_ECC_KEY_TOMCRYPT) {
		report(VL_VERBOSE, "Exporting LibTomCrypt public ECC key.\n");
		if ((err = ecc_export(outbuf, outlen, PK_PUBLIC, state->ecc_key)) != CRYPT_OK) {
			report(VL_ERROR, "exporting LibTomCrypt public ECC key: %s\n", error_to_string(err));
			return (err < 0) ? err : err * -1;
		}
	} else {
		report(VL_VERBOSE, "Exporting ANSI X9.63 public ECC key.\n");
		if ((err = ecc_ansi_x963_export(state->ecc_key, outbuf, outlen)) != CRYPT_OK) {
			report(VL_ERROR, "exporting ANSI X9.63 public ECC key: %s\n", error_to_string(err));
			return (err < 0) ? err : err * -1;
		}
	}			
	return *outlen;
}


long pkt_ecc_export_private_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->ecc_key || !outbuf)
		return -1;
		
	if (state->out_keyformat == PKT_ECC_KEY_ANSI_X963) {
		report(VL_WARNING, "- It is not possible to export private ECC keys in ANSI X9.63 format, using LibTomCrypt format.\n");
	}
	
	if ((err = ecc_export(outbuf, outlen, PK_PRIVATE, state->ecc_key)) != CRYPT_OK) {
		report(VL_ERROR, "exporting LibTomCrypt private ECC key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return *outlen;
}


int pkt_ecc_sign_hash (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->ecc_key || state->prng_idx < 0)
		return -1;
	
	//if (inlen > state->keybytes) {
	//	report(VL_WARNING, "- Hash should be smaller than ECC-key, but hash is %lu bytes and key is %lu bytes.\n", inlen, state->keybytes);		
	//}
	
	if ((err = ecc_sign_hash(inbuf, /* hash we wish to sign */
					inlen, /* hash length */
					outbuf, /* where to store signature */
					outlen, /* length of signature */
					state->prng_state, /* PRNG state */
					state->prng_idx, /* prng idx */
					state->ecc_key) /* our ECC key */
					) != CRYPT_OK) {
	
		report(VL_ERROR, "creating ECC-DSA signature: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return 0;
}


int pkt_ecc_verify_hash (pkt_state *state, unsigned char *signature, unsigned long siglen, unsigned char *hash, unsigned long hashlen)
{
	int err, status;

	if (!state || !state->ecc_key || !signature || !hash)
		return -1;
	
	if ((err = ecc_verify_hash(signature, /* signature we wish to use */
					siglen, /* signature length */
					hash, /* hash we wish to verify */
					hashlen, /* hash length */
					&status, /* status */
					state->ecc_key) /* our ECC key */
					) != CRYPT_OK) {
	
		report(VL_ERROR, "verifying ECC-DSA signature: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return status;
}


int pkt_dsa_key_gen (pkt_state *state)
{
	int err;

	if (!state || !state->dsa_key || state->prng_idx < 0)
		return -1;
	
	switch (state->keybits) {
		case 160:
			state->dsa_group_size = 20;
			state->dsa_modulus_size = 128;
			break;
		case 240:
			state->dsa_group_size = 30;
			state->dsa_modulus_size = 256;
			break;
		case 280:
			state->dsa_group_size = 35;
			state->dsa_modulus_size = 384;
			break;
		case 320:
			state->dsa_group_size = 40;
			state->dsa_modulus_size = 512;
			break;
		default:
			report(VL_ERROR, "- Generating a %lu-bit DSA key is currently not supported. Valid values are 160, 240, 280 and 320 bits (group size).\n", state->keybits);
			return -2;
	}
	
	if ((err = dsa_make_key(state->prng_state, state->prng_idx, state->dsa_group_size, state->dsa_modulus_size, state->dsa_key))
			!= CRYPT_OK) {
		report(VL_ERROR, "generating DSA key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	} else {
		report(VL_VERBOSE, "DSA key generated\n");
	}
	
	return 0;
}


int pkt_dsa_import_key (pkt_state *state, unsigned char *inbuf, unsigned long inlen)
{
	int err;

	if (!state || !state->dsa_key || !inbuf)
		return -1;
	
	if ((err = dsa_import(inbuf, inlen, state->dsa_key))
			!= CRYPT_OK) {
		report(VL_ERROR, "parsing LibTomCrypt DSA key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}				
	
	return 0;
}


long pkt_dsa_export_public_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->dsa_key || !outbuf)
		return -1;
		
	if ((err = dsa_export(outbuf, outlen, PK_PUBLIC, state->dsa_key)) != CRYPT_OK) {
		report(VL_ERROR, "exporting LibTomCrypt public DSA key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return *outlen;
}


long pkt_dsa_export_private_key (pkt_state *state, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->dsa_key || !outbuf)
		return -1;
		
	if ((err = dsa_export(outbuf, outlen, PK_PRIVATE, state->dsa_key)) != CRYPT_OK) {
		report(VL_ERROR, "exporting LibTomCrypt private DSA key: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}

	return *outlen;
}


int pkt_dsa_sign_hash (pkt_state *state, unsigned char *inbuf, unsigned long inlen, unsigned char *outbuf, unsigned long *outlen)
{
	int err;

	if (!state || !state->dsa_key || state->prng_idx < 0)
		return -1;
	
	if ((err = dsa_sign_hash(inbuf, /* hash we wish to sign */
					inlen, /* hash length */
					outbuf, /* where to store signature */
					outlen, /* length of signature */
					state->prng_state, /* PRNG state */
					state->prng_idx, /* prng idx */
					state->dsa_key) /* our DSA key */
					) != CRYPT_OK) {
	
		report(VL_ERROR, "creating DSA signature: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return 0;
}


int pkt_dsa_verify_hash (pkt_state *state, unsigned char *signature, unsigned long siglen, unsigned char *hash, unsigned long hashlen)
{
	int err, status;

	if (!state || !state->dsa_key || !signature || !hash)
		return -1;
	
	if ((err = dsa_verify_hash(signature, /* signature we wish to use */
					siglen, /* signature length */
					hash, /* hash we wish to verify */
					hashlen, /* hash length */
					&status, /* status */
					state->dsa_key) /* our DSA key */
					) != CRYPT_OK) {
	
		report(VL_ERROR, "verifying DSA signature: %s\n", error_to_string(err));
		return (err < 0) ? err : err * -1;
	}
	
	return status;
}
