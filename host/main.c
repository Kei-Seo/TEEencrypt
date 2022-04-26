/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)


int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;


	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char path[100] = "/root/";
	int len=64;
	int cipherkey = 0;

	////////////////////RSA//////////////////
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	
	/******************************Encryption******************************/
	if(strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "Ceaser") == 0)
	{	

		memset(&op, 0, sizeof(op));

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 
							TEEC_VALUE_INOUT,		//param for encrypted key
							TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
			
			
		strcat(path, argv[2]);
		FILE *fp = fopen(path, "r");
		// file open
		fgets(plaintext, sizeof(plaintext), fp);
		// file text copy plain text
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
			
		fclose(fp);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
			&err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
			&err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
			&err_origin);

		char encrypted_path[100] = "/root/encrypt";
		strcat(encrypted_path, argv[2]);
		FILE *fp_encrypted = fopen(encrypted_path, "w");

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		fputs(ciphertext, fp_encrypted);
		fclose(fp_encrypted);

		char key_path[100] = "/root/key";
		strcat(key_path, argv[2]);
		FILE *fp_key = fopen(key_path, "w");
		cipherkey = op.params[1].value.a;
		fprintf(fp_key, "%d", cipherkey);
		fclose(fp_key);

	}else if(strcmp(argv[1], "-d") == 0 && strcmp(argv[4], "Ceaser") == 0){	

		memset(&op, 0, sizeof(op));

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 
							 TEEC_VALUE_INOUT,		//param for encrypted key
							 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;

		strcat(path, argv[3]);
		FILE *fp_key = fopen(path, "r");
		fscanf(fp_key, "%d", &cipherkey);
		op.params[1].value.a = cipherkey;
		fclose(fp_key);
			
		char path2[100] = "/root/";

		strcat(path2, argv[2]);
		FILE *fp = fopen(path2, "r");
		fgets(ciphertext, sizeof(ciphertext), fp);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		fclose(fp);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);

		FILE *fp_decrypted = fopen("/root/decrypted.txt", "w");

		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		fputs(plaintext, fp_decrypted);
		fclose(fp_decrypted);
			
		
	}else if(strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "RSA") == 0){

		memset(&op, 0, sizeof(op));

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = clear;
		op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
		op.params[1].tmpref.buffer = ciph;
		op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;
		

		strcat(path, argv[2]);
		FILE *fp = fopen(path, "r");
		// file open
		fgets(clear, sizeof(clear), fp);
		// file text copy plain text

		fclose(fp);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_GENKEYS, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
		printf("\n=========== Keys already generated. ==========\n");

			
			
			
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENC,
				 &op, &err_origin);
		if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",	res, err_origin);

			
			
		char encrypted_path[100] = "/root/encrypt_RSA_";
		strcat(encrypted_path, argv[2]);
		FILE *fp_encrypted = fopen(encrypted_path, "w");

		memcpy(ciphertext, op.params[1].tmpref.buffer, len);
		fputs(ciphertext, fp_encrypted);
		fclose(fp_encrypted);


		

	}

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);


	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
