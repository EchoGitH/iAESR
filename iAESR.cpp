#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "time.h"
#define SEGMENT_SIZE 4 // 32位 = 4字节
#define MAX_SEGMENTS 10000 // 最大分割数

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

int Plaintext_num_segments = 0;

u32 get_bits_32(u32 num, unsigned int index, unsigned int offset) {
	return (num >> index) & ((1 << offset) - 1);
}

// same as changed_bit_32() when offset==1
u32 changed_bits_32(u32 num, u32 bits, int index, int offset) {
	if ((index + offset) == 32)
		return ((num << offset) >> offset) | (bits << index);
	else
		return (num >> (index + offset) << (index + offset)) | (bits << index) | (((num << (31 - index)) << 1) >> (32 - index));
}

u64 get_bit_64(u64 num, unsigned int index) {
	return (num >> index) & 1;
}

u64 changed_bit_64(u64 num, unsigned int index) {
	return (num >> index) & 1;
}

u64 changed_bit_64(u64 num, u64 bit, unsigned int index) {
	return ((num >> (index + 1)) << (index + 1)) | (bit << index) | ((num << (64 - index)) >> (64 - index));
}

u64 get_bits_64(u64 num, unsigned int index, unsigned int offset) {
	return (num << (64 - index - offset)) >> (64 - offset);
}

u64 changed_bits_64(u64 num, u64 bits, int index, int offset) {
	if ((index + offset) == 64)
		return ((num << offset) >> offset) | (bits << index);
	else
		return (num >> (index + offset) << (index + offset)) | (bits << index) | (((num << (63 - index)) << 1) >> (64 - index));
}

void prodece_constant() {
	for (int i = 0;i < 16;i++) {
		unsigned int r = rand() % 32; //constant r
	}
}
u8 rotate_left_8(u8 num, unsigned int displacement) {
	return (num >> (8 - displacement) | (num << displacement));
}

u64 subenc_key_generator1(u64 key, u8 const constant) {
	//AddRoundconstant
	key = changed_bits_64(key, get_bits_64(constant, 0, 5) ^ get_bits_64(key, 3, 5), 3, 5);
	//NX Module
	u64 key_0 = key;// Intermediate variable
	u64 t_0 = get_bit_64(key, 56) ^ get_bit_64(key, 62);
	u64 t_1 = get_bit_64(key, 57) ^ get_bit_64(key, 63);
	u64 t_2 = get_bit_64(key_0, 58) ^ t_0;
	u64 t_3 = get_bit_64(key_0, 59) ^ t_1;
	u64 t_4 = get_bit_64(key_0, 60) ^ t_2;
	u64 t_5 = get_bit_64(key_0, 61) ^ t_3;
	u64 t_6 = get_bit_64(key_0, 62) ^ t_4;
	u64 t_7 = get_bit_64(key_0, 63) ^ t_5;
	key = changed_bit_64(key, get_bit_64(key_0, 56) & t_0, 56);
	key = changed_bit_64(key, get_bit_64(key_0, 57) & t_1, 57);
	key = changed_bit_64(key, get_bit_64(key_0, 58) & t_2, 58);
	key = changed_bit_64(key, get_bit_64(key_0, 59) & t_3, 59);
	key = changed_bit_64(key, get_bit_64(key_0, 60) & t_4, 60);
	key = changed_bit_64(key, get_bit_64(key_0, 61) & t_5, 61);
	key = changed_bit_64(key, get_bit_64(key_0, 62) & t_6, 62);
	key = changed_bit_64(key, get_bit_64(key_0, 63) & t_7, 63);
	//permutation
	key_0 = key;// Intermediate variable
	key = changed_bits_64(key, get_bits_64(key_0, 56, 4), 0, 4);
	key = changed_bits_64(key, get_bits_64(key_0, 16, 12), 4, 12);
	key = changed_bits_64(key, get_bits_64(key_0, 60, 4), 16, 4);
	key = changed_bits_64(key, get_bits_64(key_0, 28, 12), 20, 12);
	key = changed_bits_64(key, get_bits_64(key_0, 40, 16), 32, 16);
	key = changed_bits_64(key, get_bits_64(key_0, 0, 16), 48, 16);
	return key;
}

u8 get_keys(u64 num, unsigned int index) {
	u8 key = 0;
	key = changed_bits_32(key, get_bits_64(num, index, 4), 0, 4);
	key = changed_bits_32(key, get_bits_64(num, index + 8, 4), 4, 4);
	return key;
}

void permutation(u32 data[], u64 key_gen[], int* key_gen_num) {
	for (unsigned int i = 0;i < 16;i++) {
		//unsigned int r = rand() % 32; //constant r
		u64 new_key = subenc_key_generator1(key_gen[*key_gen_num], 0);
		(*key_gen_num)++;
		key_gen[*key_gen_num] = new_key;
		for (unsigned int j = 0;j <= 3;j++) {
			u8 L_0 = get_bits_32(data[j], 0, 8);
			u8 L_1 = get_bits_32(data[j], 8, 8);
			u8 R_0 = get_bits_32(data[j], 16, 8);
			u8 R_1 = get_bits_32(data[j], 24, 8);
			u8 state_0 = (rotate_left_8(L_0, 1) & rotate_left_8(L_0, 7)) ^ L_1 ^ rotate_left_8(L_0, 2);
			u8 state_1 = (rotate_left_8(R_0, 1) & rotate_left_8(R_0, 7)) ^ R_1 ^ rotate_left_8(R_0, 2);
			data[j] = changed_bits_32(data[j], state_1, 0, 8);
			data[j] = changed_bits_32(data[j], rotate_left_8((rotate_left_8(state_0, 1) & rotate_left_8(state_0, 7)) ^ L_0 ^ rotate_left_8(state_0, 2) ^ get_keys(key_gen[*key_gen_num], 16), 1), 8, 8);
			data[j] = changed_bits_32(data[j], state_0, 16, 8);
			data[j] = changed_bits_32(data[j], rotate_left_8((rotate_left_8(state_1, 1) & rotate_left_8(state_1, 7)) ^ R_0 ^ rotate_left_8(state_1, 2) ^ get_keys(key_gen[*key_gen_num], 20), 7), 24, 8);
		}
	}
	// linear permutation
	u32 num_0 = data[0];
	for (unsigned int j = 0;j <= 2;j++) {
		data[j] = data[j + 1];
	}
	data[3] = num_0;
}

void Initialization(u64 nounce, u32 state[], u64 key_gen[], int* key_gen_num) {
	u64 new_key = changed_bit_64(key_gen[*key_gen_num], get_bit_64(key_gen[*key_gen_num], 0) ^ 1, 0);
	(*key_gen_num)++;
	key_gen[*key_gen_num] = new_key;
	state[0] = get_bits_64(nounce, 32, 32);
	state[1] = get_bits_64(nounce, 0, 32);
	state[2] = get_bits_64(key_gen[0], 32, 32);
	state[3] = get_bits_64(key_gen[0], 0, 32);
	permutation(state, key_gen, key_gen_num);
	state[3] = state[3] ^ 0x1u;
}

void Padding(const char* str, unsigned int* arr, int* num_segments) {
	int len = strlen(str);
	*num_segments = (len + SEGMENT_SIZE - 1) / SEGMENT_SIZE; // count the num of segnents

	for (int i = 0; i < *num_segments; i++) {
		unsigned int num = 0;
		for (int j = 0; j < SEGMENT_SIZE; j++) {
			int index = i * SEGMENT_SIZE + j;
			if (index < len) {
				num = (num << 8) | (unsigned char)str[index]; // combination
			}
			else {
				num = num | 0x10000000u;
			}
		}
		arr[i] = num; // 存入数组
	}
}

void Processing_Associated_Data(u32 associated_data[], u32 state[], int segments, u64 enc_key_gen[], int* enc_key_gen_num) {
	printf("\n\n                       关联数据处理                      \n\n");
	printf("  轮次     state[0]      state[1]      state[2]      state[3]\n");
	printf("---------------------------------------------------------------\n");
	for (int i = 0; i < segments; i++) {
		permutation(state, enc_key_gen, enc_key_gen_num);
		state[0] = state[0] ^ associated_data[i];
		printf("  %3d      %8x      %8x      %8x      %8x\n", i, state[0], state[1], state[2], state[3]);
	}
	printf("---------------------------------------------------------------\n");
	permutation(state, enc_key_gen, enc_key_gen_num);
}

void Processing_Plaintext(u32 Plaintext[], u32 state[], u32 Ciphertext[], u64* tag, int segments, u64 enc_key_gen[], int* enc_key_gen_num) {
	printf("\n\n                       明文数据处理                       \n\n");
	printf("  轮次     state[0]      state[1]      state[2]      state[3]\n");
	printf("---------------------------------------------------------------\n");
	for (int i = 0;i < segments;i++) {
		permutation(state, enc_key_gen, enc_key_gen_num);
		state[0] = state[0] ^ Plaintext[i];
		Ciphertext[i] = state[0];
		printf("  %3d      %8x      %8x      %8x      %8x\n", i, state[0], state[1], state[2], state[3]);
	}
	//Ciphertext[segments-1] = (Ciphertext[segments-1]) << 24;
	printf("---------------------------------------------------------------\n");
	state[3] = state[3] ^ 0x1u;
	*tag = changed_bits_64(*tag, state[2], 0, 32);
	*tag = changed_bits_64(*tag, state[3], 32, 32);
	*tag = *tag ^ enc_key_gen[0];

}

void Processing_Ciphertext(u32 Ciphertext[], u32 state[], u32 Decryptedtext[], u64* tag, int segments, u64 dec_key_gen[], int* dec_key_gen_num) {
	printf("\n\n                       密文数据处理                       \n\n");
	printf("  轮次     state[0]      state[1]      state[2]      state[3]\n");
	printf("---------------------------------------------------------------\n");
	for (int i = 0;i < segments;i++) {
		permutation(state, dec_key_gen, dec_key_gen_num);
		Decryptedtext[i] = state[0] ^ Ciphertext[i];
		state[0] = Ciphertext[i];
		printf("  %3d      %8x      %8x      %8x      %8x\n", i, state[0], state[1], state[2], state[3]);
	}
	printf("---------------------------------------------------------------\n");
	//Ciphertext[segments-1] = (Ciphertext[segments-1]) << 24;
	state[3] = state[3] ^ 0x1u;
	*tag = changed_bits_64(*tag, state[2], 0, 32);
	*tag = changed_bits_64(*tag, state[3], 32, 32);
	*tag = *tag ^ dec_key_gen[0];
}

void AESR_Encryption(char Plaintext[], u32 Ciphertext_32[], u64 nounce, u32 state[], u64 enc_key_gen[], int enc_key_gen_num, u64* tag) {
	Initialization(nounce, state, enc_key_gen, &enc_key_gen_num);
	char associated_data[] = "We are very honored to participate in this competition";
	unsigned int associated_data_32[MAX_SEGMENTS];
	int associated_data_num_segments = 0;
	Padding(associated_data, associated_data_32, &associated_data_num_segments);
	Processing_Associated_Data(associated_data_32, state, associated_data_num_segments, enc_key_gen, &enc_key_gen_num);
	unsigned int Plaintext_32[MAX_SEGMENTS];
	Padding(Plaintext, Plaintext_32, &Plaintext_num_segments);
	Processing_Plaintext(Plaintext_32, state, Ciphertext_32, tag, Plaintext_num_segments, enc_key_gen, &enc_key_gen_num);
	printf("\n\n                       密文输出                       \n\n");
	printf("    轮次       明文分组        密文分组  \n");
	printf("--------------------------------------------------------\n");
	for (int i = 0;i < Plaintext_num_segments;i++) {
		printf("   %d          %8x         %8x\n", i, Plaintext_32[i], Ciphertext_32[i]);
	}
	printf("--------------------------------------------------------\n");
}

void AESR_Decryption(u32 Ciphertext_32[], u32 Decryptedtext_32[], u64 nounce, u32 state[], u64 dec_key_gen[], int dec_key_gen_num, u64* tag) {
	Initialization(nounce, state, dec_key_gen, &dec_key_gen_num);
	char associated_data[] = "111111111111111111111111111111111";
	unsigned int associated_data_32[MAX_SEGMENTS];
	int associated_data_num_segments = 0;
	Padding(associated_data, associated_data_32, &associated_data_num_segments);
	Processing_Associated_Data(associated_data_32, state, associated_data_num_segments, dec_key_gen, &dec_key_gen_num);
	Processing_Ciphertext(Ciphertext_32, state, Decryptedtext_32, tag, Plaintext_num_segments, dec_key_gen, &dec_key_gen_num);
}

int main() {
	u64 nounce = 0xad75e1234ab3u;
	int enc_key_gen_num = 0;
	u64 enc_key_gen[MAX_SEGMENTS];
	int dec_key_gen_num = 0;
	u64 dec_key_gen[MAX_SEGMENTS];
	dec_key_gen[0] = 0x6cd32e63790747aeu;
	enc_key_gen[0] = 0x6cd32e63790747aeu;
	u32 enc_state[4];
	u32 dec_state[4];
	u64 tag_enc = 0;
	u64 tag_dec = 0;
	char Plaintext[] = "This project number is CACR2024HI7UPS";
	printf("加密数据为：%s", Plaintext);
	u32 Ciphertext_32[MAX_SEGMENTS];
	printf("\n-----------------------加密与认证-------------------------------------\n");
	clock_t start_time, end_time;
	start_time = clock();   //获取开始执行时间
	AESR_Encryption(Plaintext, Ciphertext_32, nounce, enc_state, enc_key_gen, enc_key_gen_num, &tag_enc);
	end_time = clock();     //获取结束时间
	double Times = (double)(end_time - start_time) / CLOCKS_PER_SEC;
	printf("%f seconds\n", Times);
	u32 Decryptedtext_32[MAX_SEGMENTS];
	printf("\n-----------------------解密与验证-------------------------------------\n\n");
	AESR_Decryption(Ciphertext_32, Decryptedtext_32, nounce, dec_state, dec_key_gen, dec_key_gen_num, &tag_dec);
	printf("\n");
	printf("\n\n                     tag输出                    \n\n");
	printf("--------------------------------------------------------\n");
	if (tag_enc == tag_dec) {
		printf("%本次认证加密输出的Tag为   %8llX.\n\n现解密验证生成的Tag为     %llX.\n\n两个tag是否相等：是.\n", tag_enc, tag_dec);
		printf("\n\n                       明文输出                       \n\n");
		printf("    轮次       密文分组        明文分组  \n");
		printf("--------------------------------------------------------\n");
		for (int i = 0;i < Plaintext_num_segments;i++) {
			printf("   %d          %8x         %8x\n", i, Ciphertext_32[i], Decryptedtext_32[i]);
		}
		printf("--------------------------------------------------------\n");
	}
	return 0;
}
