#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// same as get_bit_32() when offset==1
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

u64 changed_bit_64(u64 num, u64 bit, unsigned int index) {
	return ((num >> (index + 1)) << (index + 1)) | (bit << index) | ((num << (64 - index)) >> (64 - index));
}
// same as get_bit_64() when offset==1
u64 get_bits_64(u64 num, unsigned int index, unsigned int offset) {
	return (num << (64 - index - offset)) >> (64 - offset);
}

// same as changed_bit_64() when offset==1
u64 changed_bits_64(u64 num, u64 bits, int index, int offset) {
	if ((index + offset) == 64)
		return ((num << offset) >> offset) | (bits << index);
	else
		return (num >> (index + offset) << (index + offset)) | (bits << index) | (((num << (63 - index)) << 1) >> (64 - index));
}

u64 subkey_generator1(u64 key, u8 const constant) {
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

u8 rotate_left_8(u8 num, unsigned int displacement) {
	return (num >> (8 - displacement) | (num << displacement));
}

u8 get_keys(u64 num, unsigned int index) {
	u8 key = 0;
	key = changed_bits_32(key, get_bits_64(num, index, 4), 0, 4);
	key = changed_bits_32(key, get_bits_64(num, index + 8, 4), 4, 4);
	return key;
}
u32 round_function(u32 num, u64 key) {
	//添加步骤，num取逆
	u8 L_0 = get_bits_32(num, 0, 8);
	u8 L_1 = get_bits_32(num, 8, 8);
	u8 R_0 = get_bits_32(num, 16, 8);
	u8 R_1 = get_bits_32(num, 24, 8);
	u8 state_0 = (rotate_left_8(L_0, 1) & rotate_left_8(L_0, 7)) ^ L_1 ^ rotate_left_8(L_0, 2) ^ get_keys(key, 0);
	u8 state_1 = (rotate_left_8(R_0, 1) & rotate_left_8(R_0, 7)) ^ R_1 ^ rotate_left_8(R_0, 2) ^ get_keys(key, 4);
	num = changed_bits_32(num, state_1, 0, 8);
	//num = changed_bits_32(num, (rotate_left_8(state_0, 1) & rotate_left_8(state_0, 7)) ^ L_0 ^ rotate_left_8(state_0, 2) ^ get_keys(key, 16), 8, 8);
	num = changed_bits_32(num, rotate_left_8((rotate_left_8(state_0, 1) & rotate_left_8(state_0, 7)) ^ L_0 ^ rotate_left_8(state_0, 2) ^ get_keys(key, 16), 1), 8, 8);
	num = changed_bits_32(num, state_0, 16, 8);
	//num = changed_bits_32(num, (rotate_left_8(state_1, 1) & rotate_left_8(state_1, 7)) ^ R_0 ^ rotate_left_8(state_1, 2) ^ get_keys(key, 20), 24, 8);
	num = changed_bits_32(num, rotate_left_8((rotate_left_8(state_1, 1) & rotate_left_8(state_1, 7)) ^ R_0 ^ rotate_left_8(state_1, 2) ^ get_keys(key, 20), 7), 24, 8);
	return num;
}

u32 encryption_routine_32(u32 num, u64 key) {
	for (unsigned int r = 1;r <= 16;r++) {
		key = subkey_generator1(key, r);
		num = round_function(num, key);
		//printf("第 %lu 轮的密文: %X\n", r, num);
	}
	return num;
}
// 差分分析函数
void differential_analysis(u64 key, u32 num_0[], u32 num_1[]) {
	// 生成明文对并加密
	u32 probability_1 = 0xffffffff;
	for (int i = 0;i < 32;i++) {
		printf("%lX，%lX\n", num_0[i], num_1[i]);
		num_0[i] = round_function(num_0[i], key);
		num_0[i] = round_function(num_0[i], key);
		num_1[i] = round_function(num_1[i], key);
		num_1[i] = round_function(num_1[i], key);
		probability_1 = probability_1 & (num_0[i] ^ num_1[i]);
		printf("%lX，%lX，差分：%lX， %lX\n", num_0[i], num_1[i], num_0[i] ^ num_1[i], probability_1);
	}
}

int main() {
	u32 num_0[32];
	u32 num_1[32];
	u64 key = 0x0u;
	u32 j = 1;
	u32 num = 0x400000u;
	for (int i = 0;i < 32;i++) {
		if (pow(2, i) != num) {
			num_0[i] = pow(2, 32) - pow(2, i);
			num_1[i] = pow(2, 32) - (pow(2, i) + num);
		}
		else {
			num_0[i] = pow(2, i);
			num_1[i] = 0;
		}
	}
	differential_analysis(key, num_0, num_1);

return 0;
}
