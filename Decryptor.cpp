
#include "Decryptor.h"
using namespace Decryptor_space;
//extern uint64_t g_base_addr;

// roll functions
#pragma region roll
static uint8_t rol1(uint8_t x, unsigned int count) {
	count %= 8;
	return (x << count) | (x >> (8 - count));
}

static uint16_t rol2(uint16_t x, unsigned int count) {
	count %= 16;
	return (x << count) | (x >> (16 - count));
}

static uint32_t rol4(uint32_t x, unsigned int count) {
	count %= 32;
	return (x << count) | (x >> (32 - count));
}

static uint64_t rol8(uint64_t x, unsigned int count) {
	count %= 64;
	return (x << count) | (x >> (64 - count));
}

static uint8_t ror1(uint8_t x, unsigned int count) {
	count %= 8;
	return (x << (8 - count)) | (x >> count);
}

static uint16_t ror2(uint16_t x, unsigned int count) {
	count %= 16;
	return (x << (16 - count)) | (x >> count);
}

static uint32_t ror4(uint32_t x, unsigned int count) {
	count %= 32;
	return (x << (32 - count)) | (x >> count);
}

static uint64_t ror8(uint64_t x, unsigned int count) {
	count %= 64;
	return (x << (64 - count)) | (x >> count);
}
#pragma endregion

// public functions
#pragma region public
int Decryptor::tsl_init(uint64_t base, uint64_t table) {
	tsl = new Tsl();
	tsl->func = (decrypt_func)VirtualAlloc(NULL, 0x200, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (tsl->func == NULL) {
		return 0;
	}
	g_base_addr = base;
	TABLE = table;
	return 1;
}

void Decryptor::tsl_finit() {
	if (tsl && tsl->func != NULL) {
		VirtualFree(tsl->func, 0, MEM_RELEASE);
		tsl->func = NULL;
		delete tsl;
	}
}

uint64_t Decryptor::tsl_decrypt_actor(uint64_t actor) {
	struct uint128_t xmm;
	if (!READ(actor, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((((uint8_t)(((uint16_t)((IDA_HIWORD(key) - 16660) ^ ~((~(uint16_t)key + 6) ^ 0xFFFA)) >> 8) - 106) + 76) ^ (uint8_t)~((~((BYTE2(key) - 20) ^ ~((~(uint8_t)key + 6) ^ 0xFA)) + 54) ^ 0xCA)) % 128));
	return ror8(decrypt( func, key + rol8(key + xmm.high, 8 * (key & 7))), 50);
}

uint64_t Decryptor::tsl_decrypt_prop(uint64_t prop) {
	struct uint128_t xmm;
	if (!READ(prop, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint32_t x;
	uint32_t y;
	uint64_t z;
	x = ((uint16_t)~((~IDA_HIWORD(key) + 74) ^ 0xFFB6) + 31374) ^ (uint16_t)(key - 82);
	y = (uint8_t)(((~((~BYTE2(key) + 74) ^ 0xB6) - 114) ^ (key - 82)) + 30) ^ ((uint8_t)(BYTE1(x) + 2) + 100);
	z = key & 2 ? xmm.high ^ key : xmm.high + key;
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (y % 128));
	return ror8(decrypt(func, z), 86);
}

camera_cache_entry Decryptor::getCameraCacheEntry(uint64_t cce_address) {
	struct camera_cache_entry cce;
	READ(cce_address, &cce, sizeof(struct camera_cache_entry));
	return cce;
}

#pragma endregion

// private funcitons
#pragma region privatee

uint64_t Decryptor::GET_ADDR(uint64_t addr) {
	return g_base_addr + addr;
}

static int find_call(const uint8_t *buf, uint32_t size, struct rel_addr *ret) {
	uint32_t offset = 0;
	while (offset < (size - 5)) {
		if (buf[offset] == 0xe8) {
			uint32_t addr = *(uint32_t *)(buf + (offset + 1));
			if (addr < 0x8000) {
				ret->offset = offset + 5;
				ret->addr = addr;
				return 1;
			}
		}
		offset++;
	}
	return 0;
}

static uint32_t get_func_len(const uint8_t *buf, uint32_t size, uint8_t start, uint32_t end) {
	if (*buf == start) {
		uint32_t offset = 0;
		while (offset < (size - sizeof(end))) {
			if (*(uint32_t *)(buf + offset) == end) {
				return offset;
			}
			offset++;
		}
	}
	return 0;
}

uint64_t Decryptor::decrypt(uint64_t func, uint64_t arg) {
	uint8_t buf_0x100[0x100];
	if (!READ(func, buf_0x100, 0x100)) {
		return 0;
	}
	struct rel_addr rel_addr;
	if (!find_call(buf_0x100, 0x100, &rel_addr)) {
		return 0;
	}
	uint64_t abs_addr = func + (rel_addr.offset + rel_addr.addr);
	uint8_t buf_0x20[0x20];
	if (!READ(abs_addr, buf_0x20, 0x20)) {
		return 0;
	}
	uint32_t len = get_func_len(buf_0x20, 0x20, 0x48, 0xccccccc3);
	if (!len || len > 0xf) {
		return 0;
	}
	uint32_t temp = rel_addr.offset - 5;
	memcpy(tsl->func, buf_0x100, temp);
	memcpy((char *)tsl->func + temp, buf_0x20, len);
	memcpy((char *)tsl->func + (temp + len), buf_0x100 + rel_addr.offset, 0x100 - rel_addr.offset);
	uint64_t ret = tsl->func(arg);
	memset(tsl->func, 0, 0x200);
	return ret;
}

uint64_t Decryptor::tsl_decrypt_world(uint64_t world) {
	return 0;
}

uint64_t Decryptor::tsl_decrypt_gnames(uint64_t gnames) {
	return 0;
}

#pragma endregion

