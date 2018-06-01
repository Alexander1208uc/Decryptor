#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<functional>

namespace Decryptor_space {
#define EX_PORT __declspec(dllexport)   


#define BYTEn(x, n) (*((BYTE *)&(x) + n))
#define WORDn(x, n) (*((WORD *)&(x) + n))
#define DWORDn(x, n) (*((DWORD *)&(x) + n))

#define IDA_LOBYTE(x) BYTEn(x, 0)
#define IDA_LOWORD(x) WORDn(x, 0)
#define IDA_LODWORD(x) WORDn(x, 0)
#define IDA_HIBYTE(x) BYTEn(x, 1)
#define IDA_HIWORD(x) WORDn(x, 1)
#define IDA_HIDWORD(x) DWORDn(x, 1)

#define BYTE1(x) BYTEn(x, 1)
#define BYTE2(x) BYTEn(x, 2)
#define WORD1(x) WORDn(x, 1)
#define DWORD1(x) DWORDn(x, 1)

	typedef uint64_t(*decrypt_func)(uint64_t);

	struct uint128_t {
		uint64_t low;
		uint64_t high;
	};
	struct rel_addr {
		uint32_t offset;
		uint32_t addr;
	};
	struct Tsl {
		decrypt_func func;
	};

	struct Vector3 {
		Vector3() : x(0.f), y(0.f), z(0.f)
		{

		}

		Vector3(float _x, float _y, float _z) : x(_x), y(_y), z(_z)
		{

		}
		~Vector3()
		{

		}

		float x;
		float y;
		float z;

		inline float Dot(Vector3 v)
		{
			return x * v.x + y * v.y + z * v.z;
		}

		inline float Distance(Vector3 v)
		{
			return float(sqrtf(powf(v.x - x, 2.0) + powf(v.y - y, 2.0) + powf(v.z - z, 2.0)));
		}

		Vector3 operator+(Vector3 v)
		{
			return Vector3(x + v.x, y + v.y, z + v.z);
		}

		Vector3 operator-(Vector3 v)
		{
			return Vector3(x - v.x, y - v.y, z - v.z);
		}
	};

	struct vector2d {
		float x;
		float y;
	};

	struct minimal_view_info {
		struct vector2d off_center_projection_offset;
		// uint8_t
		uint32_t projection_mode;
		float aspect_ratio;
		float fov;
		float ortho_width;
		struct Vector3 location;
		float post_process_blend_weight;
		struct Vector3 rotation;
		// pack(16)
		//char post_process_settings[0x530];
		//float ortho_near_clip_plane;
		//uint8_t constrain_aspect_ratio : 1;
		//uint8_t use_field_of_view_for_lod : 1;
		//float ortho_far_clip_plane;
	};
	typedef minimal_view_info minimal_view_info_;

	struct camera_cache_entry {
		float time_stamp;
		uint32_t pad[3];
		minimal_view_info_ pov;
	};
	typedef camera_cache_entry camera_cache_entry_;

	class EX_PORT Decryptor {
	public:
		std::function<bool(uint64_t, void *, size_t)> READ;
		std::function<uint64_t(uint64_t)> READ64;
		std::function<uint32_t(uint32_t)> READ32;

		int tsl_init(uint64_t base, uint64_t table);
		void tsl_finit();
		uint64_t tsl_decrypt_prop(uint64_t prop);
		uint64_t tsl_decrypt_actor(uint64_t actor);
		camera_cache_entry getCameraCacheEntry(uint64_t cce_address);
	private:
		Tsl * tsl;
		uint64_t TABLE;
		uint64_t g_base_addr;
		uint64_t GET_ADDR(uint64_t addr);
		uint64_t tsl_decrypt_world(uint64_t world);
		uint64_t tsl_decrypt_gnames(uint64_t gnames);
		uint64_t decrypt(uint64_t func, uint64_t arg);
	};

}