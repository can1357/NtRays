#pragma once
	  
#include <array>
#include <string>
#include <utility>
#include <vector>
	  
struct nt_api_descriptor
{
	struct argument_descriptor
	{
		const char *type_name;
		const char *name;
	};

	const char *api_name;
	const char *return_type_name;
	std::vector<argument_descriptor> arguments;

	inline std::string arguments_to_string() const
	{
		std::string result {};
		if (!arguments.empty())
		{
			result += arguments[0].type_name;
			for (size_t i = 1; i < arguments.size(); i++)
			{
				result += ", ";
				result += arguments[i].type_name;
			}
		}
		return result;
	}

	inline std::string to_string() const
	{
		std::string result = return_type_name;
		result += " ";
		result += api_name;
		result += "(" + arguments_to_string() + ")";
		return result;
	};
};

struct nt_api_id_t {
	// 1 <= id <= std::size(nt_api_descriptors) + std::size(nt_missing_apis)
	uint16_t id;

	nt_api_id_t(uint16_t id) : id(id) {}

	const nt_api_descriptor *get_descriptor() const;
	const char *get_missing() const;

	explicit operator bool() const
	{
		return get_descriptor() || get_missing();
	}
};

struct nt_syscall_map_t
{
	std::vector<uint16_t> nt {}; // id -> api id
	std::vector<uint16_t> win32k {}; // id & 0xfff -> api id

	inline bool valid() const
	{
		return !nt.empty() || !win32k.empty();
	}

	inline void apply(nt_syscall_map_t other)
	{
		if (!other.nt.empty())
			nt = std::move(other.nt);
		if (!other.win32k.empty())
			win32k = std::move(other.win32k);
	}

	inline nt_api_id_t get_api_id(size_t syscall_id) const
	{
		const auto &map = syscall_id < 0x1000 ? nt : win32k;
		syscall_id &= 0xfff;
		return syscall_id < map.size() ? map[syscall_id] : 0;
	}

	constexpr static size_t blob_header_size = sizeof(uint16_t) + sizeof(uint16_t);

	inline std::vector<uint8_t> serialize() const
	{
		std::vector<uint8_t> result(blob_header_size + (nt.size() + win32k.size()) * sizeof(uint16_t));

		auto *buffer = (uint16_t *)result.data();
		*buffer++ = (uint16_t)nt.size();
		*buffer++ = (uint16_t)win32k.size();
		std::copy(nt.begin(), nt.end(), buffer);
		buffer += nt.size();
		std::copy(win32k.begin(), win32k.end(), buffer);

		return result;
	}

	inline void deserialize(const std::vector<uint8_t> &data)
	{
		if (data.size() > blob_header_size)
		{
			auto *buffer = (uint16_t *)data.data();
			size_t nt_size = *buffer++;
			size_t win32k_size = *buffer++;
			if (data.size() >= blob_header_size + (nt_size + win32k_size) * sizeof(uint16_t))
			{
				nt.resize(nt_size);
				std::copy(buffer, buffer + nt.size(), nt.begin());
				buffer += nt.size();
				win32k.resize(win32k_size);
				std::copy(buffer, buffer + win32k.size(), win32k.begin());
				return;
			}
		}

		nt.clear();
		win32k.clear();
	}
};

nt_syscall_map_t extract_syscall_ids(const char *filename);

#include "nt_syscalls.inc"

constexpr size_t nt_total_apis = std::size(nt_api_descriptors) + std::size(nt_missing_apis);
