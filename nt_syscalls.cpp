#include <fstream>

#include <hexsuite.hpp>
#include <linuxpe>

#include "nt_syscalls.hpp"

const nt_api_descriptor *nt_api_id_t::get_descriptor() const
{
    if (id > 0 && id <= std::size(nt_api_descriptors))
        return &nt_api_descriptors[id - 1];
    return nullptr;
}

const char *nt_api_id_t::get_missing() const
{
    if (id > 0 && id > std::size(nt_api_descriptors) && id <= std::size(nt_api_descriptors) + std::size(nt_missing_apis))
        return nt_missing_apis[id - 1 - std::size(nt_api_descriptors)];
    return nullptr;
}

static std::vector<uint8_t> read_file(const char *filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if (file.is_open())
    {
        const auto size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> result(size);
        if (file.read((char *)result.data(), size))
        {
            return result;
        }
    }

    return {};
}

// simple class for the mostly safe parsing of arbitrary 64-bit PE files
class image_view
{
    std::vector<uint8_t> buffer{};

public:
    image_view(std::vector<uint8_t> buffer) : buffer(std::move(buffer)) {}
    image_view(const image_view &) = delete;
    image_view &operator=(const image_view &) = delete;

    const win::image_x64_t *data() const
    {
        return (const win::image_x64_t *)buffer.data();
    }

    bool contains_range(size_t offset, size_t size) const
    {
        return size <= buffer.size() && offset <= buffer.size() - size;
    }

    template <typename T>
    const T *at(size_t offset) const
    {
        return contains_range(offset, sizeof(T)) ? (const T *)&buffer[offset] : nullptr;
    }

    bool check_pointer(const void *ptr, size_t size) const
    {
        if ((const uint8_t *)ptr < buffer.data()) return false;
        return contains_range((const uint8_t *)ptr - buffer.data(), size);
    }

    bool valid() const
    {
        auto *dos_header = at<win::dos_header_t>(0);
        if (!dos_header)
            return false;

        auto *nt_headers = at<win::nt_headers_x64_t>(dos_header->e_lfanew);
        if (!nt_headers)
            return false;

        if (nt_headers->signature != win::NT_HDR_MAGIC || nt_headers->optional_header.magic != win::OPT_HDR64_MAGIC)
            return false;

        if (nt_headers->optional_header.num_data_directories > win::NUM_DATA_DIRECTORIES)
            return false;

        size_t opt_hdr_offset = (const uint8_t *)&nt_headers->optional_header - buffer.data();
        size_t opt_hdr_reported_end = opt_hdr_offset + nt_headers->file_header.size_optional_header;
        size_t opt_hdr_end = opt_hdr_offset + offsetof(win::optional_header_x64_t, data_directories) + nt_headers->optional_header.num_data_directories * sizeof(win::data_directory_t);

        if (opt_hdr_reported_end < opt_hdr_end)
            return false;

        size_t sections_end = opt_hdr_reported_end + nt_headers->file_header.num_sections * sizeof(win::section_header_t);
        size_t headers_end = nt_headers->optional_header.size_headers;

        if (headers_end < sections_end)
            return false;

        if (buffer.size() < headers_end)
            return false;

        return true;
    }

    template <typename T>
    const T *resolve_rva(uint32_t rva, size_t size_bytes = sizeof(T)) const
    {
        const auto *ptr = data()->rva_to_ptr<T>(rva, size_bytes);

        if (!ptr)
            return nullptr;
        
        if (!check_pointer(ptr, size_bytes))
            return nullptr;

        return ptr;
    }
};

nt_syscall_map_t extract_syscall_ids(const char *filename)
{
    image_view view(read_file(filename));

    if (!view.valid())
        return {};

    const auto *export_data_directory = view.data()->get_directory(win::directory_entry_export);
    if (!export_data_directory)
        return {};

    const auto *export_directory = view.resolve_rva<win::export_directory_t>(export_data_directory->rva, export_data_directory->size);
    if (!export_directory)
        return {};

    const auto *rvas = view.resolve_rva<uint32_t>(export_directory->rva_functions, export_directory->num_functions * sizeof(uint32_t));
    const auto *names = view.resolve_rva<uint32_t>(export_directory->rva_names, export_directory->num_names * sizeof(uint32_t));
    const auto *ordinals = view.resolve_rva<uint16_t>(export_directory->rva_name_ordinals, export_directory->num_names * sizeof(uint16_t));

    std::map<uint32_t, const char *> sorted_exports {};
    bool is_win32u = false;

    for (size_t i = 0; i < export_directory->num_names; i++)
    {
        if (const char *name = view.resolve_rva<char>(names[i]))
        {
            sorted_exports[rvas[ordinals[i]]] = name;
            if (!is_win32u && strcmp(name, "NtGdiGetPixel") == 0)
                is_win32u = true;
        }        
    }

    size_t id = is_win32u ? 0x1000 : 0;
    uint16_t prefix = is_win32u ? 'tN' : 'wZ';
    std::vector<uint16_t> result{};

    for (const auto &[rva, name] : sorted_exports)
    {
        if (*(uint16_t *)name == prefix)
        {
            const auto *code = view.resolve_rva<uint8_t>(rva, 3);
            if (!code)
            {
                msg("Failed to resolve export %s, rva %X\n", name, rva);
                return {};
            }

            // sanity check. win32u has some Nt* exports that aren't syscalls
            if (is_win32u && memcmp(code, "\x4C\x8B\xD1", 3) != 0) // mov r10, rcx
            {
                msg("Invalid prologue for export %s, rva %X\n", name, rva);
                continue;
            }

            // find API
            const auto syscall_id = id++;
            bool mapped = false;

            for (size_t i = 0; i < nt_total_apis; i++)
            {
                bool has_definition = i < std::size(nt_api_descriptors);
                const char *api_name = has_definition ? nt_api_descriptors[i].api_name : nt_missing_apis[i - std::size(nt_api_descriptors)];
                if (strcmp(api_name + 2, name + 2) == 0)
                {
                    result.push_back(i + 1);
                    msg("Mapped %s, ID %04X%s\n", name, syscall_id, !has_definition ? " (NO DEFINITION)" : "");
                    mapped = true;
                    break;
                }
            }

            if (!mapped)
            {
                msg("Failed to find API for syscall %s, ID %04X\n", name, syscall_id);
            }
        }
    }

    return is_win32u ? nt_syscall_map_t { {}, std::move(result) } : nt_syscall_map_t { std::move(result), {} };
}