import json
import re
import argparse
import urllib.request

argparser = argparse.ArgumentParser()
argparser.add_argument("--ntapi", help="path to phnt's ntzwapi.h", required=False)
argparser.add_argument("--ntpersystem", help="path to j00ru's x64 nt-per-system.json", required=False)
args = argparser.parse_args()

if args.ntapi:
    with open(args.ntapi, "r") as file:
        nt_source = file.read()
else:
    nt_source = urllib.request.urlopen("https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/phnt/include/ntzwapi.h").read().decode()

if args.ntpersystem:
    with open(args.ntpersystem, "r") as file:
        nt_per_system = json.load(file)
else:
    nt_per_system = json.load(urllib.request.urlopen("https://raw.githubusercontent.com/j00ru/windows-syscalls/refs/heads/master/x64/json/nt-per-system.json"))

print("""// generated with generate_ntdefs.py
// nt data sourced from:
// - https://github.com/j00ru/windows-syscalls/blob/master/x64/json/nt-per-system.json
// - https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntzwapi.h

#pragma once
      
#include <array>
#include <string>
#include <utility>
#include <vector>
      
struct nt_api_descriptor {
	struct argument_descriptor {
		const char *type_name;
		const char *name;
	};

	const char *api_name;
	const char *return_type;
	std::vector<argument_descriptor> arguments;

	inline std::string arguments_to_string() const {
		std::string result {};
		if (!arguments.empty()) {
			result += arguments[0].type_name;
			for (size_t i = 1; i < arguments.size(); i++) {
				result += ", ";
				result += arguments[i].type_name;
			}
		}
		return result;
	}

	inline std::string to_string() const {
		std::string result = return_type;
		result += " ";
		result += api_name;
		result += "(" + arguments_to_string() + ")";
		return result;
	};
};
""")

pattern = re.compile(r"(\w+)\s+NTAPI\s+(\w+)\(([\s\S]+?)\)\;") # yikes
apis = {}

for return_type, api_name, args_string in pattern.findall(nt_source):
    assert api_name.startswith("Zw")

    # for parsing sake, assume each argument is on its own line
    args = [ x.split("//")[0].strip().strip(",") for x in args_string.split("\n") ]
    args = [ x for x in args if x ]
    infos = []

    if args != [ "VOID" ]:
        for arg in args:
            # yikes x2
            info = re.findall(r"([\w\*]+) ([\*\w\[\]]+)$", arg)
            assert info, arg
            info = info[0]
            is_pointer = "*" in info[0] or "*" in info[1] or info[1].endswith("[]")
            info = [ info[0].strip("*"), info[1].strip("*[]") ]
            if is_pointer:
                info[0] += "*"
            infos.append(info)

    apis["Nt" + api_name[2:]] = [ return_type, infos ]
            
print("const nt_api_descriptor nt_api_descriptors[] = {")
print(",\n".join('\t{ "%s", "%s", { %s } }' % (k, v[0], ", ".join('{ "%s", "%s" }' % (at, an) for at, an in v[1])) for k, v in apis.items()))
print("};\n")

api_to_index = { value: index for index, value in enumerate(apis.keys()) }

# now map win ver to lists of signatures

result = {}
syscall_map_capacity = 512
warned = set()

for os_name, builds in nt_per_system.items():
    for build, api_to_syscall in builds.items():
        syscall_to_api = { value: api for api, value in api_to_syscall.items() }
        syscall_list = []
        max_syscall = max(api_to_syscall.values())
        assert max_syscall < syscall_map_capacity
        for id in range(max_syscall):
            if id in syscall_to_api:
                api = syscall_to_api[id]
                if api in api_to_index:
                    syscall_list.append(api_to_index[api])
                else:
                    if api not in warned:
                        print("// WARNING: no definition for %s (id %u) in %s" % (api, id, os_name + " " + build))
                        warned.add(api)
                    syscall_list.append(None)
            else:
                print("// WARNING: missing api for syscall id %u in %s" % (id, os_name + " " + build))
                syscall_list.append(None)
        result[os_name + " > " + build] = syscall_list

print("\nconst std::pair<const char *, std::array<uint16_t, %u>> nt_syscall_maps[] = {" % syscall_map_capacity)
print(",\n".join('\t{ "%s", { { %s } } }' % (name, ", ".join(str(i + 1) if i is not None else "0" for i in syscalls)) for name, syscalls in result.items()))
print("};\n")

