import json
import re
import argparse
import urllib.request
from clang.cindex import *
import os

argparser = argparse.ArgumentParser()
argparser.add_argument("apis", help="paths to a nt header files (ntzwapi.h, ntuser.h, ntgdi.h)", nargs="+")
argparser.add_argument("--presets", help="path to j00ru's x64/json folder", required=True)
args = argparser.parse_args()

def quote_nullable_c_str(s):
    return '"%s"' % s if s else "nullptr"

class ApiParameter:
    def __init__(self, type_name, name):
        self.type_name = type_name
        self.name = name

    def __str__(self):
        assert self.type_name
        return '{ "%s", %s }' % (self.type_name, quote_nullable_c_str(self.name))

class ApiDescriptor:
    def __init__(self, name="", return_type=""):
        self.name = name
        self.return_type = return_type
        self.parameters: list[ApiParameter] = []

    def __str__(self):
        return '{ "%s", "%s", { %s } }' % (self.name, self.return_type, ", ".join(str(x) for x in self.parameters))

def parse_file(filename):
    # can't be bothered to mess with a complete C parser and toolchain
    # simple and works well enough

    apis = {}

    with open(filename, "r") as file:
        contents = file.read()

    # remove annotations
    for macro in [ r"_In_\w*", r"_Inout_\w*", r"_Out_\w*", "_Reserved_", "OUT", "IN", "OPTIONAL", "NTSYSCALLAPI", "NTAPI", "APIENTRY", "FAR" ]:
        contents = re.sub(fr"\b{macro}\b(\([^\)]*\))?\s?", "", contents)

    # remove comments
    contents = re.sub(r"\/\/[^\r\n]*", "", contents)

    # parse api declarations
    for return_type, api_name, params_string in re.findall(r"(\w+)\s+(\w+)\(([^\)]*)\);", contents):
        if (api_name.startswith("Nt") or api_name.startswith("Zw")) and not api_name.startswith("NtUserfn"):
            api_name = "Nt" + api_name[2:]
            params = [ x.strip() for x in params_string.split(",") ]
            desc = ApiDescriptor(api_name, return_type)

            if params != ["VOID"] and params != [""]:
                for param in params:
                    split = [ x for x in param.split(" ") if x ]

                    if len(split) > 1:
                        type_name = split[-2]
                        param_name = split[-1]
                    else:
                        type_name = split[0]
                        param_name = ""

                    has_pointer = "*" in type_name or "*" in param_name or param_name.endswith("[]")
                    type_name = type_name.strip("*")
                    param_name = param_name.strip("*[]")
                    if has_pointer:
                        type_name += " *"

                    desc.parameters.append(ApiParameter(type_name, param_name))

            apis[api_name] = desc
    
    return apis

def parse_presets():
    with open(os.path.join(args.presets, "nt-per-system.json"), "r") as file:
        nt_per_system = json.load(file)

    with open(os.path.join(args.presets, "win32k-per-system.json"), "r") as file:
        win32k_per_system = json.load(file)

    result = {}

    for per_system in [ nt_per_system, win32k_per_system ]:
        for os_name, builds in per_system.items():
            for build_name, api_to_syscall in builds.items():
                key = "%s > %s" % (os_name, build_name)
                if key not in result:
                    result[key] = {}
                result[key].update(api_to_syscall)

    return result

# syscall id & 0xfff -> index into nt_api_descriptors
def create_syscall_map(preset_name, api_to_syscall, api_to_index, is_win32k):
    result = []
    syscall_to_api = { value: api for api, value in api_to_syscall.items() }
    for index in range(max(api_to_syscall.values())):
        if index in syscall_to_api:
            api = syscall_to_api[index]
            if api in api_to_index:
                result.append(api_to_index[api])
            else:
                assert False
        else:
            # print("// WARNING: missing api for syscall id 0x%x in %s" % (index | 0x1000 if is_win32k else index, preset_name))
            result.append(None)
    return result

if __name__ == "__main__":
    print("// Generated with generate_nt_syscalls.py")
    
    apis = {}

    for header in args.apis:
        apis.update(parse_file(header))

    presets = parse_presets()
    preset_apis = set(x for a, b in presets.items() for x in b)
    missing_apis = list(preset_apis - set(apis.keys()))
    unknown_apis = list(set(apis.keys()) - preset_apis)

    print()
    print("// APIs parsed from j00ru presets: %u" % len(preset_apis))
    print("// APIs parsed from header files: %u" % len(apis))
    print("// Missing API definitions: %u" % len(missing_apis))
    print("// APIs missing from presets: %u" % len(unknown_apis))
    print()

    print("const nt_api_descriptor nt_api_descriptors[] = {")
    print(",\n".join('\t%s' % x for x in apis.values()))
    print("};\n")

    print("const char *const nt_missing_apis[] = {")
    print(",\n".join(
        "\t" + ", ".join('"%s"' % missing_apis[j] for j in range(i, min(i+10, len(missing_apis))))
        for i in range(0, len(missing_apis), 10)
    ))
    print("};")

    api_to_index = { value: index for index, value in enumerate(list(apis.keys()) + missing_apis) }

    lines = []

    for preset_name, api_to_syscall in presets.items():
        nt_map = create_syscall_map(preset_name, { api: id for api, id in api_to_syscall.items() if id < 0x1000 }, api_to_index, False)
        win32k_map = create_syscall_map(preset_name, { api: id & 0xfff for api, id in api_to_syscall.items() if id >= 0x1000 }, api_to_index, True)

        lines.append('\t{ "%s", {\n\t\t{ %s },\n\t\t{ %s }\n\t} }' % (
            preset_name,
            ",".join(str(i + 1) if i is not None else "0" for i in nt_map),
            ",".join(str(i + 1) if i is not None else "0" for i in win32k_map)
        ))
    
    print("\nconst std::pair<const char *, nt_syscall_map_t> nt_syscall_maps[] = {")
    print(",\n".join(lines))
    print("};\n")

