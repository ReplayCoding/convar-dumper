#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <stdio.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <dlfcn.h>
#include <sys/mman.h>

#include <fmt/core.h>
#include <fmt/os.h>
#include <nlohmann/json.hpp>

#include <link.h>

#include <convar.h>

struct ModuleInfo {
  std::string name;
  uintptr_t addr;
  uintptr_t length;
};

struct Pattern {
  Pattern(std::vector<uint8_t> pat, std::vector<uint8_t> mask) : m_mask(mask) {
    for (size_t i = 0; i < pat.size(); i++) {
      pat[i] = pat[i] & mask[i];
    }

    m_pat = pat;
  }

  std::vector<uint8_t> m_pat;
  std::vector<uint8_t> m_mask;
};

Pattern convar_register_pat{
    std::vector<uint8_t>{
        0xa1, 0xb0, 0x9a, 0x11, 0x00, 0x85, 0xc0, 0x74, 0x09, 0x80, 0x3d, 0xa0,
        0x75, 0x11, 0x00, 0x00, 0x74, 0x06, 0xc3, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x55, 0x89, 0xe5, 0x56, 0x53, 0x83, 0xec, 0x10, 0xc6, 0x05, 0xa0, 0x75,
        0x11, 0x00, 0x01, 0x8b, 0x55, 0x08, 0x89, 0x15, 0xb0, 0x75, 0x11, 0x00,
        0x8b, 0x10, 0x89, 0x04, 0x24, 0xff, 0x52, 0x14, 0x8b, 0x4d, 0x0c, 0x8b,
        0x1d, 0x10, 0x74, 0x11, 0x00, 0xa3, 0x80, 0x30, 0x06, 0x00, 0xb8, 0x74,
        0x30, 0x06, 0x00, 0x85, 0xc9, 0x0f, 0x45, 0x45, 0x0c, 0x85, 0xdb, 0xa3,
        0x00, 0x74, 0x11, 0x00, 0x75, 0x08, 0xeb, 0x27, 0xff, 0xff, 0xff, 0xff},
    std::vector<uint8_t>{
        0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xf8, 0x00, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xf8, 0xff, 0xff, 0x38, 0xff, 0xf8,
        0x00, 0xff, 0xf8, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff, 0xf8, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00}};

Pattern connect_t1_pat{
    {
        0x55, 0x89, 0xe5, 0x56, 0x53, 0x83, 0xec, 0x10, 0x80, 0x3d, 0xd0, 0x9a,
        0x11, 0x00, 0x00, 0x8b, 0x75, 0x0c, 0x75, 0x2e, 0x85, 0xf6, 0xc6, 0x05,
        0xd0, 0x9a, 0x11, 0x00, 0x01, 0x7e, 0x23, 0x31, 0xdb, 0x8d, 0xb4, 0x26,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0x15, 0xb0, 0x9a, 0x11, 0x00, 0x85, 0xd2,
        0x74, 0x1e, 0xa1, 0xa0, 0x9a, 0x11, 0x00, 0x85, 0xc0, 0x74, 0x45, 0x83,
        0xc3, 0x01, 0x39, 0xf3, 0x75, 0xe6, 0x83, 0xc4, 0x10, 0x5b, 0x5e, 0x5d,
        0xc3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8b, 0x45, 0x08, 0xc7,
        0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x04, 0x24, 0x76, 0xfb,
    },
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0xf8, 0x00, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0x3f,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff,
        0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xf8, 0x00, 0xff,
        0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x38, 0x00, 0x00,
    }};

// How inconsistent can I get?
void LogError(const std::string &s) { std::cerr << (s + "\n"); }

CreateInterfaceFn createinterface_vs = nullptr;

void *createinterface_wrapper(char *pName, int *pReturnCode) {
  void *iface = CreateInterface(pName, pReturnCode);
  if (!iface)
    iface = createinterface_vs(pName, pReturnCode);
  // fmt::print("{} {}\n", pName, fmt::ptr(iface));
  return iface;
}

struct ConVarInfo {
  ConVarInfo(std::string name, std::string desc,
             std::vector<std::string_view> flags,
             std::optional<std::string> default_value, bool is_command)
      : m_name(name), m_desc(desc), m_flags(flags), m_default(default_value),
        m_is_command(is_command) {}

  std::string m_name;
  std::string m_desc;
  std::vector<std::string_view> m_flags;
  std::optional<std::string> m_default;
  bool m_is_command;
};

struct ConVarFlags {
  int bit;
  const char *desc;
};

#define CONVARFLAG(x, y)                                                       \
  { FCVAR_##x, #y }
static ConVarFlags g_ConVarFlags[] = {
    // CONVARFLAG(UNREGISTERED, ""),
    CONVARFLAG(DEVELOPMENTONLY, "developmentonly"),
    CONVARFLAG(GAMEDLL, "gamedll"),
    CONVARFLAG(CLIENTDLL, "clientdll"),
    CONVARFLAG(HIDDEN, "hidden"),
    CONVARFLAG(PROTECTED, "protected"),
    CONVARFLAG(SPONLY, "sponly"),
    CONVARFLAG(ARCHIVE, "archive"),
    CONVARFLAG(NOTIFY, "notify"),
    CONVARFLAG(USERINFO, "userinfo"),
    CONVARFLAG(CHEAT, "cheat"),
    CONVARFLAG(PRINTABLEONLY, "printableonly"),
    CONVARFLAG(UNLOGGED, "unlogged"),
    CONVARFLAG(NEVER_AS_STRING, "never_as_string"),
    CONVARFLAG(REPLICATED, "replicated"),
    CONVARFLAG(DEMO, "demo"),
    CONVARFLAG(DONTRECORD, "dontrecord"),
    CONVARFLAG(RELOAD_MATERIALS, "reload_materials"),
    CONVARFLAG(RELOAD_TEXTURES, "reload_textures"),
    CONVARFLAG(NOT_CONNECTED, "not_connected"),
    CONVARFLAG(MATERIAL_SYSTEM_THREAD, "material_system_thread"),
    CONVARFLAG(ARCHIVE_XBOX, "archive_xbox"),
    CONVARFLAG(ACCESSIBLE_FROM_THREADS, "accessible_from_threads"),
    CONVARFLAG(SERVER_CAN_EXECUTE, "server_can_execute"),
    CONVARFLAG(SERVER_CANNOT_QUERY, "server_cannot_query"),
    CONVARFLAG(CLIENTCMD_CAN_EXECUTE, "clientcmd_can_execute"),
};

std::vector<ConVarInfo> convar_infos;

class CustomConCommandAccessor : public IConCommandBaseAccessor {
public:
  virtual bool RegisterConCommandBase(ConCommandBase *pVar) override {
    std::vector<std::string_view> flags;
    for (ConVarFlags &flag_to_check : g_ConVarFlags) {
      if (pVar->IsFlagSet(flag_to_check.bit))
        flags.emplace_back(flag_to_check.desc);
    }

    std::string name = pVar->GetName();
    std::string desc = pVar->GetHelpText();
    std::optional<std::string> default_value = std::nullopt;

    bool is_command;
    if (ConVar *cVar = dynamic_cast<ConVar *>(pVar)) {
      is_command = false;
      if (cVar->GetDefault())
        default_value = cVar->GetDefault();
    } else {
      is_command = true;
    }
    ConVarInfo cvar_info =
        ConVarInfo(name, desc, flags, default_value, is_command);

    convar_infos.push_back(cvar_info);
    return true;
  }
};

const char *file_to_do_magic_on = "";

uint32_t query_page_size(void) { return sysconf(_SC_PAGE_SIZE); }

void mprotect_page_noalign(void *addr, size_t size, int prot) {
  uint32_t page_size = query_page_size();
  void *aligned_address = (void *)((uint64_t)(addr) & ~(page_size - 1));

  size_t end = (uint64_t)addr + size;
  size_t new_size = end - (uint64_t)aligned_address;

  mprotect(aligned_address, new_size, prot);
}

void *get_pattern(ModuleInfo mod, Pattern pat) {
  uintptr_t pat_size = pat.m_pat.size();
  for (uintptr_t i = mod.addr; i < (mod.addr + mod.length - pat_size); i++) {
    bool found = true;
    for (uintptr_t j = 0; j < pat_size; j++) {
      uint8_t value = *(char *)(i + j);
      // fmt::print("Got value for {:08X} {}\n", i, j);
      found &= (pat.m_pat[j] == (value & pat.m_mask[j]));

      if (!found)
        break;
    }

    if (found)
      return (void *)i;
  }

  return nullptr;
}

// void *get_symbol(const std::unique_ptr<LIEF::ELF::Binary> &binary,
//                  uintptr_t baddr, std::string str) {
//   const auto sym = binary->get_symbol(str);
//   if (sym == nullptr) {
//     LogError("sym is nullptr\n");
//     return nullptr;
//   }
//
//   auto func = (baddr + sym->value());
//   if (baddr == 0 || sym->value() == 0 || func == 0) {
//     LogError("func is nullptr\n");
//     return nullptr;
//   }
//
//   return (void *)func;
// }

int main(int argc, char **argv) {
  if (argc > 1) {
    char *buf = (char *)malloc(MAX_PATH);
    strncpy(buf, argv[1], MAX_PATH - 1);
    file_to_do_magic_on = basename(buf);
  } else
    return 1;

  // Hook tier0 to disable CreateSimpleThread, matsys will crash otherwise.
  void *handle_t0 = dlopen("libtier0.so", RTLD_NOW | RTLD_LOCAL);
  // HACK HACK HACK ALERT XXX TODO FIXME THIS WILL CAUSE PROBLEMS MAYBE?
  void *create_simple_thread_func = dlsym(RTLD_NEXT, "CreateSimpleThread");

  static const uint8_t shellcode[8] = {0x55, 0x48, 0x8b, 0xec,
                                       0x33, 0xc0, 0xc9, 0xc3};

  mprotect_page_noalign(create_simple_thread_func, sizeof(shellcode),
                        PROT_READ | PROT_WRITE | PROT_EXEC);
  memcpy(create_simple_thread_func, shellcode, sizeof(shellcode));

  auto handle_vs = dlopen("libvstdlib.so", RTLD_NOW);
  auto ci = dlsym(handle_vs, "CreateInterface");
  if (handle_vs == nullptr) {
    LogError("no vstdlib handle!");
    return 1;
  }
  createinterface_vs = ci;

  auto handle = dlopen(file_to_do_magic_on, RTLD_NOW);
  // if (handle == nullptr)
  //   handle = dlopen("server.so", RTLD_NOW);

  if (handle == nullptr) {
    LogError(fmt::format("Handle is nullptr {}\n", dlerror()));
    return 1;
  }

  ModuleInfo module_info;
  dl_iterate_phdr(
      [](dl_phdr_info *info, size_t info_size, void *user_data) {
        auto *module_info = std::bit_cast<ModuleInfo *>(user_data);
        const std::string_view fname = basename(info->dlpi_name);

        constexpr std::string_view vsdo_path = "linux-vdso.so.1";

        if (info->dlpi_addr == 0 || info->dlpi_name == nullptr ||
            info->dlpi_name[0] == '\0') {
          return 0;
        } else if (vsdo_path == fname) {
          return 0;
        }

        uintptr_t end_addr = info->dlpi_addr;
        for (size_t i = 0; i < info->dlpi_phnum; i++) {
          ElfW(Phdr) phdr = info->dlpi_phdr[i];
          end_addr = std::max(
              end_addr, (info->dlpi_addr + (phdr.p_vaddr + phdr.p_memsz)));
        }

        if (fname == file_to_do_magic_on) {
          *module_info = {std::string(info->dlpi_name),
                          static_cast<uintptr_t>(info->dlpi_addr),
                          end_addr - static_cast<uintptr_t>(info->dlpi_addr)};
          return 1;
        }

        return 0;
      },
      &module_info);

  // const std::unique_ptr<LIEF::ELF::Binary> lief_mod =
  //     LIEF::ELF::Parser::parse(module_info.name);
  //
  // if (lief_mod == nullptr) {
  //   LogError("lIEF failed\n");
  //   return 3;
  // }

  typedef void (*ConnectTier1Libraries_t)(CreateInterfaceFn * pFactoryList,
                                          int nFactoryCount);
  typedef void (*ConVar_Register_t)(int nCVarFlag,
                                    IConCommandBaseAccessor *pAccessor);

  auto connectt1 =
      (ConnectTier1Libraries_t)get_pattern(module_info, connect_t1_pat);
  if (connectt1 == nullptr) {
    LogError("ConnectTier1Libraries is nullptr\n");
    return 2;
  }

  auto convar_register =
      (ConVar_Register_t)get_pattern(module_info, convar_register_pat);
  if (convar_register == nullptr) {
    LogError("ConVar_Register is nullptr\n");
    return 2;
  }

  CreateInterfaceFn factory = createinterface_wrapper;
  connectt1(&factory, 1);

  CustomConCommandAccessor accessor{};
  convar_register(0, &accessor);

  struct ConvarSort {
    bool operator()(const ConVarInfo &a, const ConVarInfo &b) {
      return a.m_name < b.m_name;
    }
  };
  std::sort(convar_infos.begin(), convar_infos.end(), ConvarSort());

  for (ConVarInfo &info : convar_infos) {
    std::string flag_string = "";
    for (std::string_view flag : info.m_flags) {
      flag_string += fmt::format(" {}", flag);
    }

    if (info.m_is_command) {
      fmt::print("ccommand {}\n", info.m_name);
    } else {
      fmt::print("convar {}\n", info.m_name);
    }
    fmt::print("flags: {}\n", flag_string);
    if (info.m_default)
      fmt::print("default: {}\n", info.m_default.value());

    fmt::print("{}\n", info.m_desc);

    fmt::print("\n");
  }

  dlclose(handle);

  return 0;
}
