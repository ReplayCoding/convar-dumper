#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <ostream>
#include <stdio.h>
#include <string>
#include <string_view>
#include <utility>

#include <dlfcn.h>
#include <sys/mman.h>

#include <LIEF/ELF.hpp>
#include <fmt/core.h>
#include <fmt/os.h>
#include <nlohmann/json.hpp>

#include <link.h>

#include <tier1/tier1.h>

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

struct ConVarFlags_t {
  int bit;
  const char *desc;
  const char *shortdesc;
};

#define CONVARFLAG(x, y)                                                       \
  { FCVAR_##x, #x, #y }
static ConVarFlags_t g_ConVarFlags[] = {
    //	CONVARFLAG( UNREGISTERED, "u" ),
    CONVARFLAG(ARCHIVE, "a"),
    CONVARFLAG(SPONLY, "sp"),
    CONVARFLAG(GAMEDLL, "sv"),
    CONVARFLAG(CHEAT, "cheat"),
    CONVARFLAG(USERINFO, "user"),
    CONVARFLAG(NOTIFY, "nf"),
    CONVARFLAG(PROTECTED, "prot"),
    CONVARFLAG(PRINTABLEONLY, "print"),
    CONVARFLAG(UNLOGGED, "log"),
    CONVARFLAG(NEVER_AS_STRING, "numeric"),
    CONVARFLAG(REPLICATED, "rep"),
    CONVARFLAG(DEMO, "demo"),
    CONVARFLAG(DONTRECORD, "norecord"),
    CONVARFLAG(SERVER_CAN_EXECUTE, "server_can_execute"),
    CONVARFLAG(CLIENTCMD_CAN_EXECUTE, "clientcmd_can_execute"),
    CONVARFLAG(CLIENTDLL, "cl"),
};

class CustomConCommandAccessor : public IConCommandBaseAccessor {
public:
  virtual bool RegisterConCommandBase(ConCommandBase *pVar) override {
    std::string flags;
    for (ConVarFlags_t &flag_to_check : g_ConVarFlags) {
      if (pVar->IsFlagSet(flag_to_check.bit))
        // no comma at start, total waste :)
        if (flags.empty())
          flags += fmt::format("{}", flag_to_check.shortdesc);
        else
          flags += fmt::format(",{}", flag_to_check.shortdesc);
    }

    auto name = pVar->GetName();
    auto help_text = pVar->GetHelpText();

    if (ConVar *cVar = dynamic_cast<ConVar *>(pVar)) {
      fmt::print("cvar '{}' flags: [{}] default: '{}' {}\n", name, flags,
                 cVar->GetDefault(), help_text);
    } else
      fmt::print("ccommand '{}' flags: [{}] {}\n", name, flags, help_text);
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

int main(int argc, char **argv) {
  if (argc > 1) {
    char *buf = (char *)malloc(MAX_PATH);
    strncpy(buf, argv[1], MAX_PATH - 1);
    file_to_do_magic_on = basename(buf);
  } else
    return 1;

  // Hook tier0 to disable CreateSimpleThread, matsys will crash otherwise.
  void *handle_t0 = dlopen("libtier0_srv.so", RTLD_NOW | RTLD_LOCAL);
  // HACK HACK HACK ALERT XXX TODO FIXME THIS WILL CAUSE PROBLEMS
  void *create_simple_thread_func = dlsym(RTLD_NEXT, "CreateSimpleThread");

  static const uint8_t shellcode[8] = {0x55, 0x48, 0x8b, 0xec,
                                       0x33, 0xc0, 0xc9, 0xc3};

  mprotect_page_noalign(create_simple_thread_func, sizeof(shellcode),
                        PROT_READ | PROT_WRITE | PROT_EXEC);
  memcpy(create_simple_thread_func, shellcode, sizeof(shellcode));

  auto handle_vs = dlopen("libvstdlib_srv.so", RTLD_NOW);
  auto ci = dlsym(handle_vs, "CreateInterface");
  if (handle_vs == nullptr) {
    LogError("???\n");
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

  std::pair<std::string, uintptr_t> module_info;
  dl_iterate_phdr(
      [](dl_phdr_info *info, size_t info_size, void *user_data) {
        auto *module_info =
            std::bit_cast<std::pair<std::string, uintptr_t> *>(user_data);
        const std::string_view fname = basename(info->dlpi_name);

        constexpr std::string_view vsdo_path = "linux-vdso.so.1";

        if (info->dlpi_addr == 0 || info->dlpi_name == nullptr ||
            info->dlpi_name[0] == '\0') {
          return 0;
        } else if (vsdo_path == fname) {
          return 0;
        }

        auto end_addr = info->dlpi_addr;
        for (size_t i = 0; i < info->dlpi_phnum; i++) {
          end_addr = info->dlpi_addr +
                     (info->dlpi_phdr->p_vaddr + info->dlpi_phdr->p_memsz);
        }

        if (fname == file_to_do_magic_on) {
          *module_info = {std::string(info->dlpi_name),
                          static_cast<uintptr_t>(info->dlpi_addr)};
          return 1;
        }

        return 0;
      },
      &module_info);

  const std::unique_ptr<LIEF::ELF::Binary> lief_mod =
      LIEF::ELF::Parser::parse(module_info.first);

  if (lief_mod == nullptr) {
    LogError("lIEF failed\n");
    return 3;
  }

  const auto cvr_sym =
      lief_mod->get_symbol("_Z15ConVar_RegisteriP23IConCommandBaseAccessor");
  if (cvr_sym == nullptr) {
    LogError("ConVar_Register sym is nullptr\n");
    return 2;
  }

  const auto connectt1_sym =
      lief_mod->get_symbol("_Z21ConnectTier1LibrariesPPFPvPKcPiEi");
  if (connectt1_sym == nullptr) {
    LogError("ConnectTier1Libraries sym is nullptr\n");
    return 2;
  }

  typedef void (*ConnectTier1Libraries_t)(CreateInterfaceFn * pFactoryList,
                                          int nFactoryCount);
  typedef void (*ConVar_Register_t)(int nCVarFlag,
                                    IConCommandBaseAccessor *pAccessor);

  auto connectt1 =
      (ConnectTier1Libraries_t)(module_info.second + connectt1_sym->value());
  if (module_info.second == 0 || connectt1_sym->value() == 0 ||
      connectt1 == 0) {
    LogError("ConnectTier1Libraries is nullptr\n");
    return 2;
  }

  auto convar_register =
      (ConVar_Register_t)(module_info.second + cvr_sym->value());
  if (module_info.second == 0 || cvr_sym->value() == 0 ||
      convar_register == 0) {
    LogError("ConVar_Register is nullptr\n");
    return 2;
  }

  CreateInterfaceFn factory = createinterface_wrapper;
  connectt1(&factory, 1);

  CustomConCommandAccessor accessor{};
  convar_register(0, &accessor);

  dlclose(handle);

  return 0;
}
