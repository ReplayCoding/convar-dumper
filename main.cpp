#include <dlfcn.h>
#include <dt_send.h>
#include <eiface.h>
#include <fmt/core.h>
#include <interface.h>
#include <server_class.h>
#include <stdio.h>
#include <string>
#include <string_view>
#include <utility>

#include "generator.hpp"

struct ServerProp {
  ServerProp() = default;
  ServerProp(std::ptrdiff_t offset, SendPropType type)
      : offset(offset), type(type){};

  std::ptrdiff_t offset{};
  SendPropType type{};
};
template <> struct fmt::formatter<SendPropType> : formatter<std::string_view> {
  // parse is inherited from formatter<string_view>.
  template <typename FormatContext>
  auto format(SendPropType c, FormatContext &ctx) const {
    std::string_view name = "unknown";
    switch (c) {
    case DPT_Int:
      name = "int";
      break;
    case DPT_Float:
      name = "float";
      break;
    case DPT_Vector:
      name = "vector";
      break;
    case DPT_VectorXY:
      name = "vectorxy";
      break;
    case DPT_String:
      name = "string";
      break;
    case DPT_Array:
      name = "array";
      break;
    case DPT_DataTable:
      name = "datatable";
      break;
    case DPT_NUMSendPropTypes:
      name = "numsendproptypes";
      break;
    }
    return formatter<std::string_view>::format(name, ctx);
  }
};

Generator<std::pair<std::string, ServerProp>> parse_tbl(SendTable *tbl) {
  for (auto idx = 0; idx < tbl->GetNumProps(); idx++) {
    auto prop = tbl->GetProp(idx);

    auto prop_type = prop->GetType();
    if (prop_type == SendPropType::DPT_DataTable) {
      auto subtable = prop->GetDataTable();
      auto parsed_subtable = parse_tbl(subtable);

      for (const auto &[name, subprop] : parsed_subtable) {
        const auto subprop_name =
            fmt::format("{}::{}", subtable->GetName(), name);

        co_yield std::pair(
            subprop_name,
            ServerProp(prop->GetOffset() + subprop.offset, subprop.type));
      };
    } else {
      co_yield std::pair(std::string(prop->GetName()),
                         ServerProp(prop->GetOffset(), prop_type));
    }
  }
}

int main(int argc, char **argv) {
  auto handle = dlopen("server.so", RTLD_NOW);
  if (handle == nullptr) {
    fmt::print("Handle is nullptr {}\n", dlerror());
    return 1;
  }

  auto create_interface = (CreateInterfaceFn)dlsym(handle, "CreateInterface");
  if (create_interface == nullptr) {
    fmt::print("CreateInterface is nullptr\n");
    return 1;
  }

  int retcode{};
  auto *dll = (IServerGameDLL *)create_interface(INTERFACEVERSION_SERVERGAMEDLL,
                                                 &retcode);
  if (dll == nullptr) {
    fmt::print("dll is nullptr\n");
    return 1;
  }

  for (auto server_class = dll->GetAllServerClasses(); server_class != nullptr;
       server_class = server_class->m_pNext) {
    auto class_name = server_class->GetName();
    fmt::print("{}\n", class_name);

    for (auto &[prop_name, prop] : parse_tbl(server_class->m_pTable)) {
      fmt::print("\t {} @ {:08X} ({})\n", prop_name, prop.offset, prop.type);
    };
  }

  dlclose(handle);

  return 0;
}
