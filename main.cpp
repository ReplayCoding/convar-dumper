#include <dlfcn.h>
#include <dt_common.h>
#include <dt_send.h>
#include <eiface.h>
#include <fmt/core.h>
#include <interface.h>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/for_each.hpp>
#include <range/v3/view/join.hpp>
#include <server_class.h>
#include <stdio.h>
#include <string>
#include <string_view>
#include <utility>

#include "generator.hpp"

struct ServerProp {
  std::ptrdiff_t offset{};
  SendPropType type{};
  int flags{};
};

auto get_flags_as_str(int flags) {
  std::vector<std::string> s_flags{};
  if (flags & SPROP_UNSIGNED)
    s_flags.emplace_back("UNSIGNED");
  if (flags & SPROP_COORD)
    s_flags.emplace_back("COORD");
  if (flags & SPROP_NOSCALE)
    s_flags.emplace_back("NOSCALE");
  if (flags & SPROP_ROUNDDOWN)
    s_flags.emplace_back("ROUNDDOWN");
  if (flags & SPROP_ROUNDUP)
    s_flags.emplace_back("ROUNDUP");
  if (flags & SPROP_EXCLUDE)
    s_flags.emplace_back("EXCLUDE");
  if (flags & SPROP_INSIDEARRAY)
    s_flags.emplace_back("INSIDEARRAY");
  if (flags & SPROP_PROXY_ALWAYS_YES)
    s_flags.emplace_back("PROXY_ALWAYS_YES");
  if (flags & SPROP_CHANGES_OFTEN)
    s_flags.emplace_back("CHANGES_OFTEN");
  if (flags & SPROP_IS_A_VECTOR_ELEM)
    s_flags.emplace_back("IS_A_VECTOR_ELEM");
  if (flags & SPROP_COLLAPSIBLE)
    s_flags.emplace_back("COLLAPSIBLE");
  if (flags & SPROP_COORD_MP)
    s_flags.emplace_back("COORD_MP");
  if (flags & SPROP_COORD_MP_LOWPRECISION)
    s_flags.emplace_back("COORD_MP_LOWPRECISION");
  if (flags & SPROP_COORD_MP_INTEGRAL)
    s_flags.emplace_back("COORD_MP_INTEGRAL");

  // Shared with VARINT, because valve are WIMPS who don't want to break demo
  // compatibility.
  // TODO:: FIX THIS
  if (flags & SPROP_NORMAL || flags & SPROP_VARINT)
    s_flags.emplace_back("NORMAL/VARINT");

  return s_flags;
}

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

        co_yield std::pair(subprop_name,
                           ServerProp(prop->GetOffset() + subprop.offset,
                                      subprop.type, subprop.flags));
      };
    } else {
      co_yield std::pair(
          std::string(prop->GetName()),
          ServerProp(prop->GetOffset(), prop_type, prop->GetFlags()));
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
      auto flags_l = get_flags_as_str(prop.flags);
      std::string flags =
          flags_l | ranges::views::join('|') | ranges::to<std::string>();
      fmt::print("\t {} @ {:08X} {} ({})\n", prop_name, prop.offset, prop.type,
                 flags);
    };
  }

  dlclose(handle);

  return 0;
}
