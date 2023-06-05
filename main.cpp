#include <dlfcn.h>
#include <dt_common.h>
#include <dt_send.h>
#include <eiface.h>
#include <fmt/core.h>
#include <interface.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <ostream>
#include <server_class.h>
#include <stdio.h>
#include <string>
#include <string_view>
#include <utility>

struct ServerProp {
  std::string name;
  // offset is unused rn
  std::ptrdiff_t offset{};
  SendPropType type{};
  int flags{};
};

auto get_flags_as_str(const ServerProp &prop) {
  std::vector<std::string> s_flags{};

  auto flags = prop.flags;
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

  // Shared with VARINT, because valve didn't want to break demo
  // compatibility.
  if (flags & SPROP_NORMAL || flags & SPROP_VARINT) {
    switch (prop.type) {
    case DPT_Int:
      s_flags.emplace_back("VARINT");
      break;
    case DPT_Float:
    case DPT_Vector:
      s_flags.emplace_back("NORMAL");
      break;
    default:
      s_flags.emplace_back("UNKNOWN");
      break;
    }
  }

  return s_flags;
}

std::string_view prop_type_to_str(SendPropType t) {
  switch (t) {
  case DPT_Int:
    return "int";
  case DPT_Float:
    return "float";
  case DPT_Vector:
    return "vector";
  case DPT_VectorXY:
    return "vectorxy";
  case DPT_String:
    return "string";
  case DPT_Array:
    return "array";
  case DPT_DataTable:
    return "datatable";
  case DPT_NUMSendPropTypes:
    return "numsendproptypes";
  default:
    return "unknown";
  }
}

void to_json(nlohmann::json &j, const ServerProp &prop) {
  j = nlohmann::json{{"name", prop.name},
                     {"type", std::string(prop_type_to_str(prop.type))},
                     {"flags", get_flags_as_str(prop)},
                     {"offset", prop.offset}};
}

std::vector<ServerProp> parse_tbl(SendTable *tbl) {
  std::vector<ServerProp> props;

  for (auto idx = 0; idx < tbl->GetNumProps(); idx++) {
    auto prop = tbl->GetProp(idx);

    auto prop_type = prop->GetType();
    if (prop_type == SendPropType::DPT_DataTable) {
      auto subtable = prop->GetDataTable();
      auto parsed_subtable = parse_tbl(subtable);

      for (const auto &subprop : parsed_subtable) {
        const auto subprop_name =
            fmt::format("{}::{}", subtable->GetName(), subprop.name);

        props.emplace_back(subprop_name, prop->GetOffset() + subprop.offset,
                           subprop.type, subprop.flags);
      };
    } else {
      props.emplace_back(std::string(prop->GetName()), prop->GetOffset(),
                         prop_type, prop->GetFlags());
    }
  }

  return props;
}

int main(int argc, char **argv) {
  auto handle = dlopen("server_srv.so", RTLD_NOW);
  if (handle == nullptr)
    handle = dlopen("server.so", RTLD_NOW);

  if (handle == nullptr) {
    fmt::print("Handle is nullptr {}\n", dlerror());
    return 1;
  }

  auto create_interface = (CreateInterfaceFn)dlsym(handle, "CreateInterface");
  if (create_interface == nullptr) {
    fmt::print("CreateInterface is nullptr\n");
    return 2;
  }

  int retcode{};
  auto *dll = (IServerGameDLL *)create_interface(INTERFACEVERSION_SERVERGAMEDLL,
                                                 &retcode);
  if (dll == nullptr) {
    fmt::print("dll is nullptr\n");
    return 3;
  }

  for (auto server_class = dll->GetAllServerClasses(); server_class != nullptr;
       server_class = server_class->m_pNext) {
    auto class_name = server_class->GetName();
    auto parsed = parse_tbl(server_class->m_pTable);

    fmt::print("{}:\n", class_name);
    for (auto& prop: parsed) {
      fmt::print("\t{} ({})\n", prop.name, prop_type_to_str(prop.type));
      // fmt::print("\t\toffset: {:08x}\n", prop.offset);
    }
  }

  dlclose(handle);

  return 0;
}
