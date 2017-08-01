package = "azure-b2c-auth"
version = "1.1-5"
source = {
  url = "git://github.com/thereapman/kong-external-oauth"
}
description = {
  summary = "A Kong plugin, that let you use Azure AD B2C to protect your API",
  license = "Apache 2.0"
}
dependencies = {
  "lua >= 5.1"
  -- If you depend on other rocks, add them here
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.azure-b2c-auth.access"] = "src/access.lua",
    ["kong.plugins.azure-b2c-auth.handler"] = "src/handler.lua",
    ["kong.plugins.azure-b2c-auth.schema"] = "src/schema.lua"
  }
}
