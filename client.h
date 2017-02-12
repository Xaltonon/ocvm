#pragma once
#include "value.h"
#include "luaproxy.h"

#include <string>
#include <vector>

class Host;
class LuaEnv;
class Component;
class Config;

class Client : public LuaProxy
{
public:
    Client(Host*, const string& env_path);
    ~Client();
    bool load(LuaEnv*);
    void close();
    vector<Component*> components(string filter = "", bool exact = false) const;
    Component* component(const string& address) const;
    const string& envPath() const;

    // global api that is actually computer specific
    // invoke by address
    ValuePack component_invoke(const ValuePack& args);
    ValuePack component_list(const ValuePack& args);
    ValuePack component_methods(const ValuePack& args);
    ValuePack component_type(const ValuePack& args);
    ValuePack component_slot(const ValuePack& args);
protected:
    bool createComponents();
    bool postInit();
    bool loadLuaComponentApi(LuaEnv*);
private:
    vector<Component*> _components;
    Config* _config;
    string _env_path;
    Host* _host;
};
