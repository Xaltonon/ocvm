#pragma once
#include "component.h"
#include "value.h"

#include <set>
#include <fstream>
using std::set;
using std::fstream;

class FileHandle;

class Filesystem : public Component
{
public:
    Filesystem();

    enum ConfigIndex
    {
        SourceUri = Component::ConfigIndex::Next,
        Label
    };

    string path() const;
    string src() const;
    bool isReadOnly() const;
    bool isTmpfs() const;

    void close(FileHandle*);

    int open(lua_State* lua);
    int read(lua_State* lua);
    int write(lua_State* lua);
    int close(lua_State* lua);
    int getLabel(lua_State* lua);
    int setLabel(lua_State* lua);
    int list(lua_State* lua);
    int isDirectory(lua_State* lua);
    int exists(lua_State* lua);
    int isReadOnly(lua_State* lua);
    int seek(lua_State* lua);
    int size(lua_State* lua);
    int lastModified(lua_State* lua);
    int spaceUsed(lua_State* lua);
    int spaceTotal(lua_State* lua);
    int remove(lua_State* lua);
    int makeDirectory(lua_State* lua);
    int rename(lua_State* lua);
protected:
    bool onInitialize() override;
    static string clean(string arg, bool bAbs, bool removeEnd);
    static string relative(const string& requested, const string& full);

    void* create(lua_State* lua, fstream* pstream);
    fstream* get_stream(lua_State* lua, FileHandle** ppfh = nullptr) const;
private:
    bool _isReadOnly;
    set<FileHandle*> _handles;
    string _src;
    bool _tmpfs;
};
