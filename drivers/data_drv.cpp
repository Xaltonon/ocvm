#include "drivers/data_drv.h"

using std::unique_ptr;
using std::move;

ECKey::ECKey(ECKeyType keytype, unique_ptr<vector<unsigned char>> key, ECCurve curve)
    : keytype(keytype), key(move(key)), curve(curve)
{
    add("isPublic", &ECKey::isPublic);
    add("serialize", &ECKey::serialize);
}

int ECKey::isPublic(lua_State *lua)
{
    return ValuePack::ret(lua, keytype == ECKeyType::PUBLIC);
}

int ECKey::serialize(lua_State *lua)
{
    return ValuePack::ret(lua, vector<char>(key->begin(), key->end()));
}

