#pragma once

#include "apis/userdata.h"

#include <memory>

enum class ECKeyType
{
    PUBLIC,
    PRIVATE,
};

enum class ECCurve
{
    SECP256R1,
    SECP384R1,
};

class Data;
class ECKey : public UserData
{
public:
    ECKey(ECKeyType, std::unique_ptr<vector<unsigned char>>, ECCurve);

    int isPublic(lua_State *lua);
    int serialize(lua_State *lua);

    /* I really need to refactor this */
    ECKeyType keytype;
    std::unique_ptr<vector<unsigned char>> key;
    ECCurve curve;
};
