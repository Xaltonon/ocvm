#pragma once

#include <variant>

#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/rng.h>

#include "component.h"
#include "model/value.h"
#include "apis/userdata.h"

class Data : public Component
{
public:
    /* tier 1 */
    int crc32(lua_State*);
    int encode64(lua_State*);
    int decode64(lua_State*);
    int md5(lua_State*);
    int sha256(lua_State*);
    int deflate(lua_State*);
    int inflate(lua_State*);
    int getLimit(lua_State*);

    /* tier 2 */
    int encrypt(lua_State*);
    int decrypt(lua_State*);
    int random(lua_State*);

    /* tier 3 */
    int generateKeyPair(lua_State*);
    int ecdsa(lua_State*);
    int ecdh(lua_State*);
    int deserializeKey(lua_State*);
    
    Data();

protected:
    bool onInitialize() override;

private:
    std::unique_ptr<Botan::AutoSeeded_RNG> _rng;
};

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

typedef std::variant<Botan::ECDSA_PrivateKey, Botan::ECDSA_PublicKey> PrivPubKey;

class ECKey : public UserData
{
public:
    friend class Data;

    ECKey(ECKeyType, ECCurve, PrivPubKey);
    
    int isPublic(lua_State*);
    int keyType(lua_State*);
    int serialize(lua_State*);

    static int generateKeyPair(lua_State*,
			       ECCurve,
			       Botan::RandomNumberGenerator&);
protected:
    ECKeyType _keytype;
    ECCurve _curve;
    PrivPubKey _key;
};
