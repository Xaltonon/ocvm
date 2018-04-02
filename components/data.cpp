#include "data.h"

#include <memory>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/md5.h>
#include <cryptopp/crc.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/zdeflate.h>
#include <cryptopp/zinflate.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/eccrypto.h>

#include "drivers/data_drv.h"

using std::unique_ptr;
using std::make_unique;
using namespace CryptoPP;

Data::Data()
{
    add("crc32", &Data::crc32);
    add("encode64", &Data::encode64);
    add("decode64", &Data::decode64);
    add("md5", &Data::md5);
    add("deflate", &Data::deflate);
    add("inflate", &Data::inflate);
    add("getLimit", &Data::getLimit);
    add("encrypt", &Data::encrypt);
    add("decrypt", &Data::decrypt);
    add("random", &Data::random);
    add("generateKeyPair", &Data::generateKeyPair);
    add("ecdh", &Data::ecdh);
    add("ecdsa", &Data::ecdsa);
}

bool Data::onInitialize()
{
    return true;
}

int Data::crc32(lua_State* lua)
{
    string input = Value::checkArg<string>(lua, 1);
    string result;

    CRC32 hash;
    StringSource(input, true,
                 new HashFilter(hash,
                                new StringSink(result)));

    return ValuePack::ret(lua, result);
}

int Data::encode64(lua_State* lua)
{
    string input = Value::checkArg<string>(lua, 1);
    string result;

    StringSource(input, true,
                 new Base64Encoder(
                     new StringSink(result), false));

    return ValuePack::ret(lua, result);
}

int Data::decode64(lua_State* lua)
{
    string input = Value::checkArg<string>(lua, 1);
    string result;

    StringSource(input, true,
                 new Base64Decoder(
                     new StringSink(result)));

    return ValuePack::ret(lua, result);
}

int Data::md5(lua_State* lua)
{
    string input = Value::checkArg<string>(lua, 1);
    string result;

    Weak::MD5 hash;
    StringSource(input, true,
                 new HashFilter(hash,
                                new StringSink(result)));

    return ValuePack::ret(lua, result);
}

int Data::deflate(lua_State* lua)
{
    string input = Value::checkArg<string>(lua, 1);
    string result;

    StringSource(input, true,
		 new Deflator(
		     new StringSink(result)));

    return ValuePack::ret(lua, result);
}

int Data::inflate(lua_State* lua)
{
    string input = Value::checkArg<string>(lua, 1);
    string result;

    StringSource(input, true,
		 new Inflator(
		     new StringSink(result)));

    return ValuePack::ret(lua, result);
}

int Data::getLimit(lua_State* lua)
{
    /* set to the default hardlimit, no config option yet */
    return ValuePack::ret(lua, 1048576);
}

int Data::encrypt(lua_State* lua)
{
    string input = Value::checkArg<string>(lua, 1);
    string key = Value::checkArg<string>(lua, 2);
    string iv = Value::checkArg<string>(lua, 3);
    string result;

    if (key.length() != 16)
	luaL_error(lua, "expected a 128-bit AES key");
    if (iv.length() != 16)
	luaL_error(lua, "expected a 128-bit AES IV");

    CBC_Mode<AES>::Encryption cipher((const byte *) key.c_str(),
				     key.length(),
				     (const byte *) iv.c_str());

    StringSource(input, true,
		 new StreamTransformationFilter(cipher,
						new StringSink(result),
						StreamTransformationFilter::PKCS_PADDING));

    return ValuePack::ret(lua, result);
}

int Data::decrypt(lua_State *lua)
{
    string input = Value::checkArg<string>(lua, 1);
    string key = Value::checkArg<string>(lua, 2);
    string iv = Value::checkArg<string>(lua, 3);
    string result;

    if (key.length() != 16)
	luaL_error(lua, "expected a 128-bit AES key");
    if (iv.length() != 16)
	luaL_error(lua, "expected a 128-bit AES IV");

    CBC_Mode<AES>::Decryption cipher((const byte *) key.c_str(),
				     key.length(),
				     (const byte *) iv.c_str());

    StringSource(input, true,
		 new StreamTransformationFilter(cipher,
						new StringSink(result),
						StreamTransformationFilter::PKCS_PADDING));

    return ValuePack::ret(lua, result);

}

int Data::random(lua_State *lua)
{
    unsigned len = Value::checkArg<unsigned>(lua, 1);

    vector<unsigned char> buf(len);
    _rng.GenerateBlock(buf.data(), len);

    return ValuePack::ret(lua, vector<char>(buf.begin(), buf.end()));
}

int Data::generateKeyPair(lua_State* lua)
{
    /* todo: verify elliptic curve used in oc */
    unsigned defaultlen = 384;
    unsigned keylen = Value::checkArg<unsigned>(lua, 1, &defaultlen);

    OID curve;
    ECCurve curvetype;
    if (keylen == 256)
    {
	curve = ASN1::secp256r1();
	curvetype = ECCurve::SECP256R1;
    }
    else if (keylen == 384)
    {
	curve = ASN1::secp384r1();
	curvetype = ECCurve::SECP384R1;
    }
    else
	luaL_error(lua, "invalid key length, must be 256 or 384");

    ECDH<ECP>::Domain dh(curve);

    unique_ptr<vector<unsigned char>> privk, pubk;

    privk = make_unique<vector<unsigned char>>(dh.PrivateKeyLength());
    pubk = make_unique<vector<unsigned char>>(dh.PublicKeyLength());
    
    dh.GenerateKeyPair(_rng, privk->data(), pubk->data());

    ECKey *pub, *priv;
    pub = static_cast<ECKey*>(lua_newuserdata(lua, sizeof(ECKey)));
    priv = static_cast<ECKey*>(lua_newuserdata(lua, sizeof(ECKey)));
    new (pub) ECKey(ECKeyType::PUBLIC, move(pubk), curvetype);
    new (priv) ECKey(ECKeyType::PRIVATE, move(privk), curvetype);

    return 2;
}

int Data::ecdh(lua_State* lua)
{
    ECKey *priv = static_cast<ECKey*>(Value::checkArg<void*>(lua, 1));
    ECKey *pub = static_cast<ECKey*>(Value::checkArg<void*>(lua, 2));

    if (priv->keytype != ECKeyType::PRIVATE || pub->keytype != ECKeyType::PUBLIC)
	luaL_error(lua, "key type mismatch");
    if (priv->curve != pub->curve)
	luaL_error(lua, "curve mismatch");

    OID curve;
    if (priv->curve == ECCurve::SECP256R1)
	curve = ASN1::secp256r1();
    else if (priv->curve == ECCurve::SECP384R1)
	curve = ASN1::secp384r1();

    ECDH<ECP>::Domain dh(curve);
    vector<unsigned char> result(dh.AgreedValueLength());

    if (!dh.Agree(result.data(), priv->key->data(), pub->key->data()))
	luaL_error(lua, "agreement failed");

    return ValuePack::ret(lua, vector<char>(result.begin(), result.end()));
}

int Data::ecdsa(lua_State* lua)
{
    /* okay this is kinda digusting */
    string data = Value::checkArg<string>(lua, 1);
    ECKey *key = static_cast<ECKey*>(Value::checkArg<void*>(lua, 2));
    string defsig;
    string sig = Value::checkArg<string>(lua, 3, &defsig);

    bool signing = sig == defsig;

    if (signing)
    {
	ECDSA<ECP, SHA256>::PrivateKey priv;
	Integer x(key->key->data(), key->key->size());
	

	ECDSA<ECP, SHA256>::Signer signer();
    }
    else
    {
	
    }
}
