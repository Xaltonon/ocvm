#include "data.h"

#include "model/log.h"

#include <botan/hash.h>
#include <botan/crc32.h>
#include <botan/base64.h>
#include <botan/compression.h>
#include <botan/secmem.h>
#include <botan/cipher_mode.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/pubkey.h>
#include <botan/ecdsa.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/alg_id.h>
#include <botan/data_src.h>

#include <memory>
#include <variant>

using std::unique_ptr;
using std::make_unique;
using std::holds_alternative;
using std::get;
using namespace Botan;

secure_vector<unsigned char> make_secure(vector<unsigned char> const &v)
{
    return secure_vector<unsigned char>(v.begin(), v.end());
}

Data::Data()
{
    _rng = make_unique<AutoSeeded_RNG>();

    add("crc32", &Data::crc32);
    add("encode64", &Data::encode64);
    add("decode64", &Data::decode64);
    add("md5", &Data::md5);
    add("sha256", &Data::sha256);
    add("deflate", &Data::deflate);
    add("inflate", &Data::inflate);
    add("getLimit", &Data::getLimit);
    add("encrypt", &Data::encrypt);
    add("decrypt", &Data::decrypt);
    add("random", &Data::random);
    add("generateKeyPair", &Data::generateKeyPair);
    add("deserializeKey", &Data::deserializeKey);
    add("ecdsa", &Data::ecdsa);
    add("ecdh", &Data::ecdh);
}

bool Data::onInitialize()
{
    return true;
}

int Data::crc32(lua_State *lua)
{
    vector<unsigned char> input = Value::checkArg<vector<unsigned char>>(lua, 1);

    unique_ptr<HashFunction> hash(HashFunction::create("CRC32"));
    hash->update(input);

    return ValuePack::ret(lua, hash->final_stdvec());
}

int Data::encode64(lua_State *lua)
{
    vector<unsigned char> input = Value::checkArg<vector<unsigned char>>(lua, 1);
    return ValuePack::ret(lua, base64_encode(input));
}

int Data::decode64(lua_State *lua)
{
    string input = Value::checkArg<string>(lua, 1);
    secure_vector<unsigned char> r = base64_decode(input);
    return ValuePack::ret(lua, unlock(r));
}

int Data::md5(lua_State *lua)
{
    vector<unsigned char> input = Value::checkArg<vector<unsigned char>>(lua, 1);

    unique_ptr<HashFunction> hash(HashFunction::create("MD5"));
    hash->update(input);

    return ValuePack::ret(lua, hash->final_stdvec());
}

int Data::sha256(lua_State *lua)
{
    vector<unsigned char> input = Value::checkArg<vector<unsigned char>>(lua, 1);

    unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
    hash->update(input);

    return ValuePack::ret(lua, hash->final_stdvec());
}

int Data::deflate(lua_State *lua)
{
    vector<unsigned char> input = Value::checkArg<vector<unsigned char>>(lua, 1);

    unique_ptr<Compression_Algorithm> comp(make_compressor("deflate"));
    comp->start();
    secure_vector<unsigned char> data = make_secure(input);
    comp->finish(data);

    return ValuePack::ret(lua, unlock(data));
}

int Data::inflate(lua_State *lua)
{
    vector<unsigned char> input = Value::checkArg<vector<unsigned char>>(lua, 1);

    unique_ptr<Decompression_Algorithm> comp(make_decompressor("deflate"));
    comp->start();
    secure_vector<unsigned char> data = make_secure(input);
    comp->finish(data);

    return ValuePack::ret(lua, unlock(data));
}

int Data::getLimit(lua_State *lua)
{
    return ValuePack::ret(lua, 1048576);
}

int Data::encrypt(lua_State *lua)
{
    vector<unsigned char> input = Value::checkArg<vector<unsigned char>>(lua, 1);
    vector<unsigned char> key = Value::checkArg<vector<unsigned char>>(lua, 2);
    vector<unsigned char> iv = Value::checkArg<vector<unsigned char>>(lua, 3);

    secure_vector<unsigned char> data = make_secure(input);

    if (key.size() != 16)
	luaL_error(lua, "expected a 128-bit AES key");
    if (iv.size() != 16)
	luaL_error(lua, "expected a 128-bit AES IV");

    unique_ptr<Cipher_Mode> cipher = Cipher_Mode::create("AES-128/CBC/PKCS7", ENCRYPTION);
    cipher->set_key(key);
    cipher->start(iv);
    cipher->finish(data);

    return ValuePack::ret(lua, unlock(data));
}

int Data::decrypt(lua_State *lua)
{
    vector<unsigned char> input = Value::checkArg<vector<unsigned char>>(lua, 1);
    vector<unsigned char> key = Value::checkArg<vector<unsigned char>>(lua, 2);
    vector<unsigned char> iv = Value::checkArg<vector<unsigned char>>(lua, 3);

    secure_vector<unsigned char> data = make_secure(input);

    if (key.size() != 16)
	luaL_error(lua, "expected a 128-bit AES key");
    if (iv.size() != 16)
	luaL_error(lua, "expected a 128-bit AES IV");

    unique_ptr<Cipher_Mode> cipher = Cipher_Mode::create("AES-128/CBC/PKCS7", DECRYPTION);
    cipher->set_key(key);
    cipher->start(iv);
    cipher->finish(data);

    return ValuePack::ret(lua, unlock(data));
}

int Data::random(lua_State *lua)
{
    unsigned len = Value::checkArg<unsigned>(lua, 1);

    secure_vector<unsigned char> data = _rng->random_vec(len);
    return ValuePack::ret(lua, unlock(data));
}

int Data::generateKeyPair(lua_State *lua)
{
    unsigned defaultlen = 384;
    unsigned keylen = Value::checkArg<unsigned>(lua, 1, &defaultlen);

    ECCurve curve = ECCurve::SECP256R1;

    if (keylen == 256)
	curve = ECCurve::SECP256R1;
    else if (keylen == 384)
	curve = ECCurve::SECP384R1;
    else
	luaL_error(lua, "invalid key length, must be 256 or 384");

    return ECKey::generateKeyPair(lua, curve, *_rng);
}

ECKey::ECKey(ECKeyType keytype, ECCurve curve, PrivPubKey key)
    : _keytype(keytype), _curve(curve), _key(key)
{
    add("isPublic", &ECKey::isPublic);
    add("keyType", &ECKey::keyType);
    add("serialize", &ECKey::serialize);
}

int ECKey::isPublic(lua_State *lua)
{
    return ValuePack::ret(lua, _keytype == ECKeyType::PUBLIC);
}

int ECKey::keyType(lua_State *lua)
{
    if (_keytype == ECKeyType::PUBLIC)
    {
	return ValuePack::ret(lua, "ec-public");
    }
    else
    {
	return ValuePack::ret(lua, "ec-private");	
    }
}

int ECKey::serialize(lua_State *lua)
{
    if (holds_alternative<ECDSA_PrivateKey>(_key))
    {
	return ValuePack::ret(lua, unlock(PKCS8::BER_encode(get<ECDSA_PrivateKey>(_key))));
    }
    else
    {
	return ValuePack::ret(lua, X509::BER_encode(get<ECDSA_PublicKey>(_key)));
    }
}

int Data::deserializeKey(lua_State *lua)
{
    vector<unsigned char> data = Value::checkArg<vector<unsigned char>>(lua, 1);
    std::string keytype = Value::checkArg<std::string>(lua, 2);

    ECCurve curve;
    if (data.size() == 120 || data.size() == 80)
	curve = ECCurve::SECP384R1;
    else if (data.size() == 80 || data.size() == 67)
	curve = ECCurve::SECP256R1;
    else {
	luaL_error(lua, "invalid key size");
	return 0;
    }

    if (keytype == "ec-public")
    {
	unique_ptr<ECDSA_PublicKey> pub(dynamic_cast<ECDSA_PublicKey*>(X509::load_key(data)));

	ECKey *pubkey = static_cast<ECKey*>(lua_newuserdata(lua, sizeof(ECKey)));
	new (pubkey) ECKey(ECKeyType::PUBLIC, curve, *pub);

	return 1;
    }
    else if (keytype == "ec-private")
    {
	DataSource_Memory mem(data);
	ECDSA_PrivateKey priv = dynamic_cast<ECDSA_PrivateKey&>(*PKCS8::load_key(mem));

	ECKey *privkey = static_cast<ECKey*>(lua_newuserdata(lua, sizeof(ECKey)));
	new (privkey) ECKey(ECKeyType::PRIVATE, curve, priv);

	return 1;
    }
    else
	luaL_error(lua, "invalid key type, must be ec-public or ec-private");

    return 0;
}

int ECKey::generateKeyPair(lua_State *lua,
			   ECCurve curve,
			   RandomNumberGenerator &rng)
{
    EC_Group group;
    if (curve == ECCurve::SECP256R1)
	group = EC_Group("secp256r1");
    else if (curve == ECCurve::SECP384R1)
	group = EC_Group("secp384r1");
    
    ECDSA_PrivateKey priv = ECDSA_PrivateKey(rng, group);
    ECDSA_PublicKey pub = ECDSA_PublicKey(priv);

    ECKey *privkey, *pubkey;
    pubkey = static_cast<ECKey*>(lua_newuserdata(lua, sizeof(ECKey)));
    privkey = static_cast<ECKey*>(lua_newuserdata(lua, sizeof(ECKey)));

    new (pubkey) ECKey(ECKeyType::PUBLIC, curve, pub);
    new (privkey) ECKey(ECKeyType::PRIVATE, curve, priv);

    return 2;
}

int Data::ecdsa(lua_State *lua)
{
    vector<unsigned char> data = Value::checkArg<vector<unsigned char>>(lua, 1);
    ECKey *key = static_cast<ECKey*>(Value::checkArg<void*>(lua, 2));
    if (key->_keytype == ECKeyType::PUBLIC) {
	vector<unsigned char> sig = Value::checkArg<vector<unsigned char>>(lua, 3);
	PK_Verifier verifier(get<ECDSA_PublicKey>(key->_key), "EMSA1(SHA-256)");
	verifier.update(data);
	return ValuePack::ret(lua, verifier.check_signature(sig));
    }
    else
    {
	PK_Signer signer(get<ECDSA_PrivateKey>(key->_key), *_rng, "EMSA1(SHA-256)");
	signer.update(data);
	return ValuePack::ret(lua, signer.signature(*_rng));
    }
}

int Data::ecdh(lua_State *lua)
{
    ECKey *priv = static_cast<ECKey*>(Value::checkArg<void*>(lua, 1));
    ECKey *pub = static_cast<ECKey*>(Value::checkArg<void*>(lua, 2));

    ECDH_PrivateKey privkey = reinterpret_cast<ECDH_PrivateKey&>(get<ECDSA_PrivateKey>(priv->_key));
    ECDH_PublicKey pubkey = reinterpret_cast<ECDH_PublicKey&>(get<ECDSA_PublicKey>(pub->_key));

    PK_Key_Agreement ecdh(privkey, *_rng, "Raw");
    SymmetricKey key = ecdh.derive_key(32, pubkey.public_key_bits());
    return ValuePack::ret(lua, unlock(key.bits_of()));
}
