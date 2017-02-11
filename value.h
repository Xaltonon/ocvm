#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>

using std::string;
using std::vector;
using std::map;
using std::shared_ptr;
using std::ostream;

class lua_State;
class Value;
struct ValuePack : public vector<Value>
{
    lua_State* state;
    ValuePack(std::initializer_list<Value>);
    ValuePack(lua_State* state);
    ValuePack() = default;
};
ostream& operator << (ostream& os, const ValuePack& pack);

class Value
{
public:
    Value(const string& v);
    Value(bool b);
    Value(double d);
    Value(const void* p, bool bLight);
    Value(int n) : Value(double(n)) {}
    Value(const char* cstr) : Value(string(cstr)) {}
    Value(int64_t n) : Value(double(n)) {}
    Value(size_t n) : Value(double(n)) {}
    Value(lua_State*);
    Value(lua_State*, int);
    Value();

    static Value table();
    static const Value nil;

    static ValuePack pack()
    {
        return ValuePack();
    }

    const Value& Or(const Value& def) const;

    template<typename T, typename... Ts>
    static ValuePack pack(T arg, Ts... args)
    {
        ValuePack vec = pack(args...);
        vec.insert(vec.begin(), Value(arg));
        return vec;
    }

    void push(lua_State* lua) const;

    void insert(const Value& value);
    int len() const;
    string type() const;
    int type_id() const;
    string toString() const;
    double toNumber() const;
    bool toBool() const;
    void* toPointer() const;
    lua_State* toThread() const;
    int status() const;
    const Value& metatable() const;

    static const Value& select(const ValuePack& pack, size_t index);
    static const Value& check(const ValuePack& pack, size_t index, const string& required, const string& optional = "");

    // table functions
    void set(const Value& key, const Value& value);
    const Value& get(const Value& key) const;
    Value& get(const Value& key);
    const map<Value, Value>& pairs() const;
    map<Value, Value>& pairs();

    string serialize(bool bSpacey = false) const;
    operator bool() const;
protected:
    void getmetatable(lua_State* lua, int index);
private:
    string _type;
    int _id;
    string _string;
    bool _bool = false;
    double _number = 0;
    void* _pointer = nullptr;
    lua_State* _thread = nullptr;
    int _thread_status = 0;
    shared_ptr<Value> _pmetatable;
    map<Value, Value> _table;
};

bool operator< (const Value& a, const Value& b);
