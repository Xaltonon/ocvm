#include "value.h"
#include "log.h"

#include <lua.hpp>

#include <sstream>
using std::string;
using std::map;
using std::vector;
using std::stringstream;

Value Value::nil; // the nil

Value::Value(const string& v)
{
    _type = "string";
    _string = v;
}

Value::Value()
{
    _type = "nil";
}

Value::Value(void* p)
{
    _type = "userdata";
    _pointer = p;
}

Value::Value(bool b)
{
    _type = "boolean";
    _bool = b;
}

Value::Value(double d)
{
    _type = "number";
    _number = d;
}

Value Value::table()
{
    Value t;
    t._type = "table";
    return t;
}

string Value::toString() const
{
    return _string;
}

bool Value::toBool() const
{
    return _bool;
}

double Value::toNumber() const
{
    return _number;
}

void* Value::toPointer() const
{
    return _pointer;
}

const Value& Value::metatable() const
{
    return _pmetatable ? *_pmetatable : Value::nil;
}

const Value& Value::get(const Value& key) const
{
    if (_table.find(key) == _table.end())
        return Value::nil;
    
    return _table.at(key);
}

Value& Value::get(const Value& key)
{
    if (_table.find(key) == _table.end())
        return Value::nil;
    
    return _table.at(key);
}

void Value::set(const Value& key, const Value& value)
{
    _table[key] = value;
}

vector<ValuePair> Value::pairs() const
{
    vector<ValuePair> vec;
    for (const auto& pair : _table)
    {
        vec.push_back(pair);
    }
    return vec;
}

string Value::type() const
{
    return _type;
}

string Value::serialize() const
{
    if (_type == "string")
    {
        return "\"" + _string + "\"";
    }
    else if (_type == "boolean")
    {
        return _bool ? "true" : "false";
    }
    else if (_type == "number")
    {
        stringstream ss;
        ss << _number;
        return ss.str();
    }
    else if (_type == "nil")
    {
        return "nil";
    }
    else if (_type == "table")
    {
        stringstream ss;
        ss << "{";
        for (const auto& pair : pairs())
        {
            ss << "[";
            ss << pair.first.serialize();
            ss << "] = ";
            ss << pair.second.serialize();
            ss << ",";
        }
        ss << "}";
        return ss.str();
    }

    lout << "failed to serialize Value[" << _type << "]\n";
    return "";
}

bool operator< (const Value& a, const Value& b)
{
    return a.serialize() < b.serialize();
}

Value::operator bool() const
{
    return _type != "nil" && (_type != "boolean" || _bool);
}

ValuePack Value::unpack() const
{
    return ValuePack();
}

void Value::getmetatable(Value& v, lua_State* lua, int index)
{
    if (v.type() == "table" || v.type() == "userdata")
    {
        if (lua_getmetatable(lua, index))
        {
            std::shared_ptr<Value> pmt(new Value);
            *pmt = Value::make(lua, -1);
            if (pmt->type() == "table")
            {
                v._pmetatable = pmt;
            }

            lua_pop(lua, 1);
        }
    }
}

Value Value::make(lua_State* lua, int index)
{
    int top = lua_gettop(lua);
    Value def;
    if (index <= top)
    {
        int type = lua_type(lua, index);
        string name = lua_typename(lua, type);
        def._type = name;
        switch (type)
        {
            case LUA_TSTRING:
                def = Value(lua_tostring(lua, index));
            break;
            case LUA_TBOOLEAN:
                def = Value((bool)lua_toboolean(lua, index));
            break;
            case LUA_TNUMBER:
                def = Value(lua_tonumber(lua, index));
            break;
            case LUA_TNIL:
                def = Value::nil;
            break;
            case LUA_TUSERDATA:
                def = Value(lua_touserdata(lua, index));
            break;
            case LUA_TLIGHTUSERDATA:
                def = Value((void*)lua_topointer(lua, index));
            break;
            case LUA_TTABLE:
                def = Value::table();
                index = index > 0 ? index : (top + index + 1);
                lua_pushnil(lua); // push nil as first key for next()
                while (lua_next(lua, index))
                {
                    // return key, value
                    Value value = Value::make(lua, -1);
                    Value key = Value::make(lua, -2);
                    def.set(key, value);
                    lua_pop(lua, 1); // only pop value, next retakes the key
                }
            break;
        }
        Value::getmetatable(def, lua, index);
    }
    return def;
}
