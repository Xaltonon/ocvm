#pragma once
#include "component.h"
#include "value.h"
#include <tuple>
using std::tuple;

class Screen;

class Gpu : public Component
{
public:
    Gpu();

    bool set(int x, int y, const string& text);

    int setResolution(lua_State* lua);
    int bind(lua_State* lua);
    int set(lua_State* lua);
    int maxResolution(lua_State* lua);
    int setBackground(lua_State* lua);
    int getBackground(lua_State* lua);
    int setForeground(lua_State* lua);
    int getForeground(lua_State* lua);
    int fill(lua_State* lua);
    int copy(lua_State* lua);
protected:
    bool onInitialize(Value& config) override;
    bool truncateWH(int x, int y, int* pWidth, int* pHeight) const;
private:
    Screen* _screen;
};
