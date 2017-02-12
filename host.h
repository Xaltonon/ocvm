#pragma once
#include <string>
#include "config.h"

class Component;
class Framer;

class Host
{
public:
    Host(Framer* framer);
    ~Host();

    string machinePath() const;
    Framer* getFramer() const;
    Component* create(const string& type);
    void close();
private:
    Framer* _framer;
};
