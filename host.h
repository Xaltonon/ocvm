#pragma once
#include <string>
#include "config.h"

class Component;
class Framer;

class Host
{
public:
    Host(const std::string& env_path);
    ~Host();

    std::string machinePath() const;
    std::string envPath() const;
    Framer* getFramer() const;
    Component* create(const std::string& type, const Value& init);
    void close();
private:
    std::string _env_path;
    Framer* _framer;
};
