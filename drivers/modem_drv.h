#pragma once

#include <string>
#include <vector>
#include <memory>
using std::string;
using std::vector;
using std::unique_ptr;

#include "io/event.h"
#include "worker.h"

#include "connection.h"

class FileLock
{
public:
    static unique_ptr<FileLock> create(const string& path);
    ~FileLock();
private:
    FileLock(const string& path, int fd);
    string _path;
    int _fd;
};

class ServerPool : public Worker
{
public:
    static unique_ptr<ServerPool> create(int system_port);
    virtual ~ServerPool();

protected:
    ServerPool(int id, unique_ptr<FileLock> lock);
    bool onStart() override;
    bool runOnce() override;
    void onStop() override;
    bool remove(int id);
private:
    map<int, Connection*> _connections;
    int _id;
    unique_ptr<FileLock> _lock;
};

class ModemDriver : public Worker
{
public:
    ModemDriver(EventSource<ModemEvent>* source, int system_port, const std::string& system_address);
    bool send(const vector<char>& payload);
protected:
    bool onStart() override;
    bool runOnce() override;
    void onStop() override;
    bool readNextModemMessage(ModemEvent& mev);

private:
    // ctor assigned
    EventSource<ModemEvent>* _source;
    int _system_port;
    std::string _system_address;

    // default values
    unique_ptr<ServerPool> _local_server;
    unique_ptr<Connection> _connection;
};
