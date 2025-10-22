#pragma once
#include "Packet.h"
#include <queue>
#include <mutex>
#include <condition_variable>

class PacketQueue {

private:
	std::queue<Packet> q_;
	std::mutex mtx_;
	std::condition_variable cv_;

public:
	void push(const Packet& p);
	bool pop(Packet& out);

};