#include "PacketQueue.h"

void PacketQueue::push(const Packet& p) {
	{
		std::lock_guard<std::mutex> lk(mtx_);
		q_.push(p);

	}
	cv_.notify_one();
}

bool PacketQueue::pop(Packet& out) {
	std::unique_lock<std::mutex> lk(mtx_);
	cv_.wait(lk, [&] {return !q_.empty(); });
	out = q_.front();
	q_.pop();
	return true;

}