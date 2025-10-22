#include "PacketSniffer.h"

int main(){
	PacketSniffer sniffer("mon0");
	sniffer.startCapture();
	return 0;
}