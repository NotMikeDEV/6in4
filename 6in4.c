#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>

#define MAX(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
_a > _b ? _a : _b; })

int main(int argc, char* argv[])
{
	// Command Line arguments.
	if (argc != 4)
	{
		printf("Usage: %s [Local IPv4] [Remote IPv4] [Local IPv6]", argv[0]);
		return -1;
	}
	printf("LocalIPv4: %s\n", argv[1]);
	printf("RemoteIPv4: %s\n", argv[2]);
	printf("LocalIPv6: %s\n", argv[3]);

	// Set up RAW socket. Protocol 41.
	int raw_socket = socket(AF_INET, SOCK_RAW, 41);
	struct sockaddr_in Address;
	Address.sin_family = AF_INET;
	inet_pton(AF_INET, &Address.sin_addr, argv[1]);
	if (bind(raw_socket, (struct sockaddr*)&Address, sizeof(Address)))
	{
		printf("Error binding socket.\n");
		return 0;
	}
	
	// Open Tun/Tap device.
	int tun_device;
	if ((tun_device = open("/dev/net/tun", O_RDWR)) < 0)
	{
		perror("tuntap not found");
		return -1;
	}
	struct ifreq ifr = { 0 };
	ifr.ifr_flags = IFF_TUN; // TUN mode.
	if ((ioctl(tun_device, TUNSETIFF, (void *)&ifr)) < 0)
	{
		close(tun_device);
		perror("unable to init tuntap");
		return -1;
	}
	fcntl(tun_device, F_SETFL, O_NONBLOCK);
	int status;
	
	// Configure IP address and default route.
	if (fork() == 0) execlp("ip", "ip", "link", "set", ifr.ifr_name, "up", NULL); else wait(&status);
	if (fork() == 0) execlp("ip", "ip", "link", "set", ifr.ifr_name, "mtu", "1280", NULL); else wait(&status);
	if (fork() == 0) execlp("ip", "ip", "addr", "add", argv[3], "dev", ifr.ifr_name, NULL); else wait(&status);
	if (fork() == 0) execlp("ip", "ip", "-6", "route", "delete", "default", NULL); else wait(&status);
	if (fork() == 0) execlp("ip", "ip", "-6", "route", "replace", "default", "dev", ifr.ifr_name, "prio", "1", "hoplimit", "64", NULL); else wait(&status);

	unsigned char Buffer[2048];
	int AddressLen;
	while (1)
	{
		// Wait for data
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(raw_socket, &read_fds);
		FD_SET(tun_device, &read_fds);
		int FD_MAX = MAX(tun_device, raw_socket);
		select(FD_MAX + 1, &read_fds, NULL, NULL, NULL);
		// Recv on socket
		if (FD_ISSET(raw_socket, &read_fds))
		{
			memset(&Address, 0, sizeof(Address));
			Address.sin_family = AF_INET;
			int ret = recvfrom(raw_socket, (char*)Buffer, sizeof(Buffer) - 4, 0, (struct sockaddr*)&Address, &AddressLen);
			if (ret > 0)
			{
				// write TUN header over the end of the IPv4 header.
				Buffer[16] = 0;
				Buffer[17] = 0;
				Buffer[18] = 0x86;
				Buffer[19] = 0xdd;
				// send 4 byte TUN header + offset 20 = start of IPv6 header.
				write(tun_device, Buffer + 16, ret, 0);
			}
		}
		// Read on TUN device.
		if (FD_ISSET(tun_device, &read_fds))
		{
			int ret = read(tun_device, Buffer, 2048, 0);
			if (ret > 0)
			{
				memset(&Address, 0, sizeof(Address));
				// Spit it out of our IPv4 socket.
				Address.sin_family = AF_INET;
				inet_pton(AF_INET, argv[2], &Address.sin_addr);
				sendto(raw_socket, Buffer + 4, ret - 4, 0, (struct sockaddr*)&Address, sizeof(Address)); // Offset 4 to skip TUN header.
			}
		}
	}
	return 0;
}
