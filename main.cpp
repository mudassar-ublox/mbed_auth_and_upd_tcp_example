
#include "mbed.h"
#include "CellularContext.h"
#include "mbed-trace/mbed_trace.h"

#define UDP_SERVER "2.pool.ntp.org"
#define TCP_SERVER "52.215.34.155"
#define UDP_PORT 123

static	CellularContext *ctx;

static void printNtpTime(char * buf, int len)
{
    time_t timestamp = 0;
    struct tm *localTime;
    char timeString[25];
    time_t TIME1970 = 2208988800U;

    if (len >= 43) {
        timestamp |= ((int) *(buf + 40)) << 24;
        timestamp |= ((int) *(buf + 41)) << 16;
        timestamp |= ((int) *(buf + 42)) << 8;
        timestamp |= ((int) *(buf + 43));
        timestamp -= TIME1970;
        localTime = localtime(&timestamp);
        if (localTime) {
            if (strftime(timeString, sizeof(timeString), "%a %b %d %H:%M:%S %Y", localTime) > 0) {
                printf("NTP timestamp is %s.\n", timeString);
            }
        }
    }
}

/**
 * Opens a UDP or a TCP socket with the given echo server and performs an echo
 * transaction retrieving current.
 */
nsapi_error_t udp_tcp_echo()
{
    nsapi_size_or_error_t retcode;
    const char *host_name = MBED_CONF_APP_ECHO_SERVER_HOSTNAME;
    const int port = MBED_CONF_APP_ECHO_SERVER_PORT;

#if MBED_CONF_APP_SOCK_TYPE == TCP
    TCPSocket sock;
#else
    UDPSocket sock;
#endif

    retcode = sock.open(ctx);
    if (retcode != NSAPI_ERROR_OK) {
#if MBED_CONF_APP_SOCK_TYPE == TCP
        printf("TCPSocket.open() fails, code: %d\n", retcode);
#else
        printf("UDPSocket.open() fails, code: %d\n", retcode);
#endif
        return -1;
    }

    SocketAddress sock_addr;
    retcode = ctx->gethostbyname("52.215.34.155", &sock_addr);
    if (retcode != NSAPI_ERROR_OK) {
        printf("Couldn't resolve remote host: %s, code: %d\n", host_name, retcode);
        return -1;
    }

    sock_addr.set_port(port);
    sock.set_timeout(15000);
    int n = 0;
    const char *echo_string = "TEST";
    char recv_buf[4];
#if MBED_CONF_APP_SOCK_TYPE == TCP
    retcode = sock.connect(sock_addr);
    if (retcode < 0) {
        printf("TCPSocket.connect() fails, code: %d\n", retcode);
        return -1;
    } else {
        printf("TCP: connected with %s server\n", host_name);
    }
    retcode = sock.send((void*) echo_string, sizeof(echo_string));
    if (retcode < 0) {
        printf("TCPSocket.send() fails, code: %d\n", retcode);
        return -1;
    } else {
        printf("TCP: Sent %d Bytes to %s\n", retcode, host_name);
    }

    n = sock.recv((void*) recv_buf, sizeof(recv_buf));
#else

    retcode = sock.sendto(sock_addr, (void*) echo_string, sizeof(echo_string));
    if (retcode < 0) {
        printf("UDPSocket.sendto() fails, code: %d\n", retcode);
        return -1;
    } else {
        printf("UDP: Sent %d Bytes to %s\n", retcode, host_name);
    }

    n = sock.recvfrom(&sock_addr, (void*) recv_buf, sizeof(recv_buf));
#endif

    sock.close();

    if (n > 0) {
        printf("Received from echo server %d Bytes\n", n);
        return 0;
    }

    return -1;
}

int get_ntp_time()
{
    int x;
    char buf[1024];
    UDPSocket sockUdp;
    SocketAddress udpServer;
    SocketAddress udpSenderAddress;
    nsapi_size_or_error_t retcode;

    retcode = ctx->gethostbyname(UDP_SERVER, &udpServer);
    if (retcode != NSAPI_ERROR_OK) {
        printf("Couldn't resolve remote host: %s, code: %d\n", UDP_SERVER, retcode);
        return -1;
    }

    udpServer.set_port(UDP_PORT);
	printf("Opening a UDP socket...\n");
	if (sockUdp.open(ctx) == 0) {
		printf("UDP socket open.\n");
		sockUdp.set_timeout(10000);
		printf("Sending time request to \"2.pool.ntp.org\" over UDP socket...\n");
		memset (buf, 0, sizeof(buf));
		*buf = '\x1b';
		if (sockUdp.sendto(udpServer, (void *) buf, 48) == 48) {
			printf("Socket send completed, waiting for UDP response...\n");
			x = sockUdp.recvfrom(&udpSenderAddress, buf, sizeof (buf));
			if (x > 0) {
				printf("Received %d byte response from server %s on UDP socket:\n"
					   "-------------------------------------------------------\n",
					   x, udpSenderAddress.get_ip_address());
				printNtpTime(buf, x);
				printf("-------------------------------------------------------\n");
			}
		}

		printf("Closing socket...\n");
		sockUdp.close();
		printf("Socket closed.\n");
	}
}


int main()
{
#if MBED_CONF_MBED_TRACE_ENABLE
     mbed_trace_init();
#endif

    ctx = CellularContext::get_default_instance();

    ctx->set_sim_pin(MBED_CONF_APP_CELLULAR_SIM_PIN);
#ifdef MBED_CONF_APP_APN
    ctx->set_credentials(MBED_CONF_APP_APN);
#endif

    // Set Auth type
    ctx->set_authentication_type(CellularContext::NOAUTH);

    if (ctx->connect() != NSAPI_ERROR_OK) {
        printf("Connection failed\n");
    	return -1;
    }

    printf("Connection established\n");
    while (1) {
    	get_ntp_time();

		//udp_tcp_echo();

        wait_ms(1000);
    }
}