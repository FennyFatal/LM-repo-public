#include "_kernel.h"
#include "_types.h"
#define SERVER_TCP_PORT (9997)

int sceUserMainThreadPriority = SCE_KERNEL_PRIO_FIFO_DEFAULT;

size_t sceUserMainThreadStackSize = 512 * 1024;
size_t sceLibcHeapSize = 256 * 1024 * 1024;

int main(int argc, const char* const argv[]) {
	int ret;

	printf("Initializing network...\n");
	if (!network_init()) {
		klog("Network initialization failed.\n");
		goto done;
	}

	printf("Starting server...\n");
	if (!server_start(SERVER_TCP_PORT)) {
		klog("Unable to start server.\n");
		goto err_network_fini;
	}

	printf("Waiting for connections...\n");
	if (!server_listen()) {
		klog("Unable to listen for incoming connections.\n");
		goto err_server_stop;
	}

err_server_stop:
	printf("Stopping server...\n");
	server_stop();

err_network_fini:
	printf("Finalizing network...\n");
	network_fini();

err:;

done:
	exit(0);

	return 0;
}
