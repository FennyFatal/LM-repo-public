/*
* Copyright (c) 2016 - TheoryWrong
*/

#include "webvita.h"
#include <net.h>
#include <stdlib.h>
#include <stdio.h>
#include <libsysmodule.h>
#include <string.h>
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\_pthread.h"



#define O_RDONLY         00

// Initialize NET Library
void init_net() {
	int ret = 0;
    //sceSysmoduleLoadModule(SCE_SYSMODULE_NET);

    sceNetShowNetstat();

    sceNetCtlInit();
}

// Close NET Library
void close_net() {
    if (net_memory)
        free(net_memory);

    sceNetCtlTerm();
    sceNetTerm();
}

// Create server
int create_server() {
    SceNetSockaddrIn serverAddress;
	klog("ssss\n");
    char server_name[32];
    snprintf(server_name, 32, "WEBSERVER");
    int sock = sceNetSocket(server_name, SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
	klog("ssss\n");
    serverAddress.sin_family = SCE_NET_AF_INET;
    serverAddress.sin_port = sceNetHtons(port);
    serverAddress.sin_addr.s_addr = sceNetHtonl(SCE_NET_INADDR_ANY);
	klog("ssss\n");
    if (sceNetBind(sock, (SceNetSockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        return -1;
    }
	klog("ssss\n");
    sceNetListen(sock, 128);
	klog("ssss\n");
    return sock;
}

// Accept client
int accept_client(int server_sock) {
    SceNetSockaddrIn clientAddress;
	klog("22222\n");
    unsigned int c = sizeof(clientAddress);
	klog("22222\n");
    return sceNetAccept(server_sock, (SceNetSockaddr *) &clientAddress, &c);
	klog("2222\n");
}

// Read client data
int read_client(int client_sock, void* buffer) {
	klog("sasss\n");
    memset(buffer, 0, max_size);
	klog("sasss\n");
    int read_size = sceNetRecv(client_sock, buffer, max_size, 0);
	klog("sasss\n");
    if (read_size <= 0) {
        return -1;
    }
	klog("sasss\n");
    return read_size;
}

// Split char* into an array of char (splitted by character)
char** split_strings(char* str, char* character, int* count) {
    char** strings;
	klog("111sasss\n");
    strings = malloc(1 * sizeof(char*));
	klog("111sasss\n");
    int n = 0;
	klog("111sasss\n");
    char *split = strtok(str, character);
	klog("111sasss\n");
    while(split != NULL)
    {
        strings = realloc(strings, sizeof(char*) * (n+1));
        strings[n] = strdup(split);
        split = strtok(NULL, character);
        n++;
    }
	klog("111sasss\n");
    *count = n;

    return strings;
}

// Free memory of array of char
void free_strings(char** str, int count) {
	klog("1aaaasasss\n");
    for (int i = 0; i < count; ++i)
    {
        free(str[i]);
    }
	klog("1aaaasasss\n");
}

// Free memory of request
void free_request(Request* req) {
	klog("333333333sasss\n");
    free(req->path);
    free(req->absolute_path);
	klog("333333333sasss\n");
    free(req);
}

// Free memory of response
void free_response(Response* res) {
    free(res->data);
}

// Get request parse the buffer into Request struct
Request* get_request(void* buffer, int len) {
    int headers_count;
	klog("zzzzzzzzzzzzzs\n");
    char** headers = split_strings((char*)buffer, "\r\n", &headers_count);
	klog("zzzzzzzzzzzzzs\n");
    int infos_count;
    char** infos = split_strings(headers[0], " ", &infos_count);
	klog("zzzzzzzzzzzzzs\n");
    if (infos_count < 3) {
        return NULL;
    }
	klog("zzzzzzzzzzzzzs\n");
    Request* req = malloc(sizeof(Request));
	klog("zzzzzzzzzzzzzs\n");
    if (!strcmp(infos[0], "GET")) {
        req->type = HTTP_GET;
    } else if (!strcmp(infos[0], "POST")) {
        req->type = HTTP_POST;
    }
	klog("zzzzzzzzzzzzzs\n");
    req->path = malloc(strlen(infos[1]) + 1);
    strcpy(req->path, infos[1]);
	klog("zzzzzzzzzzzzzs\n");
    req->absolute_path  = malloc(strlen(default_path) + strlen(req->path) + 1);
    sprintf(req->absolute_path, "%s%s", default_path, req->path);
	klog("zzzzzzzzzzzzzs\n");
    free_strings(headers, headers_count);
	klog("zzzzzzzzzzzzzs\n");
    return req;
}

// Build response transform a Response struct to a buffer
char* build_response(Response res, int* res_size) {
	klog("qqqqqqqqqqqs\n");
    char* header = "HTTP/1.1 %d OK\r\nServer: VitaWeb\r\nConnection: close\r\nContent-Type: %s\r\n\r\n";
    int data_len = strlen(header) - 4 + 3 + strlen(mime_types[res.mime].mime) + res.data_size;
	klog("qqqqqqqqqqqs\n"); 
    char *data = malloc(data_len);
	klog("qqqqqqqqqqqs\n"); 
    memset (data,'\0',data_len);
    sprintf(data, header, res.statut_code, mime_types[res.mime].mime);
    memcpy(data+strlen(data), res.data, res.data_size);
	klog("qqqqqqqqqqqs\n");
    *res_size = data_len;
	klog("qqqqqqqqqqqs\n");
    return data;
}

// Get mime type from extention
int getMime(char* ext) {
	klog("qqqqqqqqqqqs\n");
    for (int i = 0; i < N_MIME_TYPE; ++i)
    {
        if (!strcmp(ext, mime_types[i].ext)) {
            return i;
        }
    }
	klog("qqqqqqqqqqqs\n");

    return 0;
}

// Read file check if the file exist and read this
void* readFile(char* path, int* sz, int* mime) {
    char* buffer;
    SceUID fd;
	klog("qqqqqqqqqqqs\n");
    if ((fd = sceKernelOpen(path, O_RDONLY, 0777)) >= 0) {
        int size = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
    
        buffer = malloc(size);
        if (buffer == NULL) {
            return NULL;
        }
		klog("qqqqqqqqqqqs\n");
		sceKernelOpen(fd, buffer, size);
		sceKernelClose(fd);
        *sz = size;
		klog("qqqqqqqqqqqs\n");
        int n = 0;
        char** path_cut = split_strings(path, ".", &n);
        *mime = getMime(path_cut[n-1]);
		klog("qqqqqqqqqqqs\n");
        return (void*)buffer;
    } else {
        return NULL;
    }
}

// Add new custom response
void addCall(char* path_call, void* call_func) {
    calls = realloc(calls, sizeof(call) * (N_call+1));
    calls[N_call].path_call = path_call;
    calls[N_call].call_func = call_func;
    calls_nbr++;
}

// (Thread) Execute this went client was connected
int execute_client(SceSize args, void *argp) {
    int client_sock = *((int *) argp);
	klog("Malloc try");
    char *buffer = malloc(max_size);

    int request_size = read_client(client_sock, (void*)buffer);
	klog("[Web Client], Read_client passed\n");

    if (request_size > 0) {
        Request* req = get_request((void*)buffer, request_size);
		klog("[Web Client], get_request passed\n");
        free(buffer);

        if (req != NULL) {            
            int find_call = 0;
            int cb;

            for (cb = 0; cb < calls_nbr; ++cb)
            {
                if (!strcmp(calls[cb].path_call, req->path)) {
                    find_call = 1;
                    break;
                }
            }

            Response res;

            if (find_call) {
                res = ((call_call) calls[cb].call_func)(req);
            } else {
                int f_size = 0;
                int mime = 0;
				klog("[Web Client], starting readFile\n");
                void* f_data = readFile(req->absolute_path, &f_size, &mime);

                if (f_data != NULL) {  
                    res.statut_code = HTTP_OK;
					klog("[Web Client], HTTP_OK\n");
                    res.mime = mime;
                    res.data = f_data;
                    res.data_size = f_size;
                } else {
                    res.statut_code = HTTP_NOT_FOUND;
					klog("[Web Client], HTTP_NOT_FOUND\n");
                    char* error = malloc(strlen(error404) + strlen(req->path) + 1);
                    sprintf(error, error404, req->path);
                    res.mime = getMime("html");
                    res.data =  error;
                    res.data_size = strlen(error) + 1;
                }
            }

            free_request(req);

            int res_size = 0;
            char* res_data = build_response(res, &res_size);
			klog("[Web Client], build_response\n");

            sceNetSend(client_sock, res_data, res_size, 0);
			klog("[Web Client], sceNetSend\n");

            free_response(&res);
            free(res_data);
			klog("[Web Client], Freeing\n");
        }
    } else { free(buffer); }
    
   // sceNetSocketClose(client_sock);
	//klog("[Web Client], sceNetSocketClose\n");
    return 0;
} 

// Wait client
int wait_client() {
	int ret = 0;
    int server = create_server();

	ScePthread	m_thread;
	ScePthreadAttr threadAttr;
	scePthreadAttrInit(&threadAttr);

    int client_sock;

	klog("wait_client start\n");

    while (launched) {
        while ((client_sock = accept_client(server)) && launched) {

			//ret = scePthreadCreate(&m_thread, &threadAttr, threadUserMessage, (void*)this, "user_message_sub_thr");
			//ret = scePthreadCreate(&m_thread, &threadAttr, threadUserMessage, (void*)this, "user_message_sub_thr");
			//scePthreadCreate("web_wait_thread", wait_client, 0x40, 0x5000, 0, 0, NULL);
			ret = scePthreadCreate(&m_thread, &threadAttr, execute_client, NULL, "web_client_thread");
			ret = scePthreadJoin(m_thread, sizeof (void *)&client_sock);
			if (ret < 0)
			{
				launched = -1;
				klog("Fatal Error\n");

			}
          
			klog("web_client_thread created\n");
        }
    }

   // sceNetSocketClose(server);
   // close_net();

    //launched = -1;
    return 0;
}

// Set a port (default: 8080)
void setPort(int value) {
    port = value;
}

// Set max data size (default: 5000)
void setMaxSize(int value) {
    max_size = value;
}

// Set max client (default: 50)
void setMaxClient(int value) {
    max_client = value;
}

// set default page (default: ux0:data)
void setDefaultPath(char* value) {
    default_path = value;
}

// set 404 error page
void set404error(char* value) {
    error404 = value;
}

// set 500 error page
void set500error(char* value) {
    error500 = value;
}

// Init WebServer
void initWebServer() {
    init_net();
    launched = 1;
    calls = malloc(1 * sizeof(call));
}

// launch the server
void launchWebServer() {
	int ret = 0;
	ScePthread	m_thread;
	ScePthreadAttr threadAttr;
	scePthreadAttrInit(&threadAttr); 

	//ret = scePthreadCreate(&m_thread, &threadAttr, threadUserMessage, (void*)this, "user_message_sub_thr");
	//ret = scePthreadCreate(&m_thread, &threadAttr, threadUserMessage, (void*)this, "user_message_sub_thr");
	//scePthreadCreate("web_wait_thread", wait_client, 0x40, 0x5000, 0, 0, NULL);
	ret = scePthreadCreate(&m_thread, &threadAttr, wait_client, NULL, "web_wait_thread");
	ret = scePthreadJoin(m_thread, NULL);
	if (ret < 0)
	{
		launched = -1;
		klog("Fatal Error\n");

	}

	klog("webserver thread created\n");
}

// stop the server
void stopWebServer() {
    launched = 0;
}

// check if the server was stopped
int isServerStop() {
    if (launched == -1) {
        return 1;
    }

    return 0;
}
