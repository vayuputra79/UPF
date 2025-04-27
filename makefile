all:
	gcc -g3 -o upf upf.c pfcp_server.c pfcp.c libsicore.so -lpthread -Wl,-rpath .