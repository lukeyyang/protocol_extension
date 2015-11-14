CC = gcc
CFLAGS = -g -Wall -Werror -O
INC = -I./include
SRC_DIR = ./src/c
SRC_EXT = c
BUILD_DIR = ./build
KERNEL = $(shell uname -s)
MACHINE = $(shell uname -m)
DST_DIR = ./bin/$(MACHINE)/$(KERNEL)
TARGETS = $(DST_DIR)/rawtcp $(DST_DIR)/rawudp \
          $(DST_DIR)/udprecv $(DST_DIR)/tcprecv \
          $(DST_DIR)/twhs_client $(DST_DIR)/twhs_server

MKDIR_P = mkdir -p
DIRECTORIES = $(DST_DIR) $(BUILD_DIR)



all: $(DIRECTORIES) $(TARGETS)
tcp: $(DIRECTORIES) $(DST_DIR)/rawtcp
udp: $(DIRECTORIES) $(DST_DIR)/rawudp
udprecv: $(DIRECTORIES) $(DST_DIR)/udprecv
tcprecv: $(DIRECTORIES) $(DST_DIR)/tcprecv
twhs_client: $(DIRECTORIES) $(DST_DIR)/twhs_client
twhs_server: $(DIRECTORIES) $(DST_DIR)/twhs_server

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.$(SRC_EXT)
	$(CC) $< -o $@ $(CFLAGS) -c $(INC) 

$(DST_DIR)/rawtcp: $(BUILD_DIR)/utility.o $(BUILD_DIR)/rawtcp.o 
	$(CC) $^ -o $@

$(DST_DIR)/rawudp: $(BUILD_DIR)/utility.o $(BUILD_DIR)/rawudp.o
	$(CC) $^ -o $@

$(DST_DIR)/udprecv: $(BUILD_DIR)/udprecv.o
	$(CC) $^ -o $@

$(DST_DIR)/tcprecv: $(BUILD_DIR)/tcprecv.o
	$(CC) $^ -o $@

$(DST_DIR)/twhs_client: $(BUILD_DIR)/utility.o $(BUILD_DIR)/twhs_client.o
	$(CC) $^ -o $@

$(DST_DIR)/twhs_server: $(BUILD_DIR)/utility.o $(BUILD_DIR)/twhs_server.o
	$(CC) $^ -o $@

runtcp: $(DST_DIR)/rawtcp
	sudo $(DST_DIR)/rawtcp $(ARGS)

runudp: $(DST_DIR)/rawudp
	sudo $(DST_DIR)/rawudp $(ARGS)

runudprecv: $(DST_DIR)/udprecv
	$(DST_DIR)/udprecv $(ARGS)

runtcprecv: $(DST_DIR)/tcprecv
	$(DST_DIR)/tcprecv $(ARGS)

runtwhsclient: $(DST_DIR)/twhs_client
	sudo $^ $(ARGS)

runtwhsserver: $(DST_DIR)/twhs_server
	sudo $^ $(ARGS)

clean:
	rm -rf $(DST_DIR)/*
	rm -rf $(BUILD_DIR)/*

.PHONY: directories

directories: $(DIRECTORIES)

$(DIRECTORIES):
	$(MKDIR_P) $(DST_DIR)
	$(MKDIR_P) $(BUILD_DIR)
