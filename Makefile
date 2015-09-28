CC = gcc
CFLAGS = -g -Wall
SRC_DIR = ./src/c
KERNEL = $(shell uname -s)
MACHINE = $(shell uname -m)
DST_DIR = ./bin/$(MACHINE)/$(KERNEL)
TARGET = $(DST_DIR)/rawtcp $(DST_DIR)/rawudp $(DST_DIR)/udprecv
MKDIR_P = mkdir -p
DIRECTORIES = $(SRC_DIR) $(DST_DIR)



all: $(DIRECTORIES) $(TARGET)
tcp: $(DIRECTORIES) $(DST_DIR)/rawtcp
udp: $(DIRECTORIES) $(DST_DIR)/rawudp
udprecv: $(DIRECTORIES) $(DST_DIR)/udprecv


$(DST_DIR)/rawtcp: $(SRC_DIR)/rawtcp.c
	$(CC) $(SRC_DIR)/rawtcp.c -o $(DST_DIR)/rawtcp $(CFLAGS)

$(DST_DIR)/rawudp: $(SRC_DIR)/rawudp.c
	$(CC) $(SRC_DIR)/rawudp.c -o $(DST_DIR)/rawudp $(CFLAGS)

$(DST_DIR)/udprecv: $(SRC_DIR)/udprecv.c
	$(CC) $(SRC_DIR)/udprecv.c -o $(DST_DIR)/udprecv $(CFLAGS)

runtcp: $(DST_DIR)/rawtcp
	sudo $(DST_DIR)/rawtcp

runudp: $(DST_DIR)/rawudp
	sudo $(DST_DIR)/rawudp

clean:
	rm -rf $(DST_DIR)/*

.PHONY: directories

directories: $(DIRECTORIES)

$(DIRECTORIES):
	$(MKDIR_P) $(SRC_DIR)
	$(MKDIR_P) $(DST_DIR)

