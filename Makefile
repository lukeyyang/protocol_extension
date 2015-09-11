CC = gcc
CFLAGS = -g -Wall
SRC_DIR = ./src/c
DST_DIR = ./bin/x86_64/Darwin
TARGET = $(DST)/rawtcp $(DST)/rawudp
MKDIR_P = mkdir -p
DIRECTORIES = $(SRC_DIR) $(DST_DIR)



all: $(DIRECTORIES) $(TARGET)
tcp: $(DIRECTORIES) $(DST_DIR)/rawtcp
udp: $(DIRECTORIES) $(DST_DIR)/rawudp


$(DST_DIR)/rawtcp: $(SRC_DIR)/rawtcp.c
	$(CC) $(SRC_DIR)/rawtcp.c -o $(DST_DIR)/rawtcp $(CFLAGS)

$(DST_DIR)/rawudp: $(SRC_DIR)/rawudp.c
	$(CC) $(SRC_DIR)/rawudp.c -o $(DST_DIR)/rawudp $(CFLAGS)

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

