CC = gcc
CFLAGS = -g -Wall -Werror -O
INC = -I./include
SRC_DIR = ./src/c
SRC_EXT = c
BUILD_DIR = ./build
KERNEL = $(shell uname -s)
MACHINE = $(shell uname -m)
DST_DIR = ./bin/$(MACHINE)/$(KERNEL)
TARGETS = $(DST_DIR)/rawtcp $(DST_DIR)/rawudp $(DST_DIR)/udprecv
MKDIR_P = mkdir -p
DIRECTORIES = $(DST_DIR) $(BUILD_DIR)



all: $(DIRECTORIES) $(TARGETS)
tcp: $(DIRECTORIES) $(DST_DIR)/rawtcp
udp: $(DIRECTORIES) $(DST_DIR)/rawudp
udprecv: $(DIRECTORIES) $(DST_DIR)/udprecv

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.$(SRC_EXT)
	$(CC) $< -o $@ $(CFLAGS) -c $(INC) 

$(DST_DIR)/rawtcp: $(BUILD_DIR)/utility.o $(BUILD_DIR)/rawtcp.o 
	$(CC) $^ -o $@

$(DST_DIR)/rawudp: $(BUILD_DIR)/utility.o $(BUILD_DIR)/rawudp.o
	$(CC) $^ -o $@

$(DST_DIR)/udprecv: $(BUILD_DIR)/udprecv.o
	$(CC) $^ -o $@

runtcp: $(DST_DIR)/rawtcp
	sudo $(DST_DIR)/rawtcp $(ARGS)

runudp: $(DST_DIR)/rawudp
	sudo $(DST_DIR)/rawudp $(ARGS)

runudprecv: $(DST_DIR)/udprecv
	$(DST_DIR)/udprecv $(ARGS)

clean:
	rm -rf $(DST_DIR)/*
	rm -rf $(BUILD_DIR)/*

.PHONY: directories

directories: $(DIRECTORIES)

$(DIRECTORIES):
	$(MKDIR_P) $(DST_DIR)
	$(MKDIR_P) $(BUILD_DIR)
