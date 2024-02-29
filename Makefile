CFLAGS = -std=gnu99 -Wall -Wno-unused
TARGET = icmp_demon
SRC = icmp_demon.c toml.c utils.c
SRC_DIR = src
BUILD_DIR = build
INSTALL_DIR = /usr/local/sbin

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir $(BUILD_DIR)

$(TARGET): $(BUILD_DIR)/icmp_demon.o $(BUILD_DIR)/utils.o $(BUILD_DIR)/toml.o 
	$(CC) $(CFLAGS) -o icmp_demon $(BUILD_DIR)/icmp_demon.o $(BUILD_DIR)/utils.o $(BUILD_DIR)/toml.o

$(BUILD_DIR)/icmp_demon.o: $(SRC_DIR)/icmp_demon.c
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/icmp_demon.o -c $(SRC_DIR)/icmp_demon.c $(CFLAGS)

$(BUILD_DIR)/utils.o: $(SRC_DIR)/utils.c $(SRC_DIR)/utils.h
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/utils.o -c $(SRC_DIR)/utils.c $(CFLAGS)

$(BUILD_DIR)/toml.o: $(SRC_DIR)/toml.c $(SRC_DIR)/toml.h
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/toml.o -c $(SRC_DIR)/toml.c $(CFLAGS)

install: $(TARGET)
	install -m 755 $< $(INSTALL_DIR)
	install -m 755 icmp-demon.service /usr/lib/systemd/system

.PHONY: clean

clean:
	rm -f $(TARGET)
	rm -f $(BUILD_DIR)/*.o
