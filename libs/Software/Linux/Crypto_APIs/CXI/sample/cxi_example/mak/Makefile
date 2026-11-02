
## CONFIGURATION IS DONE IN FILE config.inc: 

include config.inc

## VARIABLES
ARCH        := $(shell uname -m)
SRC_DIR     = ../src
OBJ_DIR     = ../obj
BIN_DIR     = ../bin/linux_$(ARCH)
CFLAGS      = -Wall -c -D_GLIBCXX_USE_CXX11_ABI=0
LDFLAGS     = -lcxi_m -ldl -lrt -lpthread

.PHONY: all
all:
	mkdir -p $(BIN_DIR)
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $(OBJ_DIR)/cxi_demo.o -I$(INC_DIR) $(SRC_DIR)/cxi_demo.cpp
	$(CC)  $(OBJ_DIR)/cxi_demo.o -L$(LIB_PATH) $(LDFLAGS) -o $(BIN_DIR)/cxi_demo

# rule info: get system architecture
.PHONY: info
info:
	@echo "system architecture is ${ARCH}"
    
# rule clean: remove all object files and executables
.PHONY: clean  
clean:
	rm -f $(OBJ_DIR)/cxi_demo.o $(BIN_DIR)/cxi_demo
	







