
## CONFIGURATION IS DONE IN FILE config.inc: 

include config.inc

## VARIABLES
ARCH        := $(shell uname -m)
SRC_DIR     = ../src
OBJ_DIR     = ../obj
INC_DIR     = ../include
BIN_DIR     = ../bin/linux_$(ARCH)
VPATH       = $(INC_DIR_CXI) $(INC_DIR)
CFLAGS      = -Wall -c -D_GLIBCXX_USE_CXX11_ABI=0
LDFLAGS     = -lcxi_m -ldl -lrt -lpthread


    
.PHONY: all
all: $(OBJ_DIR)/demo_main.o $(OBJ_DIR)/demo_functions.o  $(OBJ_DIR)/demo_classes.o
	if [ ! -d "$(BIN_DIR)" ]; then mkdir $(BIN_DIR); fi
	$(CC) -o $(BIN_DIR)/demo_LoadBalancing $+ -L$(LIB_PATH) $(LDFLAGS)


# create any of the object files needed above
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp  demo.h
	if [ ! -d "$(OBJ_DIR)" ]; then mkdir $(OBJ_DIR); fi
	$(CC)  $(CFLAGS)  $< -o $@  -I$(INC_DIR_CXI) -I$(INC_DIR) 
    
    
    
# rule info: get system architecture
.PHONY: info
info:
	@echo "system architecture is ${ARCH}"
    
# rule clean: remove all object files and executables
.PHONY: clean  
clean:
	rm -f $(OBJ_DIR)/*.o $(BIN_DIR)/cxi_demo_LoadBalancing
	







