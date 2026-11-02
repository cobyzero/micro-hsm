## CONFIGURATION IS DONE IN FILE config.inc: 

include config.inc

## VARIABLES
INC_DIR     = ../include
ARCH        = ${shell uname -m}
OBJ_DIR     = ../obj
SRC_DIR     = ../src
BIN_DIR     = ../bin
VPATH       = $(INC_DIR_P11) $(INC_DIR)
CFLAGS      = -Wall -c
LDFLAGS     = -ldl -lpthread


## RULES
## e.g. to invoke rule "all" type: 
##                                 make all

# rule 'all': compile all sample programs
.PHONY: all
all: main

# rule 'main': compile main program
.PHONY: main
main: $(OBJ_DIR)/demo_LoadBalancing_main.o $(OBJ_DIR)/demo_LoadBalancing.o
	$(CC) -o $(BIN_DIR)/demo_LoadBalancing_linux $+ $(LDFLAGS)


# create any of the object files needed above
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c demo_LoadBalancing.h
	if [ ! -d "$(OBJ_DIR)" ]; then mkdir $(OBJ_DIR); fi
	$(CC)  $(CFLAGS)  $< -o $@  -I$(INC_DIR_P11) -I$(INC_DIR)

.PHONY: info
info:
	@echo "system architecture is ${ARCH}"

# rule clean: remove all object files and executables
.PHONY: clean  
clean:
	rm -f $(OBJ_DIR)/*.o $(BIN_DIR)/demo_LoadBalancing_linux



