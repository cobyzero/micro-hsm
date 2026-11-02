## CONFIGURATION IS DONE IN FILE config.inc: 

include config.inc

## VARIABLES
INC_DIR     = ../include
OBJ_DIR     = ../obj
SRC_DIR     = ../src
BIN_DIR     = ../bin
CFLAGS      = -Wall -c
VPATH       = $(INC_DIR_P11) $(INC_DIR)
LDFLAGS     = -ldl 

EXECUTABLES  = $(BIN_DIR)/main_3.2.1 \
              $(BIN_DIR)/main_3.2.3 \
              $(BIN_DIR)/main_3.3.3 \
              $(BIN_DIR)/main_3.3.4 \
              $(BIN_DIR)/main_3.3.5 

## RULES
## e.g. to invoke rule "all" type: 
##                                 make all

# rule all: compile all sample programs
.PHONY: all
all: 3.2.1 3.2.3 3.3.3 3.3.4 3.3.5

# rule 3.2.1: compile only main_3.2.1_Initialization.c
.PHONY: 3.2.1
3.2.1: $(OBJ_DIR)/main_3.2.1_Initialization.o $(OBJ_DIR)/pkcs11_handson.o
	$(CC) -o $(BIN_DIR)/main_3.2.1 $+ $(LDFLAGS)

# rule 3.2.3: compile only main_3.2.3_EnsureUserExistence.c
.PHONY: 3.2.3
3.2.3: $(OBJ_DIR)/main_3.2.3_EnsureUserExistence.o $(OBJ_DIR)/pkcs11_handson.o
	$(CC) -o $(BIN_DIR)/main_3.2.3 $+ $(LDFLAGS)

# rule 3.3.3: compile only main_3.3.3_GenerateKeyPair.c
.PHONY: 3.3.3
3.3.3: $(OBJ_DIR)/main_3.3.3_GenerateKeyPair.o $(OBJ_DIR)/pkcs11_handson.o
	$(CC) -o $(BIN_DIR)/main_3.3.3 $+ $(LDFLAGS)

# rule 3.3.4: compile only main_3.3.4_SignData.c
.PHONY: 3.3.4
3.3.4: $(OBJ_DIR)/main_3.3.4_SignData.o $(OBJ_DIR)/pkcs11_handson.o
	$(CC) -o $(BIN_DIR)/main_3.3.4 $+ $(LDFLAGS)

# rule 3.3.5: compile only main_3.3.5_VerifySignedData.c
.PHONY: 3.3.5
3.3.5: $(OBJ_DIR)/main_3.3.5_VerifySignedData.o $(OBJ_DIR)/pkcs11_handson.o
	$(CC) -o $(BIN_DIR)/main_3.3.5 $+ $(LDFLAGS)

# create any of the object files needed above
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c pkcs11_handson.h
	if [ ! -d "$(OBJ_DIR)" ]; then mkdir $(OBJ_DIR); fi
	$(CC)  $(CFLAGS)  $< -o $@  -I$(INC_DIR_P11) -I$(INC_DIR)

# rule clean: remove all object files and executables
.PHONY: clean  
clean:
	rm -f $(OBJ_DIR)/*.o $(EXECUTABLES)






