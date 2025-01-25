# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = 

# Source files
PING_SRC = ping.c
TRACEROUTE_SRC = traceroute.c

# Object files
PING_OBJ = $(PING_SRC:.c=.o)
TRACEROUTE_OBJ = $(TRACEROUTE_SRC:.c=.o)

# Output executables
PING_EXEC = ping
TRACEROUTE_EXEC = traceroute

# Default target
all: $(PING_EXEC) $(TRACEROUTE_EXEC)

# Compile ping
$(PING_EXEC): $(PING_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile traceroute
$(TRACEROUTE_EXEC): $(TRACEROUTE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile .c files into .o files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up generated files
clean:
	rm -f $(PING_OBJ) $(TRACEROUTE_OBJ) $(PING_EXEC) $(TRACEROUTE_EXEC)

# Run ping executable
run-ping:
	sudo ./$(PING_EXEC)

# Run traceroute executable
run-traceroute:
	sudo ./$(TRACEROUTE_EXEC) -a 8.8.8.8

.PHONY: all clean run-ping run-traceroute

