# ANDRONESCU IOANA, 331CA
# Operating Sytems 2013 - Assignment 1

CC = gcc
CFLAGS = -g -Wall
OBJ_PARSER = parser.tab.o parser.yy.o
OBJ = main.o utils-lin.o
TARGET = mini-shell

build: $(TARGET)

$(TARGET): parser.tab.o parser.yy.o main.o utils-lin.o
	$(CC) $(CFLAGS) $(OBJ) $(OBJ_PARSER) -o $(TARGET)
	
parser.tab.o: parser.tab.c
	$(CC) $(CFLAGS) -c parser.tab.c
	
parser.yy.o: parser.yy.c
	$(CC) $(CFLAGS) -c parser.yy.c
	
main.o: main.c
	$(CC) $(CFLAGS) -c main.c
	
utils-lin.o: utils-lin.c
	$(CC) $(CFLAGS) -c utils-lin.c
	
.PHONY: clean

clean:
	rm -rf $(OBJ) $(OBJ_PARSER) $(TARGET) *~
