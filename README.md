# Pretty Simple SHell (pssh) Project

Written by: Justin Ngo <br />
Last updated on: 3/16/2023 <br />

## Description
A user shell that is similar to bash. Supported operations:
1. Display the current working directory within the shell prompt.
2. Run a single command with optional input and output redirection. Command line arguments are supported.
3. Run multiple pipelined commands with optional input and output redirection.
4. Builtin command "exit" and "which."
5. Job control:
	1. Builtin foreground command (fg): move background jobs to foreground and run.
	2. Builtin background command (bg): run jobs in the background.
	3. Builtin jobs command (jobs): print out all available jobs and their state.
	4. Run a command in the background by adding ampersand (&) character at the end.
6. Builtin command "kill" that can specify and send signal to multiple jobs and pids at once.


## Make and run
* make: compile the pssh shell from all the source files
* To run the shell: ./pssh
* make clean: remove .o, .txt, any core dump and the built pssh shell  


## List of source files 
* builtin.c: check if a command is built in and execute.
* builtin.h: header file of builtin.c.
* parse.c: parse command line into different command lines with their arguments.
* parse.h: header file of parse.c.
* pssh.c: main file for the shell, including checking if a command is available and executing all of them.
* Makefile: makefile :)
* README.md: it's the one you are reading. 

