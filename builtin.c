#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "builtin.h"
#include "parse.h"

static char* builtin[] = {
    "exit",   /* exits the shell */
    "which",  /* displays full path to command */
	"fg",	  /* run bg process in fg */
	"bg",	  /* continue running process in bg */
	"jobs",	  /* print out all jobs */
	"kill",	  /* built-in kill signal */
    NULL
};


int is_builtin (char* cmd)
{
    int i;

    for (i=0; builtin[i]; i++) {
        if (!strcmp (cmd, builtin[i]))
            return 1;
    }

    return 0;
}


void builtin_execute (Task T)
{
    if (!strcmp (T.cmd, "exit")) {
		printf("pssh: exiting the shell...\n");
        exit (EXIT_SUCCESS);
    }
	if (!strcmp(T.cmd, "which")) {
		char* path = getenv("PATH");
		char* path_copy;
		char* dir;
		char cmd_path[1024];
		int found = 0;
		int i;

		if (!T.argv[1])
			printf("Usage: which [commands]\n");
		for (i=1; T.argv[i]; i++) {
			if (is_builtin(T.argv[i])) {
				printf("%s: built-in command\n", T.argv[i]);
			} else {
				found = 0;
				path_copy = strdup(path);
				dir = strtok(path_copy, ":");
				while (dir != NULL) {
					snprintf(cmd_path, sizeof(cmd_path), "%s/%s", dir, T.argv[i]);
					if (access(cmd_path, X_OK) == 0) {
						printf("%s: %s\n", T.argv[i], cmd_path);
						found=1;
						break;
					}
					dir = strtok(NULL, ":");
				}
				if(!found) {
					printf("%s: command not found\n", T.argv[i]);
				}
				free(path_copy);
			}
		}
		exit (EXIT_SUCCESS);
	}
    else {
        printf ("pssh: builtin command: %s (not implemented!)\n", T.cmd);
		exit (EXIT_SUCCESS); 
	}
}
