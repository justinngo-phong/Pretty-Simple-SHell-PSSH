#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <readline/readline.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "builtin.h"
#include "parse.h"

/*******************************************
 * Set to 1 to view the command line parse *
 *******************************************/
#define DEBUG_PARSE 0
#define MAX_JOBS 100

typedef enum {
	STOPPED,
	TERM,
	BG,
	FG,
} JobStatus;

typedef struct {
	char *name;
	pid_t *pids;
	unsigned int npids;
	pid_t pgid;
	JobStatus status;
} Job;

void print_banner ()
{
    printf ("                    ________   \n");
    printf ("_________________________  /_  \n");
    printf ("___  __ \\_  ___/_  ___/_  __ \\ \n");
    printf ("__  /_/ /(__  )_(__  )_  / / / \n");
    printf ("_  .___//____/ /____/ /_/ /_/  \n");
    printf ("/_/ Type 'exit' or ctrl+c to quit\n\n");
}


/* returns a string for building the prompt
 *
 * Note:
 *   If you modify this function to return a string on the heap,
 *   be sure to free() it later when appropirate!  */
static char* build_prompt ()
{
	char cwd[1024];
	char *prompt;
	if (getcwd(cwd, sizeof(cwd)) != NULL) {
		int l = strlen(cwd) + strlen("$ ") + 1;
		prompt = (char*)malloc(l);
		strcpy(prompt,cwd);
		strcat(prompt,"$ ");
	} else {
		prompt = "$ ";
	}
	return prompt;
}


/* return true if command is found, either:
 *   - a valid fully qualified path was supplied to an existing file
 *   - the executable file was found in the system's PATH
 * false is returned otherwise */
static int command_found (const char* cmd)
{
    char* dir;
    char* tmp;
    char* PATH;
    char* state;
    char probe[PATH_MAX];

    int ret = 0;

    if (access (cmd, X_OK) == 0)
        return 1;

    PATH = strdup (getenv("PATH"));

    for (tmp=PATH; ; tmp=NULL) {
        dir = strtok_r (tmp, ":", &state);
        if (!dir)
            break;

        strncpy (probe, dir, PATH_MAX-1);
        strncat (probe, "/", PATH_MAX-1);
        strncat (probe, cmd, PATH_MAX-1);

        if (access (probe, X_OK) == 0) {
            ret = 1;
            break;
        }
    }

    free (PATH);
    return ret;
}

/* Set foreground process */
void set_fg_pgrp(pid_t pgrp)
{
	void (*sav)(int sig);
		
	if (pgrp == 0)
		pgrp = getpgrp();

	sav = signal(SIGTTOU, SIG_IGN);
	tcsetpgrp(STDOUT_FILENO, pgrp);
	signal(SIGTTOU, sav);
	
	while (tcgetpgrp(STDOUT_FILENO) != getpgrp())
		pause();	
}

/* Signal handler */
void handler(int sig) {
	pid_t chld;
	int status;
	
	if ((sig == SIGTTOU) || (sig == SIGTTIN)) {
		//while (tcgetpgrp(STDOUT_FILENO) != getpgrp()) 
		while (tcgetpgrp(0) != getpgrp()) 
			pause();
	} else if (sig == SIGCHLD) {
		while ((chld = waitpid(-1, &status, WNOHANG|WUNTRACED|WCONTINUED)) > 0) {
			if (WIFSTOPPED(status)) {
				set_fg_pgrp(0);
				
			} else {
				set_fg_pgrp(0);
			}
		}
	}
}

// add new job to job array and return job number
int add_new_job(Job* new_job, Job** jobs) {
	int i=0;
	while (jobs[i] != NULL) {
		i++;
	}
	jobs[i] = new_job;
	return i;
}

void delete_job(int job_num, Job** jobs) {
   	jobs[job_num] = NULL;
}	

void print_jobs(Job **jobs) {
	int i;

	for (i=0; i<MAX_JOBS; i++) {
		if (jobs[i] != NULL) {
			if (jobs[i]->status == STOPPED) {
				printf("[%d] + stopped\t%s\n", i, jobs[i]->name);
			} else if (jobs[i]->status == BG || jobs[i]->status == FG) {
				printf("[%d] + running\t%s\n", i, jobs[i]->name);
			}
		}
	}
}

	
/* Called upon receiving a successful parse.
 * This function is responsible for cycling through the
 * tasks, and forking, executing, etc as necessary to get
 * the job done! */
void execute_tasks (Parse* P, Job* J, Job** jobs)
{
    int fd[2];
	int prev_fd;
    pid_t pid[P->ntasks];
	int fd_in = STDIN_FILENO;
	int fd_out = STDOUT_FILENO;
    unsigned int t;


	// create new job
	J->pids = pid;
	J->npids = P->ntasks;

	int curr_job_num = add_new_job(J, jobs);

    for (t = 0; t < P->ntasks; t++) {
		if (!strcmp(P->tasks[t].cmd, "exit")) {
			builtin_execute(P->tasks[t]);
		} else if (!command_found(P->tasks[t].cmd)) {
			printf("pssh: command not found: %s\n", P->tasks[t].cmd);
			break;
		} else if (!strcmp(P->tasks[t].cmd, "jobs")) {
		 	print_jobs(jobs);  
		} else { 
			// create a new pipe
			if (pipe(fd) == -1) {
				printf("pssh: failed to create pipe\n");
				exit(EXIT_FAILURE);
			}
		pid[t] = fork();
		if (pid[t] == -1) {
			printf("pssh: failed to fork\n");
			exit(EXIT_FAILURE);
		}
		setpgid(pid[t], pid[0]);
		J->pgid = pid[0];
		J->status = FG;
		set_fg_pgrp(pid[0]);


			if (pid[t] == 0) { /* Child Process */
				// redirect input to input file if there exists one
				// note: this process is only ran for the first task 
				// 		or if there is only one task 
				if ((t == 0) && (P->infile)) {
					fd_in = open(P->infile, O_RDONLY);
					if (fd_in == -1) {
						printf("pssh: failed to open input file\n");
						exit(EXIT_FAILURE);
					}
					
					if (dup2(fd_in, STDIN_FILENO) == -1) {
						printf("pssh: dup2 failed\n");
						exit(EXIT_FAILURE);
					}

					close(fd_in);
				}

				// redirect output to output file if there exists one
				// note: this process is only ran for the last task
				// 		or if there is only one task
				if ((t == P->ntasks-1) && (P->outfile)) {
					fd_out = open(P->outfile, O_WRONLY|O_CREAT|O_TRUNC, 0664);
					if (fd_out == -1) {
						printf("pssh: failed to open output file\n");
						exit(EXIT_FAILURE);
					}
					if (dup2(fd_out, STDOUT_FILENO) == -1) {
						printf("pssh: dup2 failed\n");
						exit(EXIT_FAILURE);
					}

					close(fd_out);
				}

				// redirect write side of previous pipe to stdin of child process
				// note: used for tasks after the first one
				if (t > 0) {
					if (dup2(prev_fd, STDIN_FILENO) == -1) {
						printf("pssh: dup2 failed\n");
						exit(EXIT_FAILURE);
					}
					close(prev_fd);
				}

				// redirect read side of the new pipe to stdout of child process
				// note: used for tasks before the last one
				if (t < P->ntasks - 1) {
					if (dup2(fd[1], STDOUT_FILENO) == -1) {
						printf("pssh: dup2 failed\n");
						exit(EXIT_FAILURE);
					}
					close(fd[1]);
				}
				
				// close read side of new pipe
				close(fd[0]);

				// exec builtin-command if it is one
				if (is_builtin(P->tasks[t].cmd)) {
					builtin_execute(P->tasks[t]);
				} else if (command_found(P->tasks[t].cmd)) {
					execvp(P->tasks[t].cmd, P->tasks[t].argv);
					printf("pssh: failed to exec\n");
					exit(EXIT_FAILURE);
				}
			} else { /* Parent Process */
				// if the parent process is not the initial process
				// then close the the previous file descriptor
				if (t > 0) {
					close(prev_fd);
				}

				prev_fd = fd[0];
				close(fd[1]);
				if (t  == P->ntasks-1) {
					close(prev_fd);
				}
			}
		
		}
	}
	// parent waits for all its child
	for (t = 0; t < P->ntasks; t++) {
		int status;
		waitpid(pid[t], &status, WNOHANG);
	}
	delete_job(curr_job_num, jobs);
}

int main (int argc, char** argv)
{
    char* cmdline;
    Parse* P;
	Job **jobs = calloc(MAX_JOBS, sizeof(Job*));

	signal(SIGTTOU, handler);
	signal(SIGCHLD, handler);
	signal(SIGTTIN, handler);

    print_banner ();

    while (1) {
		Job* new_job=malloc(sizeof(Job));
		char *prompt = build_prompt();
        cmdline = readline (prompt);
		free(prompt);
        if (!cmdline)       /* EOF (ex: ctrl-d) */
            exit (EXIT_SUCCESS);

		new_job->name = strdup(cmdline);
        P = parse_cmdline (cmdline);
        if (!P)
            goto next;

        if (P->invalid_syntax) {
            printf ("pssh: invalid syntax\n");
            goto next;
        }

#if DEBUG_PARSE
        parse_debug (P);
#endif

        execute_tasks (P, new_job, jobs);
		free(new_job);
    next:
        parse_destroy (&P);
        free(cmdline);
    }
	free(jobs);
}
