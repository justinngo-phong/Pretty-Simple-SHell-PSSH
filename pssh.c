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
	int job_num;
} Job;

// global current job pointer and current job number
Job *curr_job;
Job *next_job = NULL;
Job **jobs;

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

	//printf("pgrp: %d\n", pgrp);
		
	if (pgrp == 0)
		pgrp = getpgrp();

	sav = signal(SIGTTOU, SIG_IGN);
	tcsetpgrp(STDOUT_FILENO, pgrp);
				//printf("FG Process Group: %d\n", tcgetpgrp(STDOUT_FILENO));
	signal(SIGTTOU, sav);
}

void terminate_job(int job_num, Job** jobs) {
	free(jobs[job_num]);
   	jobs[job_num] = NULL;
}	

/* Signal handler */
void handler(int sig) {
	pid_t chld;
	int status;
	//printf("handler: %x\n", curr_job);
	
	if ((sig == SIGTTOU) || (sig == SIGTTIN)) {
		while (tcgetpgrp(STDOUT_FILENO) != getpgrp()) 
			pause();
	} else if (sig == SIGCHLD) {
		while ((chld = waitpid(-1, &status, WNOHANG|WUNTRACED|WCONTINUED)) > 0) {
			if (WIFSTOPPED(status)) {
				set_fg_pgrp(0);
				curr_job->status = STOPPED;
				printf("[%d] + suspended\t%s\n", curr_job->job_num, curr_job->name);
			} else if (WIFCONTINUED(status)) {
				curr_job->status = FG;
				/*
			} else if (WIFEXITED(status)) {
				// check to see if child is in foreground first
				int chld_is_fg = 0;
				if (getpgrp() == tcgetpgrp(STDOUT_FILENO)) {
					chld_is_fg = 1;
				}

				set_fg_pgrp(0);
				// if child was in background and finished, print the following
				if (!chld_is_fg)
					printf("[%d] + done\t%s\n", curr_job->job_num, curr_job->name);
				terminate_job(curr_job->job_num, jobs);
				*/
			} else {
				set_fg_pgrp(0);
				printf("next: %x, curr: %x\n", next_job, curr_job);
				printf("freeing of curr: %x, job num %d, jobs[%d]: %x\n", curr_job,
					   	curr_job->job_num, curr_job->job_num, jobs[curr_job->job_num]);
				terminate_job(curr_job->job_num, jobs);
			}
		}
	}
}

// add new job to job array and return job number
void add_new_job(Job* new_job, Job** jobs) {
	int i=0;

	for (i=0; i<MAX_JOBS; i++) {
		if (jobs[i] == NULL) {
			break;
		}
	}
	jobs[i] = new_job;
	jobs[i]->job_num = i;
	printf("next: %x, next job num: %d, jobs[%d]: %x\n", next_job, next_job->job_num, i, jobs[i]);
	printf("curr: %x, jobs[%d]: %x\n", curr_job,i, jobs[i]);
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

// move job to foreground and continue
void fg(char *num_str, Job **jobs) {
	if (num_str == NULL || num_str[0] != '%') {  
		printf("Usage: fg %%<job number>\n");
		return;
	}

	char *job_num_str = num_str + 1;
	int i;
	for (i=0; job_num_str[i] != '\0'; i++) {
		if (!isdigit(job_num_str[i])) {
			printf("pssh: invalid job number: %s\n", num_str);
			return;
		}
	}
	int job_num = atoi(job_num_str);
	if (job_num < 0 || job_num >= 100 || jobs[job_num] == NULL) {
		printf("pssh: invalid job number: %s\n", num_str);
		return;
	}

	//printf("job num: %d, pgid: %d\n", job_num, jobs[job_num]->pgid);
	curr_job = jobs[job_num];
	next_job = curr_job;
	set_fg_pgrp(jobs[job_num]->pgid);
	if (jobs[job_num]->status == STOPPED) { // if it is stopped, then move to fg and continue
		kill(-1 * jobs[job_num]->pgid, SIGCONT);
	} else { // if its running in bg, then just move to fg
		jobs[job_num]->status = FG;
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

	J->status = FG;
	if (!is_builtin(P->tasks[0].cmd))
		add_new_job(J, jobs);
	
    for (t = 0; t < P->ntasks; t++) {
		if (!strcmp(P->tasks[t].cmd, "exit")) {
			builtin_execute(P->tasks[t]);
		} else if (!command_found(P->tasks[t].cmd)) {
			printf("pssh: command not found: %s\n", P->tasks[t].cmd);
			break;
		} else if (!strcmp(P->tasks[0].cmd, "jobs")) {
			print_jobs(jobs);
		} else if (!strcmp(P->tasks[0].cmd, "fg")) {
			fg(P->tasks[0].argv[1], jobs);
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
			if (J->status == FG)
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
}

int main (int argc, char** argv)
{
	jobs = calloc(MAX_JOBS, sizeof(Job*));
    char* cmdline;
    Parse* P;

	signal(SIGTTOU, handler);
	signal(SIGCHLD, handler);
	signal(SIGTTIN, handler);

    print_banner ();

    while (1) {
		curr_job = next_job;
		Job* new_job=malloc(sizeof(Job));
		next_job = new_job;
		//curr_job = new_job;
		//printf("curr %x 0 %x 1 %x 2 %x\n", curr_job, jobs[0], jobs[1], jobs[2]);
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
    next:
        parse_destroy (&P);
        free(cmdline);
    }
	free(jobs);
}
