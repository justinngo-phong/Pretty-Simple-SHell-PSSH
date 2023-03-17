#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <readline/readline.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

#include "builtin.h"
#include "parse.h"

/****************************************************************
 * Set DEBUG_PARSE to 1 to view the command line parse 			*
 * Set DEBUG_PRINT to 1 to use p to print out job array content *
 ***************************************************************/
#define DEBUG_PARSE 0
#define DEBUG_PRINT 0
#define MAX_JOBS 100

/* job states */
typedef enum {
	STOPPED,
	TERM,
	BG,
	FG,
} JobStatus;

/* job struct */
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
Job **jobs;
pid_t pssh_id;

#if DEBUG_PRINT
// debugging function to print all jobs in job array
void _print_job_array() {
	int i, j;
	for (i=0; i<MAX_JOBS; i++) {
		if (jobs[i] != NULL) {
			printf("jobs[%d]:\n", i);
			printf("name = %s\n", jobs[i]->name);
			printf("npids = %d\n", jobs[i]->npids);
			printf("pids = \n");
			for (j=0; j<jobs[i]->npids; j++)
				printf("\t%d\n", jobs[i]->pids[j]);
			printf("pgid = %d\n", jobs[i]->pgid);
			printf("status = %d\n", jobs[i]->status);
			printf("\n");
		}
	}
}
#endif

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
}

/* set the finished pid in job to 0 */
void remove_pid(int job_num, pid_t pid) {
	int i;
	for (i=0; i<jobs[job_num]->npids; i++) {
		if (jobs[job_num]->pids[i] == pid) {
			jobs[job_num]->pids[i] = 0;
			return;
		}
	}
}

/* check if the current job has finished */
int job_finished(int job_num) {
	int i;
	for (i=0; i<jobs[job_num]->npids; i++) {
		if (jobs[job_num]->pids[i] !=0) {
			return 0;
		}
	}
	return 1;
}

/* get the current job by supplying a pid */
void get_curr_job(pid_t pid) {
	int i, j;
	for (i=0; i<MAX_JOBS; i++) {
		if (jobs[i]) {
			for (j=0; j<jobs[i]->npids; j++) {
				if (jobs[i]->pids[j] == pid) {
					curr_job = jobs[i];
					return;
				}
			}
		}
	}
}

/* terminate job by freeing its memory and setting 
 * its position in the job array to NULL */
void terminate_job(int job_num) {
	free(jobs[job_num]->name);
	free(jobs[job_num]->pids);
	free(jobs[job_num]);
   	jobs[job_num] = NULL;
}	

/* add new job pointer to the global job array 
 * and set the current job pointer to the new job */
void add_new_job(Job* new_job) {
	int i=0;

	curr_job = new_job;
	for (i=0; i<MAX_JOBS; i++) {
		if (jobs[i] == new_job) 
			return; 
		if (jobs[i] == NULL) 
			break;
	}
	jobs[i] = new_job;
	jobs[i]->job_num = i;
}

/* print out all available jobs in the job array */
void print_jobs() {
	int i;

	for (i=0; i<MAX_JOBS; i++) {
		if (jobs[i] != NULL) {
			if (jobs[i]->status == STOPPED) {
				printf("[%d] + stopped     %s\n", i, jobs[i]->name);
			} else if (jobs[i]->status == BG || jobs[i]->status == FG) {
				printf("[%d] + running     %s\n", i, jobs[i]->name);
			} 
		}
	}
}

/* move job to foreground and continue */
void fg(char *num_str) {
	if (num_str == NULL) {  
		printf("Usage: fg %%<job number>\n");
		return;
	}

	if (num_str[0] != '%') {  
		printf("pssh: invalid job number: %s\n", num_str);
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

	curr_job = jobs[job_num];
	jobs[job_num]->status = FG;
	set_fg_pgrp(jobs[job_num]->pgid);
	kill(-1 * jobs[job_num]->pgid, SIGCONT);
}

/* continue job in background */
void bg(char *num_str) {
	if (num_str == NULL) { 
		printf("Usage: fg %%<job number>\n");
		return;
	}

	if (num_str[0] != '%') {  
		printf("pssh: invalid job number: %s\n", num_str);
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

	curr_job = jobs[job_num];
	if (jobs[job_num]->status == STOPPED) { // if it is stopped, continue to run it in background
		kill(-1 * jobs[job_num]->pgid, SIGCONT);
	} else { // if its running in background, do nothing 
		jobs[job_num]->status = BG;
	}
}

/* kill command error message */
void kill_usage() {
	printf("Usage: kill [-s <signal>] <pid> | %%<job> ...\n");
}

/* built in kill command
 * accept a list of pids and jobs
 * allow specifying signal to send */
void kill_cmd(Task T) {
	int i = 1;
	int sig = SIGTERM;
	int pid;
	int signal_sent;
	int job_num;

	// check if possible
	if (!T.argv[1]) { // there is no argument
		kill_usage();
		return;
	}

	if (!strcmp(T.argv[1], "-s")) { // if -s flag is supplied
		if (!T.argv[2]) { // example: kill -s => not enough
			kill_usage();
			return;
		} else if (!T.argv[3]) { // example: kill -s 0 => still not enough (no pid or job args)
			kill_usage();
			return;
		}	
		sig = atoi(T.argv[2]);
		i = 3; // start iterating from the argv[3]
	}


	while (T.argv[i]) {
		if (T.argv[i][0] == '%') { // is a job
			job_num = atoi(T.argv[i] + 1);
			if (jobs[job_num] == NULL) {
				printf("pssh: invalid job number: %s\n", T.argv[i]);
			} else {
				signal_sent = kill(-1*jobs[job_num]->pgid, sig);
			}
		} else {
			pid = atoi(T.argv[i]);
			signal_sent = kill(pid, sig);
			if (signal_sent == -1) {
				printf("pssh: invalid pid: %s\n", T.argv[i]);
			}
		}
		i++;
	}
}

/* Signal handler */
void handler(int sig) {
	pid_t chld;
	int status;
	
	if (sig == SIGTTOU) {
		while (tcgetpgrp(STDOUT_FILENO) != getpgrp()) 
			pause();
	} else if (sig == SIGTTIN) {
		while (tcgetpgrp(STDIN_FILENO) != getpgrp()) 
			pause();
	} else if (sig == SIGCHLD) {
		while ((chld = waitpid(-1, &status, WNOHANG|WUNTRACED|WCONTINUED)) > 0) {
			get_curr_job(chld); // get the current job pointer
			if (WIFSTOPPED(status)) {
				if (curr_job->status != STOPPED) {
					set_fg_pgrp(0);
					curr_job->status = STOPPED;
					printf("\n[%d] + suspended   %s\n", curr_job->job_num, curr_job->name);
				}
				continue;
			} else if (WIFCONTINUED(status)) {
				if (curr_job->status == STOPPED) {
					curr_job->status = BG;
					printf("[%d] + continued   %s\n", curr_job->job_num, curr_job->name);
				}
				continue;
			} else {
				remove_pid(curr_job->job_num, chld); // remove the child pid from the current job
				if (job_finished(curr_job->job_num)) { // if current job doesn't have any more pids, then terminate
					set_fg_pgrp(0);
					if (curr_job->status == BG) {  // only print out done if job status is background
						printf("\n[%d] + done        %s\n", curr_job->job_num, curr_job->name);
					}
					terminate_job(curr_job->job_num); // terminate the job by freeing its memory and set its position in the job array to NULL
				}
			}
		}
	}
}
	
/* Called upon receiving a successful parse.
 * This function is responsible for cycling through the
 * tasks, and forking, executing, etc as necessary to get
 * the job done! */
void execute_tasks (Parse* P, Job* J)
{
    int fd[2];
	int prev_fd;
    pid_t *pid = malloc(sizeof(pid_t) * P->ntasks);
	int fd_in = STDIN_FILENO;
	int fd_out = STDOUT_FILENO;
    unsigned int t, i;

	// setting up new job
	J->pids = pid;
	J->npids = P->ntasks;
	
    for (t = 0; t < P->ntasks; t++) {
		if (!command_found(P->tasks[t].cmd)) {
			printf("pssh: command not found: %s\n", P->tasks[t].cmd);
			return;
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

			if (!pid[t]) { /* Child Process */
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

				if ((t == P->ntasks-1) && (P->outfile)) {
					fd_out = open(P->outfile, O_WRONLY|O_CREAT|O_TRUNC, 0600);
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

				if (t > 0) {
					if (dup2(prev_fd, STDIN_FILENO) == -1) {
						printf("pssh: dup2 failed\n");
						exit(EXIT_FAILURE);
					}
					close(prev_fd);
				}

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

	// set job pgid to the leader's pid
	J->pgid = pid[0];
	add_new_job(J);

	// run job either in background or foreground
	if (!P->background) { 
		J->status = FG;
		set_fg_pgrp(pid[0]);
	} else {
		J->status = BG;
		printf("[%d] ", J->job_num);
		for (i=0; i<P->ntasks; i++) {
			printf("%d ", J->pids[i]);
		}
		printf("\n");
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
	pssh_id = getpgrp();

    while (1) {
		Job* new_job=malloc(sizeof(Job));
		char *prompt = build_prompt();
        cmdline = readline (prompt);
		free(prompt);
		new_job->name = strdup(cmdline);
        if (!cmdline)       /* EOF (ex: ctrl-d) */
            exit (EXIT_SUCCESS);

        P = parse_cmdline (cmdline);
        if (!P)
            goto next;

        if (P->invalid_syntax) {
            printf ("pssh: invalid syntax\n");
            goto next;
        }

		if (!strcmp(P->tasks[0].cmd, "exit")) {
			builtin_execute(P->tasks[0]);
            goto next;
		} else if (!strcmp(P->tasks[0].cmd, "jobs")) {
			print_jobs();
            goto next;
		} else if (!strcmp(P->tasks[0].cmd, "fg")) {
			fg(P->tasks[0].argv[1]);
            goto next;
		} else if (!strcmp(P->tasks[0].cmd, "bg")) {
			bg(P->tasks[0].argv[1]);
            goto next;
		} else if (!strcmp(P->tasks[0].cmd, "kill")) {
			kill_cmd(P->tasks[0]);
            goto next;
#if DEBUG_PRINT
		} else if (!strcmp(P->tasks[0].cmd, "p")) {
			_print_job_array();
            goto next;
#endif
		}


#if DEBUG_PARSE
        parse_debug (P);
#endif

        execute_tasks (P, new_job);
    next:
        parse_destroy (&P);
        free(cmdline);
    }
	free(jobs);
}
