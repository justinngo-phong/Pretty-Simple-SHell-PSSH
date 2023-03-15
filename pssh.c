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

/*******************************************
 * Set to 1 to view the command line parse *
 *******************************************/
#define DEBUG_PARSE 0
#define DEBUG_PRINT 1
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
// Job *next_job = NULL;
Job **jobs;

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

void remove_pid(int job_num, pid_t pid) {
	int i;
	for (i=0; i<jobs[job_num]->npids; i++) {
		if (jobs[job_num]->pids[i] == pid) {
			jobs[job_num]->pids[i] = 0;
			return;
		}
	}
}

int job_finished(int job_num) {
	int i;
	for (i=0; i<jobs[job_num]->npids; i++) {
		if (jobs[job_num]->pids[i] !=0) {
			return 0;
		}
	}
	return 1;
}


void terminate_job(int job_num) {
	free(jobs[job_num]->name);
	free(jobs[job_num]->pids);
	free(jobs[job_num]);
   	jobs[job_num] = NULL;
}	

/* Signal handler */
void handler(int sig) {
	pid_t chld;
	int status;
	
	if ((sig == SIGTTOU) || (sig == SIGTTIN)) {
		while (tcgetpgrp(STDOUT_FILENO) != getpgrp()) 
			pause();
	} else if (sig == SIGCHLD) {
		while ((chld = waitpid(-1, &status, WNOHANG|WUNTRACED|WCONTINUED)) > 0) {
			if (WIFSTOPPED(status)) {
				set_fg_pgrp(0);
				curr_job->status = STOPPED;
				printf("\n[%d] + suspended\t\t%s\n", curr_job->job_num, curr_job->name);
			} else if (WIFCONTINUED(status)) {
				if (getpgrp() == tcgetpgrp(STDOUT_FILENO)) {
					curr_job->status = BG;
					printf("\n[%d] + continued\t\t%s\n", curr_job->job_num, curr_job->name);
				} else {
					curr_job->status = FG;
				}
			} else {
				remove_pid(curr_job->job_num, chld);
				if (job_finished(curr_job->job_num)) { 
					set_fg_pgrp(0);
					if (curr_job->status == BG) { 
						printf("\n[%d] + done\t\t%s\n", curr_job->job_num, curr_job->name);
					}
					terminate_job(curr_job->job_num);
				}
			}
		}
	}
}

// add new job to job array and return job number
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

void print_jobs() {
	int i;

	for (i=0; i<MAX_JOBS; i++) {
		if (jobs[i] != NULL) {
			if (jobs[i]->status == STOPPED) {
				printf("[%d] + stopped\t\t%s\n", i, jobs[i]->name);
			} else if (jobs[i]->status == BG || jobs[i]->status == FG) {
				printf("[%d] + running\t\t%s\n", i, jobs[i]->name);
			} 
		}
	}
}

// move job to foreground and continue
void fg(char *num_str) {
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

	curr_job = jobs[job_num];
	set_fg_pgrp(jobs[job_num]->pgid);
	if (jobs[job_num]->status == STOPPED) { // if it is stopped, then move to fg and continue
		kill(-1 * jobs[job_num]->pgid, SIGCONT);
	} else { // if its running in bg, then just move to fg
		jobs[job_num]->status = FG;
	}
}

// continue job in background
void bg(char *num_str) {
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

	curr_job = jobs[job_num];
	if (jobs[job_num]->status == STOPPED) { // if it is stopped, then move to fg and continue
		kill(-1 * jobs[job_num]->pgid, SIGCONT);
	} else { // if its running in bg, then just move to fg
		jobs[job_num]->status = FG;
	}
}


const char *sigabbrev(unsigned int sig)
{
	const char *sigs[31] = { "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", 
		"BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM",
		"TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN",
		"TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO",
		"PWR", "SYS" };
	if (sig > 31)
		return NULL;
	return sigs[sig-1];
}

void signals_list() {
	int i;
	for (i=1; i<=31; i++) {
		printf("%2d) SIG%s\t%s\n", i, sigabbrev(i), strsignal(i));
	}
}

void usage() {
	printf("Usage: ./signal [options] <pid>\n");
	printf("\n");
	printf("Options:\n");
	printf("\t-s <signal>\tSends <signal> to <pid>\n");
	printf("\t-l\t\tLists all signal numbers with their names\n");
}

int kill_cmd(int argc, char *argv[]) {
	int opt;
	int sig = SIGTERM;
	int pid;

	if (argc == 1) {
		usage();
		return 1;
	}
	
	// get the options
	while ((opt = getopt(argc, argv, "ls:")) != -1) {
		switch (opt) {
			case 's':
				// get the signal number
				sig = atoi(optarg);
				break;
			case 'l':
				signals_list();
				return 0;
			default:
				usage();
				return 1;
		}
	}	

	// if optind (option index from the getopt function) is greater than the argument count then printout the usage
	if (argc <= optind) {
		usage();
		return 1;
	}

	// get pid which is at index optind of the argument list
	pid = atoi(argv[optind]);

	// send the signal to pid with the kill function
	int signal_sent = kill(pid, sig);

	// if the return value of kill is -1 then there are errors
	if (signal_sent == -1) {
		switch (errno) {
			case EINVAL:
				printf("%d is an invalid signal\n", sig);
				return 1;
			case EPERM:
				printf("PID %d exists, but we can't send it signals\n", pid);
				return 1;
			case ESRCH:
				printf("PID %d does not exist\n", pid);
				return 1;
			default:
				printf("Cannot send signal %d to PID %d\n", sig, pid);
				return 1;
		}
	}

	// if signal number is 0 and there is no err, then PID exists and can receive signals
	if ((sig == 0) && (signal_sent != -1)) {
		printf("PID %d exists and is able to receive signals\n", pid);
	}

	return 0;
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


	if (!strcmp(P->tasks[0].cmd, "exit")) {
		builtin_execute(P->tasks[0]);
		return;
	} else if (!strcmp(P->tasks[0].cmd, "jobs")) {
		print_jobs();
		return;
	} else if (!strcmp(P->tasks[0].cmd, "fg")) {
		fg(P->tasks[0].argv[1]);
		return;
	} else if (!strcmp(P->tasks[0].cmd, "bg")) {
		bg(P->tasks[0].argv[1]);
		return;
#if DEBUG_PRINT
	} else if (!strcmp(P->tasks[0].cmd, "p")) {
		_print_job_array();
		return;
#endif
	}

	// create new job
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

	J->pgid = pid[0];

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
	
	add_new_job(J);
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

        execute_tasks (P, new_job);
    next:
        parse_destroy (&P);
        free(cmdline);
    }
	free(jobs);
}
