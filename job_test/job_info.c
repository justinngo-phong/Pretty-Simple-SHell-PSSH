/* This incredibly useful tool is provided to help you
 * analyze your shell's job creation and management.
 *
 * Don't be afraid to build other simple tools (like this one)
 * to help you debug your shell as you develop Project 2.
 *
 * Compile using:
 *   $ gcc -o job_info job_info.c
 *
 *********************************************************
 *
 * Example Use Cases:
 *
 *
 * 1. You can use this tool to check if your shell is
 *    putting jobs into process groups correctly:
 *
 * $ ./job_info | ./job_info | ./job_info | ./job_info
 * Terminal FG process group: 10648
 * Command    PID    PPID    PGID
 *     1    10648    10533  10648
 *     2    10649    10533  10648
 *     3    10650    10533  10648
 *     4    10651    10533  10648
 * ^C$
 *
 *********************************************************
 *
 * 2. You can check to see that the foreground process
 *    group is being set correctly:
 *
 * $ ps -A | grep pssh
 * 12085 pts/28   00:00:00 pssh
 *
 * $ ./job_info | ./job_info | ./job_info | ./job_info &
 * [0] 12128 12129 12130 12131
 * Terminal FG process group: 12085
 * Command    PID     PPID   PGID
 *     1    12128    12085  12128
 *     2    12129    12085  12128
 *     3    12130    12085  12128
 *     4    12131    12085  12128
 *
 * $ jobs
 * [0] + running   ./job_info | ./job_info | ./job_info | ./job_info &
 *
 * $ fg %0
 * Terminal FG process group: 12128
 * Process 12130 (3) received signal 18 [Continued]
 * Process 12131 (4) received signal 18 [Continued]
 * Process 12128 (1) received signal 18 [Continued]
 * Process 12129 (2) received signal 18 [Continued]
 *
 * ^ZProcess 12130 (3) received signal 20 [Stopped]
 * Process 12129 (2) received signal 20 [Stopped]
 * Process 12131 (4) received signal 20 [Stopped]
 * Terminal FG process group: 12128
 * Process 12128 (1) received signal 20 [Stopped]
 * [0] + suspended ./job_info | ./job_info | ./job_info | ./job_info &
 *
 * $ bg %0
 * [0] + continued ./job_info | ./job_info | ./job_info | ./job_info &
 * Terminal FG process group: 12085
 * Process 12128 (1) received signal 18 [Continued]
 * Process 12131 (4) received signal 18 [Continued]
 * Process 12130 (3) received signal 18 [Continued]
 * Process 12129 (2) received signal 18 [Continued]
 *
 * $ kill %0
 * [0] + done      ./job_info | ./job_info | ./job_info | ./job_info &
 * $
 */


#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

static int cmd_num;

static void handler (int sig)
{
    if (getpid() == getpgrp())
        fprintf (stderr, "Terminal FG process group: %i\n",
                tcgetpgrp (STDIN_FILENO));

    fprintf (stderr, "Process %i (%i) received signal %i [%s]\n",
            getpid(), cmd_num, sig, strsignal (sig));

    if (sig == SIGTSTP)
        raise (SIGSTOP);
}


int main (int argc, char** argv)
{
    struct sigaction sa;

    sigemptyset (&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = handler;

    sigaction (SIGTSTP, &sa, NULL);
    sigaction (SIGCONT, &sa, NULL);

    if (isatty (STDIN_FILENO)) {
        fprintf (stderr, "Terminal FG process group: %i\n",
                tcgetpgrp (STDIN_FILENO));

        fprintf (stderr, "Command    PID     PPID   PGID\n");
        cmd_num = 0;
    } else {
        read (STDIN_FILENO, &cmd_num, sizeof(cmd_num));
    }

    cmd_num++;

    fprintf (stderr, " %4i    %5i    %5i  %5i\n",
            cmd_num, getpid(), getppid(), getpgrp());

    if (!isatty (STDOUT_FILENO))
        write (STDOUT_FILENO, &cmd_num, sizeof(cmd_num));

    while (1)
        pause ();

}