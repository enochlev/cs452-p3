#include "lab.h"
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 

#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>

#include <sys/wait.h>

pid_t shell_pgid;
struct job *jobs = NULL;

// create a job list to keep track of background jobs
struct job
{
    pid_t pid;
    char *cmd;
    struct job *next;
    int job_id;
};



char *get_prompt(const char *env)
{   
    char *env_value = getenv(env);
    if (env_value == NULL)
    {
        env_value = "shell>";
    }
    char *line_copy = strdup(env_value);
    return line_copy;
}

void sh_init(struct shell *sh)
{
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    shell_pgid = getpid ();

    // Initialize empty list of jobs and job counter
    

    // Put the shell in its own process group
    int shell_terminal = STDIN_FILENO;
    tcsetpgrp (shell_terminal, shell_pgid);

    char *line;

    using_history();
    while ((line=readline(sh->prompt))){

        line = trim_white(line);
        if (strlen(line) != 0)
        {
            add_history(line);
        }

        // Check for background execution
        bool do_background = false;
        if ((strlen(line) > 0) && (line[strlen(line) - 1] == '&'))
        {
            do_background = true;
            line[strlen(line) - 1] = '\0';
            line = trim_white(line);
        }

        char **argv = cmd_parse(line);

        // Get length of argv (not used here but kept for completeness)
        int argc = 0;
        while(argv[argc] != NULL && argc < ARG_MAX)
        {
            argc++;
        }

        if (do_builtin(sh, argv) == false)
        {
            // Fork and exec
            pid_t pid = fork();
            if (pid == 0)
            {
                pid_t child = getpid();
                setpgid(child, child);
                tcsetpgrp(sh->shell_terminal, child);
                signal (SIGINT, SIG_DFL);
                signal (SIGQUIT, SIG_DFL);
                signal (SIGTSTP, SIG_DFL);
                signal (SIGTTIN, SIG_DFL);
                signal (SIGTTOU, SIG_DFL);
                execvp(argv[0], argv);
                fprintf(stderr, "exec failed\n");
                exit(1);
            }
            else
            {
                if (do_background == false)
                {
                    waitpid(pid, NULL, 0);
                    //https://www.gnu.org/software/libc/manual/html_node/Launching-Jobs.html
                    // Return terminal control to the shell
                    tcsetpgrp(sh->shell_terminal, shell_pgid);
                }
                else
                {
                    int job_counter = 0;
                    if (jobs != NULL)
                    {
                        job_counter = jobs->job_id + 1;
                    }

                    // Add job to job list
                    struct job *new_job = malloc(sizeof(struct job));
                    new_job->pid = pid;
                    new_job->cmd = strdup(line);
                    new_job->next = jobs;
                    new_job->job_id = job_counter++;
                    jobs = new_job;
                    // Print job information
                    printf("[%d] %d %s\n", new_job->job_id, pid, line);
                }
            }
        }


        //https://stackoverflow.com/questions/47441871/why-should-we-check-wifexited-after-wait-in-order-to-kill-child-processes-in-lin
        //https://www.gnu.org/software/libc/manual/html_node/Process-Completion.html
        // Check all jobs and clear any that have finished
        struct job **job_ptr = &jobs;
        while (*job_ptr != NULL)
        {
            int status;
            pid_t result = waitpid((*job_ptr)->pid, &status, WNOHANG);
            if (result == -1)
            {
                perror("waitpid");
                // Remove the job from the list
                struct job *finished_job = *job_ptr;
                *job_ptr = (*job_ptr)->next;
                free(finished_job->cmd);
                free(finished_job);
            }
            else if (result == 0)
            {
                job_ptr = &(*job_ptr)->next;
            }
            else if (result == (*job_ptr)->pid)
            {
                // Process has terminated
                if (WIFEXITED(status) || WIFSIGNALED(status))
                {
                    printf("[%d] Done %s\n", (*job_ptr)->job_id, (*job_ptr)->cmd);
                    // Remove the job from the list
                    struct job *finished_job = *job_ptr;
                    *job_ptr = (*job_ptr)->next;
                    free(finished_job->cmd);
                    free(finished_job);
                }
                else
                {
                    job_ptr = &(*job_ptr)->next;
                }
            }
            else
            {
                // Should not happen
                job_ptr = &(*job_ptr)->next;
            }
        }

        cmd_free(argv);
    }
    free(line);
}


void sh_destroy(struct shell *sh) {
    if (sh->prompt != NULL) {
        free(sh->prompt);
        sh->prompt = NULL;
    }
}

char **cmd_parse(char const *line)
{
    char *line_copy = strdup(line);
    char *token = strtok(line_copy, " ");

    char **argv = malloc(ARG_MAX * sizeof(char*));

    int argc = 0;
    while (token != NULL && argc < ARG_MAX)
    {
        // Allocate memory for each token
        argv[argc] = strdup(token);
        argc++;

        token = strtok(NULL, " ");
    }

    // Null-terminate the argv array
    if (argc < ARG_MAX)
    {
        argv[argc] = NULL;
    }

    free(line_copy); // Free the original line_copy
    return argv;
}

void parse_args(int argc, char **argv)
{
    int c;
    while ((c = getopt(argc, argv, "v")) != -1)
    {
        switch (c)
        {
            case 'v':
                printf("v%d.%d\n", lab_VERSION_MAJOR, lab_VERSION_MINOR);
                exit(0);
            case '?':
                printf("Usage: %s [-v]\n", argv[0]);
                exit(0);
            default:
                fprintf(stderr, "Usage: %s [-v]\n", argv[0]);
                exit(1);
        }
    }
}


  char *trim_white(char *line)
    {
        while (isspace(*line))
        {
            line++;
        }

        char *end = line + strlen(line) - 1;
        while (end > line && isspace(*end))
        {
            end--;
        }

        *(end + 1) = '\0';//add null at the end

        return line;
    }

    void cmd_free(char **argv)
    {
        for (int i = 0; argv[i] != NULL; i++)
        {
            free(argv[i]); 
        }
        free(argv);
    }

bool do_builtin(struct shell *sh, char **argv)
    {   
        if (argv[0] == NULL)
        {
            return true;
        }

        if (strcmp(argv[0], "cd") == 0)
        {
            change_dir(argv);
            return true;
        }
        else if (strcmp(argv[0], "exit") == 0)
        {
            sh_destroy(sh);
            free(argv);
            exit(0);
            return true;
        }
        else if (strcmp(argv[0], "history") == 0)
        {
            //https://tiswww.cwru.edu/php/chet/readline/history.html
            register HIST_ENTRY **the_list;
            register int i;

            the_list = history_list ();
            if (the_list)
                for (i = 0; the_list[i]; i++)
                printf ("%d: %s\n", i + history_base, the_list[i]->line);
            
            return true;
        }
        else if (strcmp(argv[0], "pwd") == 0)
        {
            char *cwd = getcwd(NULL, 0);
            printf("%s\n", cwd);
            free(cwd);
            return true;
        }

        else if (strcmp(argv[0], "jobs") == 0)
        {
            // Print all jobs
            //https://stackoverflow.com/questions/47441871/why-should-we-check-wifexited-after-wait-in-order-to-kill-child-processes-in-lin
            //https://www.gnu.org/software/libc/manual/html_node/Process-Completion.html
            // Check all jobs and clear any that have finished
            struct job **job_ptr = &jobs;
            while (*job_ptr != NULL)
            {
                int status;
                pid_t result = waitpid((*job_ptr)->pid, &status, WNOHANG);
                if (result == -1)
                {
                    perror("waitpid");
                    // Remove the job from the list
                    struct job *finished_job = *job_ptr;
                    *job_ptr = (*job_ptr)->next;
                    free(finished_job->cmd);
                    free(finished_job);
                }
                else if (result == 0)
                {   
                    printf("[%d] %d %s\n", (*job_ptr)->job_id, (*job_ptr)->pid, (*job_ptr)->cmd);
                    job_ptr = &(*job_ptr)->next;
                }
                else if (result == (*job_ptr)->pid)
                {
                    // Process has terminated
                    if (WIFEXITED(status) || WIFSIGNALED(status))
                    {
                        printf("[%d] Done %s\n", (*job_ptr)->job_id, (*job_ptr)->cmd);
                        // Remove the job from the list
                        struct job *finished_job = *job_ptr;
                        *job_ptr = (*job_ptr)->next;
                        free(finished_job->cmd);
                        free(finished_job);
                    }
                    else
                    {
                        //print processor normally
                        
                        job_ptr = &(*job_ptr)->next;
                    }
                }
                else
                {
                    // Should not happen
                    job_ptr = &(*job_ptr)->next;
                }
            }
            return true;
        }

        return false;
    }

int change_dir(char **dir)
{
    int res;

    if (dir[1] == NULL)
    { //https://man7.org/linux/man-pages/man3/getpwuid.3p.html
        char *home = getenv("HOME");
        if (home == NULL)
        {
            struct passwd *pw = getpwuid(getuid());
            if (pw == NULL)
            {
                return -1;
            }
            home = pw->pw_dir;
            if (home == NULL)
            {
                return -1;
            }
        }
        res = chdir(home);
        if (res != 0)
        {
            perror("cd");
        }
        return res;
    }
    else
    {
        res = chdir(dir[1]);
        if (res != 0)
        {
            perror("cd");
        }
        return res;
    }
}