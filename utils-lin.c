/**
 * ANDRONESCU IOANA, 331CA
 * Operating Sytems 2013 - Assignment 1
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"
#include "parser.h"

#define READ		0
#define WRITE		1

#define NAME_LEN	50		


/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s) {
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL) {
			return NULL;
		}

		if (s->expand == true) {
			char *aux = substring;
			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL) {
				substring = calloc(1, sizeof(char));
				if (substring == NULL) {
					free(aux);
					return NULL;
				}
			}

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (substring != NULL)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false) {
			free(substring);
		}

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size) {
	char **argv;
	word_t *param;

	int argc = 0;
	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}

/**
 * Internal change-directory command.
 */
void shell_cd(word_t *params) {
	int ret, type;
	struct stat sb;
	
	/* execute cd */
	type = stat(params->string, &sb);
	if (type == 0)
		ret = chdir(params->string);
	if (ret < 0) {
		fprintf(stderr, "bash: cd: %s: No such file or directory\n", params->string);
		exit(EXIT_FAILURE);
	}
}

/**
 * Internal exit/quit command.
 */
void shell_exit() {
	/* execute exit/quit */
	exit(EXIT_SUCCESS);
}

/**
 * Environment vars to be set in the command.
 */
int set_environment_vars(word_t *part, const char *name) {
	int ret;
	
	/* if next part of the command is "=" */
	if (strcmp(part->string, "=") == 0) {
		part = part->next_part;
		/* set environment var */
		ret = setenv(name, part->string, WRITE);
		if (ret < 0) {
			perror("setting environment variable failed");
			exit(EXIT_FAILURE);
		}
	}
	part = part->next_part;
	
	return ret;
}

/**
 * File redirect.
 */
int do_redirect(int fd_std, int fd) {
	int fd_save, ret;
	
	/* save the std reserved file descriptor */
	fd_save = dup(fd_std);
	if (fd_save < 0) {
		perror("redirecting std failed");
		exit(EXIT_FAILURE);
	}
		
	/* close the std */
	ret = close(fd_std);
	if (ret < 0) {
		perror("closing std failed");
		exit(EXIT_FAILURE);
	}
	
	/* redirect from STD(IN/OUT/ERR) to file */
	ret = dup2(fd, fd_std);
	if (ret < 0) {
		perror("redirecting failed");
		exit(EXIT_FAILURE);
	}
		
	return fd_save;
}

/**
 * File close.
 */
int close_fd(int fd, int fd_saved, int fd_std) {
	int ret;
	
	/* close file */
	ret = close(fd);
	if (ret < 0) {
		perror("closing failed");
		exit(EXIT_FAILURE);
	}
		
	/* redirect again to std */
	ret = dup2(fd_saved, fd_std);
	if (ret < 0) {
		perror("redirecting failed");
		exit(EXIT_FAILURE);
	}
	
	/* close std */
	ret = close(fd_saved);
	if (ret < 0) {
		perror("closing failed");
		exit(EXIT_FAILURE);
	}
		
	return ret;
}

/**
 * External command.
 */
int execute_external_cmd(simple_command_t *s) {
	/* process id, wait process to terminate */
	pid_t pid, wait_ret;
	/* file descriptors */
	int fd_in, fd_out, fd_err, save_in, save_out, save_err;
	/* command size, status for execv, append */
	int size, status, append;
	/* args of the command */
	char **args = NULL;
	/* last filename (in case of multiple file redirect) */
	char *last_fname = NULL;
	/* name of the file */
	char *filename = NULL;
	
	/* create new process */
	pid = fork();
	
	switch (pid) {
		/* failed creating new process */
		case -1:
			exit(EXIT_FAILURE);
		case 0:
			/* get command with arguments */
			args = get_argv(s, &size);
			
			/* redirect from STDIN */
			if (s->in != NULL) {
				filename = get_word(s->in);
				
				/* open new file */
				fd_in = open(filename, O_RDONLY, 0600);
				if (fd_in < 0) {
					perror("opening file failed");
					exit(EXIT_FAILURE);
				}
				
				/* save STDIN file descriptor */
				save_in = do_redirect(STDIN_FILENO, fd_in);
				last_fname = malloc(NAME_LEN * sizeof(char));
				if (last_fname == NULL) {
					perror("malloc failed");
					exit(EXIT_FAILURE);
				}
				/* save current filename */
				sscanf(filename, "%s", last_fname);
			}

			/* redirect to STDERR */
			if (s->err != NULL) {
				filename = get_word(s->err);
                
                append = 1;
                /* multiple files redirects. */
                if (last_fname != NULL)
					append = strcmp(last_fname, filename);
				
				/* overwrite/write to file */
                if (s->io_flags == IO_REGULAR && append != 0) {
                	fd_err = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
					if (fd_err < 0) {
						perror("opening file failed");
						exit(EXIT_FAILURE);
					}
				}
				/* append to file */
				if (!s->io_flags == IO_REGULAR || append == 0) {
                	fd_err = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0600);
                	if (fd_err < 0) {
						perror("opening file failed");
						exit(EXIT_FAILURE);
					}
				}
				
				/* save STDERR file descriptor */
				save_err = do_redirect(STDERR_FILENO, fd_err);
				last_fname = malloc(NAME_LEN * sizeof(char));
				if (last_fname == NULL) {
					perror("malloc failed");
					exit(EXIT_FAILURE);
				}
				/* save current filename */
				sscanf(filename, "%s", last_fname);
			}
			
			/* redirect to STDOUT */
			if (s->out != NULL) {
				filename = get_word(s->out);
				
				append = 1;
				/* multiple files redirects. */
				if (last_fname != NULL)
					append = strcmp(last_fname, filename);
				
				/* overwrite/write to file */
				if (s->io_flags == IO_REGULAR && append != 0) {
					fd_out = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
					if (fd_out < 0) {
						perror("opening file failed");
						exit(EXIT_FAILURE);
					}
				}
				/* append to file */
				if (!s->io_flags == IO_REGULAR || append == 0) {
					fd_out = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0600);
					if (fd_out < 0) {
						perror("opening file failed");
						exit(EXIT_FAILURE);
					}
				}
				
				/* save STDOUT file descriptor */
				save_out = do_redirect(STDOUT_FILENO, fd_out);
				last_fname = malloc(NAME_LEN * sizeof(char));
				if (last_fname == NULL) {
					perror("malloc failed");
					exit(EXIT_FAILURE);
				}
				/* save current filename */
				sscanf(filename, "%s", last_fname);
			}
			
			/* execute command */
			if (execvp(args[0], args) < 0) {
				fprintf(stderr, "Execution failed for '%s'\n", args[0]);
				exit(EXIT_FAILURE);
			}

			/* close files */
			if (s->in)	
				close_fd(fd_in, save_in, STDIN_FILENO);
			if (s->out)
				close_fd(fd_out, save_out, STDOUT_FILENO);
			if (s->err)
				close_fd(fd_err, save_err, STDERR_FILENO);
			
			break;	
		default:
			/* wait for the process to terminate */
			wait_ret = waitpid(pid, &status, 0);
			if (wait_ret < 0) {
				perror("waitpid failed");
				exit(EXIT_FAILURE);
			}
			break;
	}
	
	free(filename);
	free(last_fname);
	
	return status;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father) {
	if (s == NULL)
		exit(EXIT_FAILURE);
	
	/* exit/quit commands */
	if (strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0) {
		if (s->params == NULL)
			shell_exit();
		exit(EXIT_FAILURE);
	}
	
	/* cd command */
	if (strcmp(s->verb->string, "cd") == 0) {
		if (s->params == NULL)
			exit(EXIT_FAILURE);
		shell_cd(s->params);
	}
	
	/* set environment vars */
	word_t *part = s->verb->next_part;
	if (part)
		return set_environment_vars(part, s->verb->string);
	
	/* external commands */
	return execute_external_cmd(s);
}

/**
 * Process two commands in parallel by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father) {
	/* process id, wait process to terminate */
	pid_t pid, wait_ret;
	/* status for execv */
	int status;
	
	/* create new process */
	pid = fork();

	switch (pid) {
		case -1:
			/* creating new process failed */
			exit(EXIT_FAILURE);
		case 0:
			/* child process */
			status = parse_command(cmd1, level, father);
			break;
		default:
			/* parent process */ 
			status = parse_command(cmd2, level, father);
			/* wait for the process to terminate */
			wait_ret = waitpid(pid, &status, 0);
			if (wait_ret < 0) {
				perror("waitpid failed");
				exit(EXIT_FAILURE);
			}
			break;
	}

	return status;
}

/**
 * Pipe redirect.
 */
void get_redirect(command_t *c, char *filename, int fd_std) {
	while (c->scmd == NULL)
		c = c->cmd2;
		
	simple_command_t *s = c->scmd;
	
	/* file descriptor for the file */
	int fd;
	/* return value for checks */
	int ret;
	/* new word_t for redirection */
	word_t *newout, *newin;
	
	/* set new out for redirection*/
    if (fd_std == STDOUT_FILENO) {     
		fd = open(filename, O_RDWR | O_CREAT, 0644);
		if (fd < 0) {
			perror("opening file failed");
			exit(EXIT_FAILURE);
		}
		
		ret = close(fd);
		if (ret < 0) {
			perror("closing file failed");
			exit(EXIT_FAILURE);
		}
		
		/* set "out" for simple command when executed */
		newout = (word_t *)malloc(sizeof(word_t));
		newout->string = filename;
		newout->expand = false;
		newout->next_part = NULL;
		newout->next_word = NULL;
		s->out = newout;
	}
	
	/* set new in for redirection */
    if (fd_std == STDIN_FILENO) {
		fd = open(filename, O_RDWR | O_CREAT, 0644);
		if (fd < 0) {
			perror("opening file failed");
			exit(EXIT_FAILURE);
		}
		
		ret = close(fd);
		if (ret < 0) {
			perror("closing file failed");
			exit(EXIT_FAILURE);
		}
		
		/* set "in" for simple command when executed */
		newin = (word_t *)malloc(sizeof(word_t));
		newin->string = filename;
		newin->expand = false;
		newin->next_part = NULL;
		newin->next_word = NULL;
		s->in = newin;
    }
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father) {
	/* redirect the output of cmd1 to the input of cmd2 */
	int status;
	
	char *filename = malloc(NAME_LEN * sizeof(char));
	if (filename == NULL) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}
    sprintf(filename, "tmp%d.txt", rand());

	/* redirect from stdout to temporary file */
	get_redirect(cmd1, filename, STDOUT_FILENO);
	status = parse_command(cmd1, level, father);

	/* redirect from from temporary file to stdin */
	get_redirect(cmd2, filename, STDIN_FILENO);
	status = parse_command(cmd2, level, father);
	
	/* remove tmp files */
	remove(filename);
	
	free(filename);

	return status;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father) {
	
	/* sanity checks */
	if(c == NULL || c->up != father)
		return EXIT_FAILURE;
	
	/* status return for new processes */	
	int status;

	if (c->op == OP_NONE) {
		/* execute a simple command */
		simple_command_t *simple_cmd = c->scmd;
		return parse_simple(simple_cmd, level, father);
	}

	switch (c->op) {
		case OP_SEQUENTIAL:
			/* execute the commands one after the other */
			level++;
			status = parse_command(c->cmd1, level, c);
			status = parse_command(c->cmd2, level, c);
			break;

		case OP_PARALLEL:
			/* execute the commands simultaneously */
			level++;
			status = do_in_parallel(c->cmd1, c->cmd2, level, c);			
			break;

		case OP_CONDITIONAL_NZERO:
			/* execute the second command only if the first one
			 * returns non zero */
		    level++;
		   	status = parse_command(c->cmd1, level, c); 
			if(status != 0)
				status = parse_command(c->cmd2, level, c);
			break;

		case OP_CONDITIONAL_ZERO:
			/* execute the second command only if the first one
			 * returns zero */
		    level++;
		   	status = parse_command(c->cmd1, level, c); 
			if(status == 0)
				status = parse_command(c->cmd2, level, c);
			break;

		case OP_PIPE:
			/* redirect the output of the first command to the
			 * input of the second */
			 level++;
			 status = do_on_pipe(c->cmd1, c->cmd2, level, c);
			 break;

		default:
			assert(false);
	}

	return status;
}

/**
 * Readline from mini-shell.
 */
char *read_line() {
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL) {
			break;
		}

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		ret = instr;
		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL) {
			free(ret);
			return instr;
		}
		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}
