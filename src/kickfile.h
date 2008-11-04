#ifndef KICKFILE_H
#define KICKFILE_H

struct kickfile {
	char	*cmd;
	char	*curname;
	char	*basename;
	char	*tmpname;
};

extern char *kickfile_time(void);
extern void kickfile_destroy(struct kickfile **);
extern void kickfile_exec(struct kickfile *);
extern void kickfile_rotate(struct kickfile *);

#endif
