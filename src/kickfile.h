#ifndef NMSGTOOL_KICKFILE_H
#define NMSGTOOL_KICKFILE_H

struct kickfile {
	char	*cmd;
	char	*curname;
	char	*basename;
	char	*tmpname;
};

char *
kickfile_time(void);

void
kickfile_destroy(struct kickfile **);

void
kickfile_exec(struct kickfile *);

void
kickfile_rotate(struct kickfile *);

#endif
