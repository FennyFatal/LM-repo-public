

#define	SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}

#define	SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
}

#define	TRACEBUF

#define	TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

struct sendto_args {
	int	s;
	void *	buf;
	size_t	len;
	int	flags;
	void *	to;
	int	tolen;
};

//struct ucred {
//	u_int	cr_ref;			/* reference count */
//	uid_t	cr_uid;			/* effective user id */
//	uid_t	cr_ruid;		/* real user id */
//	uid_t	cr_svuid;		/* saved user id */
//	int	cr_ngroups;		/* number of groups */
//	gid_t	cr_rgid;		/* real group id */
//	gid_t	cr_svgid;		/* saved group id */
//	struct uidinfo	*cr_uidinfo;	/* per euid resource consumption */
//	struct uidinfo	*cr_ruidinfo;	/* per ruid resource consumption */
//	struct prison	*cr_prison;	/* jail(2) */
//	struct loginclass	*cr_loginclass; /* login class */
//	u_int		cr_flags;	/* credential flags */
//	void 		*cr_pspare2[2];	/* general use 2 */
//	struct label	*cr_label;	/* MAC label */
//	struct auditinfo_addr	cr_audit;	/* Audit properties. */
//	gid_t	*cr_groups;		/* groups */
//	int	cr_agroups;		/* Available groups */
//};


