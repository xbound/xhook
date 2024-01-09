#include <limits.h>
#define XCURSED_INSTLEN 20
#define XHOOK_INITED {.hooks=NULL,.targets=NULL,.memfd=-1}
struct xhook_hook {
	void *addr;
	const void *callback;
	unsigned long sequence;
	long level;
};
struct xhook_target {
	void *addr;
	char orig_inst[XCURSED_INSTLEN];
	char sealed;
};
typedef struct xhook_struct {
	struct xhook_hook *restrict hooks;
	struct xhook_target *restrict targets;
	size_t size,tsize;
	long last_level;
	int memfd;
} xhook_t;
void xhook_init_r(xhook_t *restrict xhp);
int xhook_curse_r(xhook_t *restrict xhp,void *target,const void *callback,long level);
int xhook_uncurse_r(xhook_t *restrict xhp,void *target,const void *callback,long level);
int xhook_wipe_r(xhook_t *restrict xhp);
int xhook_seal_r(xhook_t *restrict xhp,void *target);
int xhook_unseal_r(xhook_t *restrict xhp,void *target);
long xhook_getlevel_r(xhook_t *restrict xhp);
int xhook_curse(void *target,const void *callback,long level);
int xhook_uncurse(void *target,const void *callback,long level);
int xhook_wipe(void);
int xhook_seal(void *target);
int xhook_unseal(void *target);
long xhook_getlevel(void);

