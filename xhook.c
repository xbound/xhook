#define _GNU_SOURCE
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "xhook.h"

static void xhook_mkinst(const void *callback,void *buf){
#ifdef __aarch64__
	union {
		uint32_t bin;
		struct {
			uint32_t :5;
			uint32_t imm:16;
			uint32_t lsl:2;
			uint32_t :9;
		} bf;
	} v;
	const uint16_t *t=(const uint16_t *)&callback;
	uint32_t *out=buf;
	int i;
	v.bin=0xf2800008;
	for(i=0;i<4;++i){
		v.bf.imm=t[i];
		v.bf.lsl=i;
		out[i]=v.bin;
	}
	out[4]=0xd61f0100;
#else
#error "unknown arch"
#endif
}
static __attribute__((__used__)) void xhook_asmfunctions(void){
	asm volatile (
"ret\n"
//".global xhook_syscall\n"
//".global xhook_memcpy\n"
"xhook_syscall:\n\t\
	mov x8,x6\n\t\
	svc #0\n\t\
	ret\n\t\
xhook_memcpy:\n\t\
	lsr x3,x2,#3\n\t\
	and x2,x2,#7\n\
.L0:\n\t\
	cmp x3,#0\n\t\
	beq .L1\n\t\
	ldr x4,[x1]\n\t\
	str x4,[x0]\n\t\
	sub x3,x3,1\n\t\
	add x0,x0,8\n\t\
	add x1,x1,8\n\t\
	b .L0\n\
.L1:\n\t\
	cmp x2,#0\n\t\
	beq .L2\n\t\
	ldrb w4,[x1]\n\t\
	strb w4,[x0]\n\t\
	sub x2,x2,1\n\t\
	add x0,x0,1\n\t\
	add x1,x1,1\n\t\
	b .L1\n\
.L2:\n\t\
	ret"
		     );
}
long xhook_syscall(long arg0,long arg1,long arg2,long arg3,long arg4,long arg5,long num);
void xhook_memcpy(void *restrict dest,const void *restrict src,size_t n);
#define xhook_sys_pwrite(fd,buf,count,offset) ((ssize_t)xhook_syscall((long)(fd),(long)(buf),(long)(count),(long)(offset),0,0,SYS_pwrite64))
#define xhook_sys_pread(fd,buf,count,offset) ((ssize_t)xhook_syscall((long)(fd),(long)(buf),(long)(count),(long)(offset),0,0,SYS_pread64))
#define xhook_sys_mmap(addr,length,prot,flags,fd,offset) ((void *)xhook_syscall((long)(addr),(long)(length),(long)(prot),(unsigned long)(flags),(long)(fd),(long)(offset),SYS_mmap))
#define xhook_sys_munmap(addr,length) ((int)xhook_syscall((long)(addr),(long)(length),0,0,0,0,SYS_munmap))
#define xhook_sys_close(fd) ((int)xhook_syscall((long)(fd),0,0,0,0,0,SYS_close))
#define xhook_sys_open(path,flags) ((int)xhook_syscall(AT_FDCWD,(long)(path),(unsigned long)flags,0,0,0,SYS_openat))
static void xhook_mwrite(int fd, const void *buf, size_t count, off_t offset){
	xhook_sys_pwrite(fd,buf,count,offset);
	xhook_syscall(0,0,0,0,0,0,SYS_sched_yield);
	//sched_yield();
}
static long xhook_storeinst(xhook_t *restrict xhp,void *target,const char *inst){
	long r;
	void *p;
	if(!xhp->targets){
		xhp->targets=xhook_sys_mmap(NULL,xhp->tsize=PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
	}
	for(r=0;xhp->targets[r].addr;++r){
		if(xhp->targets[r].addr==target){
			return r;
		}
	}
	if((r+2)*sizeof(struct xhook_target)>xhp->tsize){
		p=xhook_sys_mmap(NULL,xhp->tsize+PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
		xhook_memcpy(p,xhp->targets,xhp->tsize);
		xhook_sys_munmap(xhp->targets,xhp->tsize);
		xhp->targets=p;
		xhp->tsize+=PAGE_SIZE;
	}
	xhp->targets[r].addr=target;
	xhp->targets[r].sealed=0;
	xhook_memcpy(xhp->targets[r].orig_inst,inst,XCURSED_INSTLEN);
	return r;
}
static int xhook_stealinst(xhook_t *restrict xhp,void *target,char *inst){
	long r,r1;
	int ret=-1;
	if(xhp->targets)
	for(r=0;xhp->targets[r].addr;++r){
		if(xhp->targets[r].addr!=target)continue;
		xhook_memcpy(inst,xhp->targets[r].orig_inst,XCURSED_INSTLEN);
		ret=0;
		r1=r;
	}
	if(ret)return -1;
	if(!xhp->targets[r1].sealed){
	if(--r>r1)xhook_memcpy(xhp->targets+r1,xhp->targets+r,sizeof(struct xhook_target));
	xhp->targets[r].addr=NULL;
	}else return 1;
	return 0;
}
static int xhook_issealed(xhook_t *restrict xhp,void *target){
	long r;
	if(xhp->targets)
	for(r=0;xhp->targets[r].addr;++r){
		if(xhp->targets[r].addr!=target)continue;
		if(xhp->targets[r].sealed)return 1;
	}
	return 0;
}
static xhook_t xhook_localxh=XHOOK_INITED;

void xhook_init_r(xhook_t *restrict xhp){
	xhp->hooks=NULL;
	xhp->targets=NULL;
	xhp->memfd=-1;
}
long xhook_getlevel_r(xhook_t *restrict xhp){
	return xhp->last_level;
}
int xhook_curse_r(xhook_t *restrict xhp,void *target,const void *callback,long level){
	char instbuf[XCURSED_INSTLEN];
	long r,rm;
	unsigned long seq;
	int fd,insert=0;
	const void *to=NULL;
	void *p;
	if(level==LONG_MIN||target==NULL)return -4;
	if(!xhp->hooks){
		xhp->hooks=xhook_sys_mmap(NULL,xhp->size=PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
	}
	if(xhp->memfd<0){
	fd=xhook_sys_open("/proc/self/mem",O_RDWR);
		if(fd<0)return -2;
		else xhp->memfd=fd;
	}else fd=xhp->memfd;

	for(r=0,seq=0,rm=-1l;xhp->hooks[r].addr;++r){
		if(xhp->hooks[r].addr==target){
			if(xhp->hooks[r].sequence>=seq&&xhp->hooks[r].level<=level){
				seq=xhp->hooks[r].sequence+1;
			}
			if(rm==-1l||xhp->hooks[r].sequence>xhp->hooks[rm].sequence){
				rm=r;
			}

		}
	}
	if((r+2)*sizeof(struct xhook_hook)>xhp->size){
		p=xhook_sys_mmap(NULL,xhp->size+PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
		xhook_memcpy(p,xhp->hooks,xhp->size);
		xhook_sys_munmap(xhp->hooks,xhp->size);
		xhp->hooks=p;
		xhp->size+=PAGE_SIZE;
	}
	for(r=0;xhp->hooks[r].addr;++r){
		if(xhp->hooks[r].addr==target){
			if(xhp->hooks[r].sequence>=seq){
				++xhp->hooks[r].sequence;
				insert=1;
			}
			if(seq&&xhp->hooks[r].sequence==xhp->hooks[rm].sequence){
				to=xhp->hooks[r].callback;
			}
		}
	}
	xhp->hooks[r].addr=target;
	xhp->hooks[r].callback=callback;
	xhp->hooks[r].level=level;
	xhp->hooks[r].sequence=seq;
	if(!insert){
		if(!seq&&!xhook_issealed(xhp,target)){
			xhook_sys_pread(fd,instbuf,XCURSED_INSTLEN,(off_t)target);
			xhook_storeinst(xhp,target,instbuf);
		}
		if(!to||to!=callback){
		xhook_mkinst(callback,instbuf);
		if(!xhook_issealed(xhp,target))xhook_mwrite(fd,instbuf,XCURSED_INSTLEN,(off_t)target);
		}
	}
	return 0;
}
int xhook_uncurse_r(xhook_t *restrict xhp,void *target,const void *callback,long level){
	char instbuf[XCURSED_INSTLEN];
	long r,r1,i,rm;
	unsigned long seq,seqmax;
	const void *to;
	if(!target)return -4;
	if(!xhp->hooks){
		return -1;
	}
	for(r=0,seqmax=0,seq=0,r1=-1l;xhp->hooks[r].addr;++r){
		if(xhp->hooks[r].addr==target){
			if(xhp->hooks[r].sequence>=seqmax){
				seqmax=xhp->hooks[r].sequence;
				rm=r;
			}
			if(xhp->hooks[r].sequence>=seq){
				if((callback&&xhp->hooks[r].callback!=callback)||(level!=LONG_MIN&&xhp->hooks[r].level!=level))continue;
				seq=xhp->hooks[r].sequence;
				r1=r;
			}
		}
	}
	if(r1==-1l){
		return -1;
	}
	for(i=0;xhp->hooks[i].addr;++i){
		if(xhp->hooks[i].addr==target){
			if(xhp->hooks[i].sequence>seq){
				--xhp->hooks[i].sequence;
			}
			if(seq&&xhp->hooks[i].sequence==seqmax-1){
				to=xhp->hooks[i].callback;
			}
		}
	}
	if(r1==rm){
		if(seqmax){
			if(to!=xhp->hooks[rm].callback){
			xhook_mkinst(to,instbuf);
			if(!xhook_issealed(xhp,target))xhook_mwrite(xhp->memfd,instbuf,XCURSED_INSTLEN,(off_t)target);
			}
		}else {
			if(xhook_stealinst(xhp,target,instbuf)!=1)xhook_mwrite(xhp->memfd,instbuf,XCURSED_INSTLEN,(off_t)target);
		}
	}
	xhp->last_level=xhp->hooks[r1].level;
	if(--r>r1){
		xhook_memcpy(xhp->hooks+r1,xhp->hooks+r,sizeof(struct xhook_hook));
	}
	xhp->hooks[r].addr=NULL;

	return 0;
}
int xhook_wipe_r(xhook_t *restrict xhp){
	long r;
	if(xhp->hooks)xhook_sys_munmap(xhp->hooks,xhp->size);
	if(!xhp->targets)return -3;
	for(r=0;xhp->targets[r].addr;++r){
		if(xhp->targets[r].sealed)continue;
		xhook_mwrite(xhp->memfd,xhp->targets[r].orig_inst,XCURSED_INSTLEN,(off_t)xhp->targets[r].addr);
	}
	xhook_sys_munmap(xhp->targets,xhp->tsize);
	if(xhp->memfd>=0)xhook_sys_close(xhp->memfd);
	xhook_init_r(xhp);
	return 0;
}

int xhook_seal_r(xhook_t *restrict xhp,void *target){
	long r;
	int fd;
	char instbuf[XCURSED_INSTLEN];
	if(!target)return -4;
	if(xhp->memfd<0){
	fd=xhook_sys_open("/proc/self/mem",O_RDWR);
		if(fd<0)return -2;
		else xhp->memfd=fd;
	}
	if(!xhp->targets)goto nulltargets;
	for(r=0;xhp->targets[r].addr;++r){
		if(xhp->targets[r].addr!=target)continue;
		if(xhp->targets[r].sealed)return -5;
		break;
	}
	if(!xhp->targets[r].addr){
nulltargets:
		xhook_sys_pread(xhp->memfd,instbuf,XCURSED_INSTLEN,(off_t)target);
		r=xhook_storeinst(xhp,target,instbuf);
	}else
	xhook_mwrite(xhp->memfd,xhp->targets[r].orig_inst,XCURSED_INSTLEN,(off_t)target);
	xhp->targets[r].sealed=1;
	return 0;
}
int xhook_unseal_r(xhook_t *restrict xhp,void *target){
	long r=-1l,r1,rm=-1l,r2;
	unsigned long seqmax;
	char instbuf[XCURSED_INSTLEN];
	if(!target)return -4;
	if(xhp->targets)
	for(r2=0;xhp->targets[r2].addr;++r2){
		if(xhp->targets[r2].addr!=target)continue;
		if(!xhp->targets[r2].sealed)break;
		r=r2;
	}
	if(r==-1l)return -5;
	if(xhp->hooks)
	for(r1=0,seqmax=0;xhp->hooks[r1].addr;++r1){
		if(xhp->hooks[r1].addr==target){
			if(xhp->hooks[r1].sequence>=seqmax){
				seqmax=xhp->hooks[r1].sequence;
				rm=r1;
			}
		}
	}
	if(rm==-1l){
		if(--r2>r)xhook_memcpy(xhp->targets+r,xhp->targets+r2,sizeof(struct xhook_target));
		xhp->targets[r2].addr=NULL;
	}else {
		xhook_mkinst(xhp->hooks[rm].callback,instbuf);
		xhook_mwrite(xhp->memfd,instbuf,XCURSED_INSTLEN,(off_t)target);
		xhp->targets[r].sealed=0;
	}
	return 0;
}
int xhook_curse(void *target,const void *callback,long level){
	return xhook_curse_r(&xhook_localxh,target,callback,level);
}
int xhook_uncurse(void *target,const void *callback,long level){
	return xhook_uncurse_r(&xhook_localxh,target,callback,level);
}
int xhook_seal(void *target){
	return xhook_seal_r(&xhook_localxh,target);
}
int xhook_unseal(void *target){
	return xhook_unseal_r(&xhook_localxh,target);
}
int xhook_wipe(void){
	return xhook_wipe_r(&xhook_localxh);
}
long xhook_getlevel(void){
	return xhook_getlevel_r(&xhook_localxh);
}

