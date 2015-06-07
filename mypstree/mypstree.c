/**
 * Print a hierarchical structure of all system processes
 * This is my fake exercise of Werner Almesberger's psmisc.
 *
 * ver 0.1.0
 *
 */
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

#define DEBUG 1

#ifdef DEBUG
#define DBG(x) do { printf("[DBG] %20s:%d - ", __func__, __LINE__); printf x; putchar('\n'); fflush(stdout); } while(0)
#define DUMP_PROC_LIST(x) do { \
    PROC* p = 0; \
    for (p = (x); p != NULL; p=p->next) { \
        if (p->next) \
            printf("%s, ", p->comm); \
        else \
            printf("%s\n", p->comm); \
    } \
} while (0)

#define DUMP_CHLD_LIST(x) do { \
    CHILD* p = 0; \
    for (p = (x); p != NULL; p=p->next) { \
        if (p->next) \
            printf("%s, ", p->proc->comm); \
        else \
            printf("%s\n", p->proc->comm); \
    } \
} while (0)

#else
#define DBG(x)
#define DUMP_PROC_LIST(x)
#define DUMP_CHLD_LIST(x)
#endif


#define BUF_SIZE 256
#define PROC_BASE "/proc"

/**
 * 进程以链表的形式串起来
 */
typedef struct proc {
    char comm[BUF_SIZE];
    pid_t pid;
    pid_t ppid;
    pid_t pgrp;
    int nchild;             /* 孩子的数量 */
    struct proc *parent;
    struct child *children; /* 该进程fork()的所有子进程 */
    struct proc *next;
} PROC;

static PROC *proc_list = NULL;  /* 包含所有进程的链表 */
static PROC *root_proc = NULL;  /* 记录根进程 */


/**
 * 表示一个进程中fork出的子进程，链表形式串起来
 */
typedef struct child {
    PROC *proc;
    struct child *next;
} CHILD;


/**
 * 匿名的结构体，只实例化一次
 */
struct {
    const char *empty_2;         /*    */
    const char *branch_2;        /* |- */
    const char *vert_2;          /* |  */
    const char *last_2;          /* `- */
    const char *single_3;        /* --- */
    const char *first_3;         /* -+- */
} sym_ascii = {
    " ", "|-", "| ", "`-", "---", "-+-"
};

void print_node(PROC *node, int indent)
{
    int i = 0;
    for (; i < indent; i++)
        printf("\t");

    if (indent > 0)
        printf("-%s\n", node->comm);
    else
        printf("%s\n", node->comm);


    CHILD *child = node->children;
    while (child) {
        print_node(child->proc, indent + 1);
        child = child->next;
    }
}

void dump_tree(PROC *root)
{
    print_node(root, 0);
}

void unix_error(char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

void free_children(PROC *p)
{
    if (!p)
        return;

    CHILD *c = p->children;
    CHILD *next = NULL;
    while (c) {
        next = c->next;
        free(c);
        c = next;
    }
}

void free_procs()
{
    PROC *p = proc_list;
    PROC *q = NULL;

    while (p) {
        q = p->next;
        free_children(p);
        free(p);
        p = q;
    }
}

PROC *find_proc_pid(pid_t pid)
{
    PROC *p;
    for (p = proc_list; p; p = p->next) {
        if (pid == p->pid)
            return p;
    }

    return NULL;
}

PROC *new_proc(char *comm, pid_t pid, pid_t ppid, pid_t pgrp)
{
    PROC *proc = malloc(sizeof(PROC));
    if (!proc)
        unix_error("alloc PROC error");

    strncpy(proc->comm, comm, strlen(comm) + 1);
    proc->pid = pid;
    proc->ppid = ppid;
    proc->pgrp = pgrp;
    proc->nchild = 0;
    proc->children = NULL;
    /* 添加到链表中 */
    proc->next = proc_list;
    proc_list = proc;

    return proc;
}

void rename_proc(PROC *proc, char *comm, pid_t ppid, pid_t pgrp)
{
    strncpy(proc->comm, comm, strlen(comm) + 1);
    proc->ppid = ppid;
    proc->pgrp = pgrp;
}

/**
 * 往parent->children中添加一个元素
 */
void add_child(PROC *parent, PROC *childproc)
{
    childproc->parent = parent;

    CHILD *child = malloc(sizeof(CHILD));
    if (!child)
        unix_error("alloc child error");

    DBG(("parent:%s, child:%s", parent->comm, childproc->comm));

    child->proc = childproc;
    /* 添加到parent的children链表中 */
    child->next = parent->children;
    parent->children = child;
    parent->nchild += 1;
}

PROC *add_proc(char *comm, pid_t pid, pid_t ppid, pid_t pgrp)
{

    PROC *proc = find_proc_pid(pid);
    if (!proc) {
        proc = new_proc(comm, pid, ppid, pgrp);
    } else {
        rename_proc(proc, comm, ppid, pgrp);
    }

    PROC *parent = find_proc_pid(ppid);
    if (!parent) {
        parent = new_proc("?", ppid, 0, 0);
    }

    if (ppid != 0) {
        add_child(parent, proc);
    }

    return proc;
}

/**
 * 读取/proc，获取系统中所有进程的信息
 */
void read_procs()
{
    DIR *procdirp;
    struct dirent *dentp;
    char path[BUF_SIZE] = {0};
    sprintf(path, "%s", PROC_BASE);

    if (!(procdirp = opendir(path))) {
        unix_error("opendir()");
    }

    char readbuf[4 * BUF_SIZE] = {0};
    /* 遍历/proc文件系统 */
    char *beginp = 0;
    char *endp = 0;
    pid_t pid;
    while ((dentp = readdir(procdirp))) {
        /* 如果文件名不是纯数字，表示不是一个进程，跳过 */
        if ((pid = strtol(dentp->d_name, &endp, 10)) <= 0 || *endp != '\0')
            continue;

        /* 从/proc/[pid]/stat文件中读取进程相关信息 */
        sprintf(path, "/proc/%d/stat", pid);
        FILE *fstatp = fopen(path, "r");
        if (!fstatp)
            unix_error("fopen()");


        fread(readbuf, sizeof(char), sizeof(readbuf), fstatp);
        if (ferror(fstatp))
            unix_error("fread()");

        char *readbufp = readbuf;
        char *comm;
        pid_t ppid = 0, pgrp = 0;

        /* 获取进程名 */
        if ((beginp = strchr(readbuf, '(')) &&
                (endp = strrchr(readbuf, ')'))) {
            *endp = '\0';
            comm = beginp + 1;

            /* 跳过进程状态字符 */
            while (!isdigit(*endp))
                endp++;

            readbufp = endp;
            /* 获取ppid和pgrp */
            ppid = strtol(readbufp, &endp, 10);
            readbufp = endp;
            pgrp = strtol(readbufp, &endp, 10);

            /* DBG(("proc[comm:%s, pid:%d, ppid:%d, pgrp:%d]", comm, pid, ppid, pgrp)); */
            PROC *proc = add_proc(comm, pid, ppid, pgrp);
            if (1 == pid)
                root_proc = proc;

        }

    }

    if (errno != 0)
        unix_error("readdir()");
}


int main(int argc, char *argv[])
{

    read_procs();
    PROC *proc = find_proc_pid(2158);
    if (!proc)
        exit(1);

    DUMP_CHLD_LIST(proc->children);

    free_procs();

    /* read_procs();
     * dump_tree(init_proc);
     * free_procs(); */

    return 0;
}
