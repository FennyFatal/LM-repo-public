#include "ps4.h"
#include "defines.h"
#include "stdbool.h"

#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2


//#include "stdio.h"
#include "C:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\kernel.h"
//#include "_mmap.h"
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\time.h"

typedef struct DIR DIR;
//typedef struct FILE FILE;

#define TRUE 1
#define FALSE 0

extern int run;

typedef struct {
    int index;
    uint64_t fileoff;
    size_t bufsz;
    size_t filesz;
    int enc;
} SegmentBufInfo;


#define SELF_MAGIC	0x1D3D154F
#define ELF_MAGIC	0x464C457F

int is_self(const char *fn)
{
    struct stat st;
    int res = 0;
    int fd = open(fn, O_RDONLY, 0);
    if (fd != -1) {
        stat(fn, &st);
        void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (addr != MAP_FAILED) {
            ////printfsocket("mmap %s : %p\n", fn, addr);
            if (st.st_size >= 4)
            {
                uint32_t selfMagic = *(uint32_t*)((uint8_t*)addr + 0x00);
                if (selfMagic == SELF_MAGIC)
                {
                    uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
                    if (st.st_size >= (0x20 + snum * 0x20 + 4))
                    {
                        uint32_t elfMagic = *(uint32_t*)((uint8_t*)addr + 0x20 + snum * 0x20);
                        if ((selfMagic == SELF_MAGIC) && (elfMagic == ELF_MAGIC))
                            res = 1;
                    }
                }
            }
            munmap(addr, 0x4000);
        }
        else {
            ////printfsocket("mmap file %s err : %s\n", fn, strerror(errno));
        }
        close(fd);
    }
    else {
        ////printfsocket("open %s err : %s\n", fn, strerror(errno));
    }

    return res;
}


#define BUFFER_SIZE 65536

static void copy_file(char *sourcefile, char* destfile)
{
    int fdin = open(sourcefile, O_RDONLY, 0);
    if (fdin != -1)
    {
        int fdout = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (fdout != -1)
        {
            size_t bytes;
            char *buffer = malloc(BUFFER_SIZE);
            if (buffer != NULL)
            {
                while (0 < (bytes = read(fdin, buffer, BUFFER_SIZE)))
                    write(fdout, buffer, bytes);
                    free(buffer);
            }
            close(fdout);
        }
        else {
            ////printfsocket("write %s err : %s\n", destfile, strerror(errno));
        }
        close(fdin);
    }
    else {
        ////printfsocket("open %s err : %s\n", sourcefile, strerror(errno));
    }
}

static void touch_file(char* destfile)
{
    int fd = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd != -1) close(fd);
}

static void decrypt_dir(char *sourcedir, char* destdir)
{
    DIR *dir;
    struct dirent *dp;
    struct stat info;
    char src_path[1024], dst_path[1024];

    dir = opendir(sourcedir);
    if (!dir)
        return;

    mkdir(destdir, 0777);

    while ((dp = readdir(dir)) != NULL)
    {
        if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
        {
            // do nothing (straight logic)
        }
        else
        {
            sprintf(src_path, "%s/%s", sourcedir, dp->d_name);
            sprintf(dst_path, "%s/%s", destdir  , dp->d_name);
            if (!stat(src_path, &info))
            {
                if (S_ISDIR(info.st_mode))
                {
                    decrypt_dir(src_path, dst_path);
                }
                else
                if (S_ISREG(info.st_mode))
                {
                    if (is_self(src_path))
                        decrypt_and_dump_self(src_path, dst_path);
                }
            }
        }
    }
    closedir(dir);
}

int wait_for_game(char *title_id)
{
    int res = 0;

    DIR *dir;
    struct dirent *dp;

    dir = opendir("/mnt/sandbox/pfsmnt");
    if (!dir)
        return 0;

    while ((dp = readdir(dir)) != NULL)
    {
        if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
        {
            // do nothing (straight logic)
        }
        else
        {
            if (strstr(dp->d_name, "-app0") != NULL)
            {
                sscanf(dp->d_name, "%[^-]", title_id);
                res = 1;
                break;
            }
        }
    }
    closedir(dir);

    return res;
}

int wait_for_bdcopy(char *title_id)
{
    char path[256];
    char *buf;
    size_t filelen, progress;

    sprintf(path, "/system_data/playgo/%s/bdcopy.pbm", title_id);
    FILE *pbm = fopen(path, "rb");
    if (!pbm) return 100;

    fseek(pbm, 0, SEEK_END);
    filelen = ftell(pbm);
    fseek(pbm, 0, SEEK_SET);

    buf = malloc(filelen);

    fread(buf, sizeof(char), filelen, pbm);
    fclose(pbm);

    progress = 0;
    for (int i = 0x100; i < filelen; i++)
    {
        if (buf [i]) progress++;
    }

    free(buf);

    return (progress * 100 / (filelen - 0x100));
}

int wait_for_usb(char *usb_name, char *usb_path)
{
    int fd = open("/mnt/usb0/.probe", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd != -1)
    {
        close(fd);
        unlink("/mnt/usb0/.probe");
        sprintf(usb_name, "%s", "USB0");
        sprintf(usb_path, "%s", "/mnt/usb0");
        return 1;
    }
    return 0;
}

int file_exists(char *fname)
{
    FILE *file = fopen(fname, "rb");
    if (file)
    {
        fclose(file);
        return 1;
    }
    return 0;
}

void dump_game(char *title_id, char *usb_path)
{
    char base_path[64];
    char src_path[64];
    char dst_file[64];
    char dst_app[64];
    char dst_pat[64];
    char dump_sem[64];
    char comp_sem[64];

    sprintf(base_path, "%s/%s", usb_path, title_id);

    sprintf(dump_sem, "%s.dumping", base_path);
    sprintf(comp_sem, "%s.complete", base_path);

    unlink(comp_sem);
    touch_file(dump_sem);


    unlink(dump_sem);
    touch_file(comp_sem);
}
