// cygwin dladdr attempt, apparently cygwin has like dlopen but no dladdr, gah!
// based off https://raw.githubusercontent.com/shr-project/enlightenment/master/efl/src/lib/evil/dlfcn.c
// mentioned in http://marc.info/?l=cygwin&m=126356512905471&w=2
// to use compile like $gcc -c dladdr.c
// then add it to you linker line like $ gcc ... dladdr.o
// another option would be this, if you have the flexibility to "just not call dladdr" https://cygwin.com/ml/cygwin/2010-01/msg00597.html

#include "dlfcn.h"
#include "limits.h"
#include "w32api/windows.h"

/**
 * @typedef Dl_info
 * @brief A structure that stores infomation of a calling process.
 */
typedef struct Dl_info Dl_info;

/**
 * @struct Dl_info
 * @brief A structure that stores infomation of a calling process.
 */

struct Dl_info
{
   char        dli_fname[PATH_MAX];  /**< Filename of defining object */
   void       *dli_fbase;            /**< Load address of that object */
   const char *dli_sname;            /**< Name of nearest lower symbol */
   void       *dli_saddr;            /**< Exact value of nearest symbol */
};


int
dladdr (const void *addr, Dl_info *info)
{
   // only returns filename, FWIW.
   TCHAR  tpath[PATH_MAX];
   MEMORY_BASIC_INFORMATION mbi;
   char  *path;
   char  *tmp;
   size_t length;
   int    ret = 0;

   if (!info)
     return 0;

   ret = GetModuleFileName(NULL, (LPTSTR)&tpath, PATH_MAX);
   if (!ret)
     return 0;

   path = tpath;

   length = strlen (path);
   if (length >= PATH_MAX)
     {
       length = PATH_MAX - 1;
       path[PATH_MAX - 1] = '\0';
     }

   /* replace '/' by '\' */
   tmp = path;
   while (*tmp)
     {
        if (*tmp == '/') *tmp = '\\';
        tmp++;
     }

   memcpy (info->dli_fname, path, length + 1);
   info->dli_fbase = NULL;
   info->dli_sname = NULL;
   info->dli_saddr = NULL;
   return 1;
}