#ifndef LG2SQL_HPP
#define LG2SQL_HPP

#include <git2.h>

int git_odb_backend_sqlite(git_odb_backend **backend_out, const char *sqlite_db);
int git_refdb_backend_sqlite(git_refdb_backend **backend_out, const char *sqlite_db);

#endif
