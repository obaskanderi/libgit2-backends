#include <assert.h>
#include <git2.h>
#include <git2/errors.h>
#include <git2/sys/refdb_backend.h>
#include <git2/sys/refs.h>
#include <string.h>
#include <sqlite3.h>

#define GIT2_REFDB_TABLE_NAME "git2_refdb"

static const char* GIT2_TABLE_NAME = "git_refdb";
static const char* GIT_TYPE_REF_OID = "1";
static const char* GIT_TYPE_REF_SYMBOLIC = "2";

typedef struct sqlite_refdb_backend {
    git_refdb_backend parent;
    git_repository *repo;
    sqlite3 *db;
    sqlite3_stmt *st_read;
    sqlite3_stmt *st_read_all;
    sqlite3_stmt *st_write;
    sqlite3_stmt *st_delete;
} sqlite_refdb_backend;

typedef struct sqlite_refdb_iterator {
    git_reference_iterator parent;
    size_t current;
    const char** keys;
    size_t size;
    sqlite_refdb_backend *backend;
} sqlite_refdb_iterator;

static int sqlite_refdb_backend__exists(int *exists, git_refdb_backend *_backend, const char *ref_name)
{
    sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;

    assert(backend);

    *exists = 0;

    if (sqlite3_bind_text(backend->st_read, 1, (char *)ref_name, -1, SQLITE_TRANSIENT) == SQLITE_OK) {
        if (sqlite3_step(backend->st_read) == SQLITE_ROW) {
            *exists = 1;
            assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
        }
    }

    sqlite3_reset(backend->st_read);
    return 0;
}

static int sqlite_refdb_backend__lookup(git_reference **out, git_refdb_backend *_backend, const char *ref_name)
{
    sqlite_refdb_backend *backend;
    int error = GIT_OK;

    assert(ref_name && _backend);

    backend = (sqlite_refdb_backend *) _backend;

    if (sqlite3_bind_text(backend->st_read, 1, ref_name, strlen(ref_name), SQLITE_TRANSIENT) == SQLITE_OK) {
        if (sqlite3_step(backend->st_read) == SQLITE_ROW) {
            char *raw_ref = (char *) sqlite3_column_text(backend->st_read, 0);

            int size = strlen(raw_ref) - 1;
            char oid_str[size];
            strncpy(oid_str, raw_ref + 2, size);
            oid_str[size] = (char)0;

            if (raw_ref[0] == GIT_TYPE_REF_OID[0]) {
                git_oid oid;
                git_oid_fromstr(&oid, oid_str);
                *out = git_reference__alloc(ref_name, &oid, NULL);
            } else if (raw_ref[0] == GIT_TYPE_REF_SYMBOLIC[0]) {
                *out = git_reference__alloc_symbolic(ref_name, oid_str);
            } else {
                giterr_set_str(GITERR_REFERENCE, "sqlite refdb storage corrupted (unknown ref type returned)");
                error = GIT_ERROR;
            }
            assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
        } else {
            giterr_set_str(GITERR_REFERENCE, "sqlite refdb storage corrupted (unknown ref type returned)");
            error = GIT_ERROR;
        }
    } else {
        giterr_set_str(GITERR_REFERENCE, "sqlite refdb storage corrupted (unknown ref type returned)");
        error = GIT_ERROR;
    }

    sqlite3_reset(backend->st_read);
    return error;
}

static void sqlite_refdb_backend__iterator_free(git_reference_iterator *_iter)
{
    sqlite_refdb_iterator *iter;
    assert(_iter);
    free(iter->keys);
    iter = (sqlite_refdb_iterator *) _iter;
    free(iter);
}

static int sqlite_refdb_backend__iterator_next(git_reference **ref, git_reference_iterator *_iter)
{
    sqlite_refdb_iterator *iter;
    const char* ref_name;
    int error;

    assert(_iter);
    iter = (sqlite_refdb_iterator *) _iter;

    if (iter->current < iter->size) {
        ref_name = iter->keys[iter->current++];
        error = sqlite_refdb_backend__lookup(ref, (git_refdb_backend *)iter->backend, ref_name);
        return error;
    } else {
        return GIT_ITEROVER;
    }
}

static int sqlite_refdb_backend__iterator_next_name(const char **ref_name, git_reference_iterator *_iter)
{
    sqlite_refdb_iterator *iter;

    assert(_iter);
    iter = (sqlite_refdb_iterator *) _iter;

    if(iter->current < iter->size) {
        *ref_name = strdup(iter->keys[iter->current++]);
        return GIT_OK;
    } else {
        return GIT_ITEROVER;
    }
}

int sqlite_refdb_backend__iterator(git_reference_iterator **_iter, struct git_refdb_backend *_backend, const char *glob)
{
    sqlite_refdb_backend *backend;
    sqlite_refdb_iterator *iterator;

    assert(_backend);

    backend = (sqlite_refdb_backend *) _backend;

    char count_stmt_str[] = "SELECT COUNT(*) FROM ";
    char refname_stmt_str[] = "SELECT refname FROM ";
    strncat(count_stmt_str, GIT2_TABLE_NAME, strlen(GIT2_TABLE_NAME));
    strncat(refname_stmt_str, GIT2_TABLE_NAME, strlen(GIT2_TABLE_NAME));

    if (glob != NULL) {
        char where_clause[] = "WHERE refname LIKE '";
        strncat(where_clause, glob, strlen(glob));
        char end[] = "%';";
        strncat(where_clause, end, strlen(end));
        strncat(count_stmt_str, where_clause, strlen(where_clause));
        strncat(refname_stmt_str, where_clause, strlen(where_clause));
    } else {
        char where_clause[] = "WHERE refname LIKE 'refs/%';";
        strncat(count_stmt_str, where_clause, strlen(where_clause));
        strncat(refname_stmt_str, where_clause, strlen(where_clause));
    }

    sqlite3_stmt *count_stmt;
    sqlite3_stmt *refname_stmt;
    int result = sqlite3_prepare_v2(backend->db, count_stmt_str, -1, &count_stmt, NULL);
    result &= sqlite3_prepare_v2(backend->db, refname_stmt_str, -1, &refname_stmt, NULL);

    if (result != SQLITE_OK) {
        sqlite3_finalize(count_stmt);
        sqlite3_finalize(refname_stmt);
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for sqlite refdb backend");
        return GIT_ERROR;
    }

    int rows;
    result = sqlite3_step(count_stmt);
    if (result == SQLITE_ROW) {
        rows = sqlite3_column_int(count_stmt, 0);
    }

    iterator = (sqlite_refdb_iterator *) calloc(1, sizeof(sqlite_refdb_iterator));
    iterator->backend = backend;
    iterator->keys = (const char**)malloc(sizeof(char**)*rows);
    iterator->size = rows;

    int count = 0;
    do {
        result = sqlite3_step(refname_stmt);
        if (result == SQLITE_ROW) {
            iterator->keys[count++] = (const char*) sqlite3_column_text(refname_stmt, 0);
        }
    } while (result == SQLITE_ROW) ;


    iterator->parent.next = &sqlite_refdb_backend__iterator_next;
    iterator->parent.next_name = &sqlite_refdb_backend__iterator_next_name;
    iterator->parent.free = &sqlite_refdb_backend__iterator_free;

    *_iter = (git_reference_iterator *) iterator;

    sqlite3_finalize(count_stmt);
    sqlite3_finalize(refname_stmt);

    return GIT_OK;
}

static int sqlite_refdb_backend__write(
    git_refdb_backend *_backend,
    const git_reference *ref,
    int force,
    const git_signature *who,
    const char *message,
    const git_oid *old,
    const char *old_target)
{
    sqlite_refdb_backend *backend;

    const char *name = git_reference_name(ref);
    const git_oid *target;
    char oid_str[GIT_OID_HEXSZ + 1];

    assert(ref && _backend);

    backend = (sqlite_refdb_backend *) _backend;

    int result = sqlite3_bind_text(backend->st_write, 1, name, strlen(name), SQLITE_TRANSIENT);
    if (result == SQLITE_OK) {
        char write_value[] = {0};
        if (target) {
            git_oid_nfmt(oid_str, sizeof(oid_str), target);
            strncat(write_value, GIT_TYPE_REF_OID, 1);
            strncat(write_value, ":", 1);
            strncat(write_value, oid_str, strlen(oid_str));
        } else {
            const char *symbolic_target = git_reference_symbolic_target(ref);
            strncat(write_value, GIT_TYPE_REF_SYMBOLIC, 1);
            strncat(write_value, ":", 1);
            strncat(write_value, symbolic_target, strlen(symbolic_target));
        }

        result = sqlite3_bind_text(backend->st_write, 2, write_value, strlen(write_value), SQLITE_TRANSIENT);
        if (result == SQLITE_OK) {
            result = sqlite3_step(backend->st_write);
        }
    }

    sqlite3_reset(backend->st_write);
    if (result == SQLITE_DONE) {
        return GIT_OK;
    } else {
        giterr_set_str(GITERR_ODB, "Error writing reference to Sqlite RefDB backend");
        return GIT_ERROR;
    }
}

int sqlite_refdb_backend__rename(git_reference **out, git_refdb_backend *_backend, const char *old_name,
    const char *new_name, int force, const git_signature *who, const char *message)
{
    sqlite_refdb_backend *backend;

    assert(old_name && new_name && _backend);

    backend = (sqlite_refdb_backend *) _backend;
    sqlite3_stmt *stmt;
    const char *stmt_str =
            "UPDATE '" GIT2_REFDB_TABLE_NAME "' SET refname = ? WHERE refname = ?;";

    if (sqlite3_prepare_v2(backend->db, stmt_str, -1, &stmt, NULL) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    int result = sqlite3_bind_text(stmt, 1, new_name, strlen(new_name), SQLITE_TRANSIENT);
    result &= sqlite3_bind_text(stmt, 2, old_name, strlen(old_name), SQLITE_TRANSIENT);

    if (result != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error binding variables prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    if (sqlite3_step(stmt) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        giterr_set_str(GITERR_REFERENCE, "sqlite refdb storage error");
        return GIT_ERROR;
    }

    sqlite3_finalize(stmt);
    return sqlite_refdb_backend__lookup(out, (git_refdb_backend *)backend, new_name);
}

int sqlite_refdb_backend__del(git_refdb_backend *_backend, const char *ref_name, const git_oid *old, const char *old_target)
{
    sqlite_refdb_backend *backend;

    assert(ref_name && _backend);

    backend = (sqlite_refdb_backend *) _backend;

    int error = SQLITE_ERROR;
    if (sqlite3_bind_text(backend->st_delete, 1, ref_name, strlen(ref_name), SQLITE_TRANSIENT) == SQLITE_OK) {
      error = sqlite3_step(backend->st_delete);
    }

    sqlite3_reset(backend->st_delete);
    if (error == SQLITE_DONE) {
      return GIT_OK;
    } else {
      giterr_set_str(GITERR_ODB, "Error deleting reference from Sqlite RefDB backend");
      return GIT_ERROR;
    }
}

static void sqlite_refdb_backend__free(git_refdb_backend *_backend)
{
    sqlite_refdb_backend *backend;
    assert(_backend);
    backend = (sqlite_refdb_backend *) _backend;

    sqlite3_finalize(backend->st_read);
    sqlite3_finalize(backend->st_read_all);
    sqlite3_finalize(backend->st_write);
    sqlite3_finalize(backend->st_delete);
    sqlite3_close(backend->db);

    free(backend);
}

static int sqlite_refdb_backend__has_log(git_refdb_backend *_backend, const char *name)
{
    return 0;
}

static int sqlite_refdb_backend__ensure_log(git_refdb_backend *_backend, const char *name)
{
    return GIT_ERROR;
}

static int sqlite_refdb_backend__reflog_read(git_reflog **out, git_refdb_backend *_backend, const char *name)
{
    return GIT_ERROR;
}

static int sqlite_refdb_backend__reflog_write(git_refdb_backend *_backend, git_reflog *reflog)
{
    return GIT_ERROR;
}

static int sqlite_refdb_backend__reflog_rename(git_refdb_backend *_backend, const char *old_name, const char *new_name)
{
    return GIT_ERROR;
}

static int sqlite_refdb_backend__reflog_delete(git_refdb_backend *_backend, const char *name)
{
    return GIT_ERROR;
}

static int create_table(sqlite3 *db)
{
    static const char *sql_creat =
        "CREATE TABLE '" GIT2_REFDB_TABLE_NAME "' ("
        "'refname' TEXT PRIMARY KEY NOT NULL,"
        "'ref' TEXT NOT NULL);";

    if (sqlite3_exec(db, sql_creat, NULL, NULL, NULL) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating table for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    return GIT_OK;
}

static int init_db(sqlite3 *db)
{
    static const char *sql_check =
        "SELECT name FROM sqlite_master WHERE type='table' AND name='" GIT2_REFDB_TABLE_NAME "';";

    sqlite3_stmt *st_check;
    int error;

    if (sqlite3_prepare_v2(db, sql_check, -1, &st_check, NULL) != SQLITE_OK) {
        return GIT_ERROR;
    }

    switch (sqlite3_step(st_check)) {
        case SQLITE_DONE:
            /* the table was not found */
            error = create_table(db);
            break;

        case SQLITE_ROW:
            /* the table was found */
            error = GIT_OK;
            break;

        default:
            error = GIT_ERROR;
            break;
    }

    sqlite3_finalize(st_check);
    return error;
}

static int init_statements(sqlite_refdb_backend *backend)
{
    static const char *sql_read =
        "SELECT ref FROM '" GIT2_REFDB_TABLE_NAME "' WHERE refname = ?;";

    static const char *sql_read_all =
        "SELECT refname FROM '" GIT2_REFDB_TABLE_NAME "';";

    static const char *sql_write =
        "INSERT OR IGNORE INTO '" GIT2_REFDB_TABLE_NAME "' VALUES (?, ?);";

    static const char *sql_delete =
        "DELETE FROM '" GIT2_REFDB_TABLE_NAME "' WHERE refname = ?;";

    if (sqlite3_prepare_v2(backend->db, sql_read, -1, &backend->st_read, NULL) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    if (sqlite3_prepare_v2(backend->db, sql_read_all, -1, &backend->st_read_all, NULL) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    if (sqlite3_prepare_v2(backend->db, sql_write, -1, &backend->st_write, NULL) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    if (sqlite3_prepare_v2(backend->db, sql_delete, -1, &backend->st_delete, NULL) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    return GIT_OK;
}

int git_refdb_backend_sqlite(
  git_refdb_backend **backend_out,
  git_repository *repository,
  const char *sqlite_db)
{
    sqlite_refdb_backend *backend;

    backend = (sqlite_refdb_backend *) calloc(1, sizeof(sqlite_refdb_backend));
    if (backend == NULL) {
        return -1;
    }

    backend->repo = repository;

    if (sqlite3_open(sqlite_db, &backend->db) != SQLITE_OK) {
        goto fail;
    }

    if (init_db(backend->db) < 0) {
        goto fail;
    }

    if (init_statements(backend) < 0) {
        goto fail;
    }

    backend->parent.exists = &sqlite_refdb_backend__exists;
    backend->parent.lookup = &sqlite_refdb_backend__lookup;
    backend->parent.iterator = &sqlite_refdb_backend__iterator;
    backend->parent.write = &sqlite_refdb_backend__write;
    backend->parent.del = &sqlite_refdb_backend__del;
    backend->parent.rename = &sqlite_refdb_backend__rename;
    backend->parent.compress = NULL;
    backend->parent.has_log = &sqlite_refdb_backend__has_log;
    backend->parent.ensure_log = &sqlite_refdb_backend__ensure_log;
    backend->parent.free = &sqlite_refdb_backend__free;
    backend->parent.reflog_read = &sqlite_refdb_backend__reflog_read;
    backend->parent.reflog_write = &sqlite_refdb_backend__reflog_write;
    backend->parent.reflog_rename = &sqlite_refdb_backend__reflog_rename;
    backend->parent.reflog_delete = &sqlite_refdb_backend__reflog_delete;

    *backend_out = (git_refdb_backend *)backend;
    return 0;

fail:
    sqlite_refdb_backend__free((git_refdb_backend *)backend);
    return -1;
}
