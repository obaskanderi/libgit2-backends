#include "sqlite.hpp"

#include <assert.h>
#include <git2/sys/refdb_backend.h>
#include <git2/sys/refs.h>
#include <string>
#include <sqlite3.h>
#include <vector>

static const std::string GIT2_REFDB_TABLE_NAME = "git2_refdb";
static const char GIT_TYPE_REF_OID = '1';
static const char GIT_TYPE_REF_SYMBOLIC = '2';

typedef struct sqlite_refdb_backend {
    git_refdb_backend parent;
    sqlite3 *db;
    sqlite3_stmt *st_read;
    sqlite3_stmt *st_read_all;
    sqlite3_stmt *st_write;
    sqlite3_stmt *st_delete;
} sqlite_refdb_backend;

typedef struct sqlite_refdb_iterator {
    git_reference_iterator parent;
    size_t current;
    std::vector<std::string> keys;
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
            std::string raw_ref = std::string(reinterpret_cast<const char*>(sqlite3_column_text(backend->st_read, 0)));
            if (raw_ref[0] == GIT_TYPE_REF_OID) {
                git_oid oid;
                git_oid_fromstr(&oid, raw_ref.substr(2).c_str());
                *out = git_reference__alloc(ref_name, &oid, nullptr);
            } else if (raw_ref[0] == GIT_TYPE_REF_SYMBOLIC) {
                *out = git_reference__alloc_symbolic(ref_name, raw_ref.substr(2).c_str());
            } else {
                giterr_set_str(GITERR_REFERENCE, "sqlite refdb storage corrupted (unknown ref type returned)");
                error = GIT_ERROR;
            }
            assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
        } else {
            giterr_set_str(GITERR_REFERENCE, "sqlite refdb failed to find reference for name");
            error = GIT_ENOTFOUND;
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

    if (iter->current < iter->keys.size()) {
        ref_name = iter->keys.at(iter->current++).c_str();
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

    if(iter->current < iter->keys.size()) {
        *ref_name = strdup(iter->keys.at(iter->current++).c_str());
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

    sqlite3_stmt *stmt_read;
    std::string stmt_str = "SELECT refname FROM " + GIT2_REFDB_TABLE_NAME + " WHERE refname LIKE '" + (glob != nullptr ? glob : "refs/") + "%';";
    if (sqlite3_prepare_v2(backend->db, stmt_str.c_str(), -1, &stmt_read, nullptr) != SQLITE_OK) {
        sqlite3_finalize(stmt_read);
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    /* loop reading each row until step returns anything other than SQLITE_ROW */
    int result;
    std::vector<std::string> keys;
    do {
        result = sqlite3_step(stmt_read);
        if (result == SQLITE_ROW) {
            std::string key = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt_read, 0)));
            keys.emplace_back(key);
        }
    } while (result == SQLITE_ROW) ;

    iterator = (sqlite_refdb_iterator *) calloc(1, sizeof(sqlite_refdb_iterator));

    iterator->backend = backend;
    iterator->keys = keys;

    iterator->parent.next = &sqlite_refdb_backend__iterator_next;
    iterator->parent.next_name = &sqlite_refdb_backend__iterator_next_name;
    iterator->parent.free = &sqlite_refdb_backend__iterator_free;

    *_iter = (git_reference_iterator *) iterator;

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
        target = git_reference_target(ref);
        std::string write_value;
        if (target) {
            git_oid_nfmt(oid_str, sizeof(oid_str), target);
            write_value.append(1, GIT_TYPE_REF_OID);
            write_value.append(":");
            write_value.append(oid_str);
        } else {
            std::string symbolic_target = std::string(reinterpret_cast<const char*>(git_reference_symbolic_target(ref)));
            write_value.append(1, GIT_TYPE_REF_SYMBOLIC);
            write_value.append(":");
            write_value.append(symbolic_target);
        }

        result = sqlite3_bind_text(backend->st_write, 2, write_value.c_str(), write_value.size(), SQLITE_TRANSIENT);
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
    std::string stmt_str = "UPDATE " + GIT2_REFDB_TABLE_NAME + " SET refname = ? WHERE refname = ?;";

    if (sqlite3_prepare_v2(backend->db, stmt_str.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
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
    static const std::string sql_create =
        "CREATE TABLE " + GIT2_REFDB_TABLE_NAME +" ("
        "'refname' TEXT PRIMARY KEY NOT NULL,"
        "'ref' TEXT NOT NULL);";

    if (sqlite3_exec(db, sql_create.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating table for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    return GIT_OK;
}

static int init_db(sqlite3 *db)
{
    static const std::string sql_check =
        "SELECT name FROM sqlite_master WHERE type='table' AND name= '" + GIT2_REFDB_TABLE_NAME + "';";

    sqlite3_stmt *st_check;
    int error;

    if (sqlite3_prepare_v2(db, sql_check.c_str(), -1, &st_check, nullptr) != SQLITE_OK) {
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
    static const std::string sql_read =
        "SELECT ref FROM " + GIT2_REFDB_TABLE_NAME + " WHERE refname = ?;";

    static const std::string sql_read_all =
        "SELECT refname FROM " + GIT2_REFDB_TABLE_NAME +";";

    static const std::string sql_write =
        "INSERT OR IGNORE INTO " + GIT2_REFDB_TABLE_NAME +" VALUES (?, ?);";

    static const std::string sql_delete =
        "DELETE FROM " + GIT2_REFDB_TABLE_NAME + " WHERE refname = ?;";

    if (sqlite3_prepare_v2(backend->db, sql_read.c_str(), -1, &backend->st_read, nullptr) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    if (sqlite3_prepare_v2(backend->db, sql_read_all.c_str(), -1, &backend->st_read_all, nullptr) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    if (sqlite3_prepare_v2(backend->db, sql_write.c_str(), -1, &backend->st_write, nullptr) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    if (sqlite3_prepare_v2(backend->db, sql_delete.c_str(), -1, &backend->st_delete, nullptr) != SQLITE_OK) {
        giterr_set_str(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
        return GIT_ERROR;
    }

    return GIT_OK;
}

int git_refdb_backend_sqlite(git_refdb_backend **backend_out, const char *sqlite_db)
{
    sqlite_refdb_backend *backend;

    backend = (sqlite_refdb_backend *) calloc(1, sizeof(sqlite_refdb_backend));
    if (backend == nullptr) {
        return -1;
    }

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
    backend->parent.compress = nullptr;
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
