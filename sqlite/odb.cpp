#include "sqlite.hpp"

#include <assert.h>
#include <git2/odb.h>
#include <git2/sys/odb_backend.h>
#include <string>
#include <sqlite3.h>

static const std::string GIT2_ODB_TABLE_NAME = "git2_odb";

typedef struct {
    git_odb_backend parent;
    sqlite3 *db;
    sqlite3_stmt *st_read;
    sqlite3_stmt *st_write;
    sqlite3_stmt *st_read_header;
} sqlite_odb_backend;

static int sqlite_odb_backend__read_header(size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
    sqlite_odb_backend *backend;
    int error;

    assert(len_p && type_p && _backend && oid);

    backend = (sqlite_odb_backend *)_backend;
    error = GIT_ERROR;

    if (sqlite3_bind_text(backend->st_read_header, 1, (char *)oid->id, 20, SQLITE_TRANSIENT) == SQLITE_OK) {
        if (sqlite3_step(backend->st_read_header) == SQLITE_ROW) {
            *type_p = (git_otype)sqlite3_column_int(backend->st_read_header, 0);
            *len_p = (size_t)sqlite3_column_int(backend->st_read_header, 1);
            assert(sqlite3_step(backend->st_read_header) == SQLITE_DONE);
            error = GIT_OK;
        } else {
            error = GIT_ENOTFOUND;
        }
    }

    sqlite3_reset(backend->st_read_header);
    return error;
}

static int sqlite_odb_backend__read(void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
    sqlite_odb_backend *backend;
    int error;

    assert(data_p && len_p && type_p && _backend && oid);

    backend = (sqlite_odb_backend *)_backend;
    error = GIT_ERROR;

    if (sqlite3_bind_text(backend->st_read, 1, (char *)oid->id, 20, SQLITE_TRANSIENT) == SQLITE_OK) {
        if (sqlite3_step(backend->st_read) == SQLITE_ROW) {
            *type_p = (git_otype)sqlite3_column_int(backend->st_read, 0);
            *len_p = (size_t)sqlite3_column_int(backend->st_read, 1);
            *data_p = malloc(*len_p);

            if (*data_p == nullptr) {
                error = GIT_ERROR;
            } else {
                memcpy(*data_p, sqlite3_column_blob(backend->st_read, 2), *len_p);
                error = GIT_OK;
            }

            assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
        } else {
            error = GIT_ENOTFOUND;
        }
    }

    sqlite3_reset(backend->st_read);
    return error;
}

static int sqlite_odb_backend__read_prefix(
    git_oid *out_oid,
    void **data_p,
    size_t *len_p,
    git_otype *type_p,
    git_odb_backend *_backend,
    const git_oid *short_oid,
    size_t len)
{
    if (len >= GIT_OID_HEXSZ) {
        /* Just match the full identifier */
        int error = sqlite_odb_backend__read(data_p, len_p, type_p, _backend, short_oid);
        if (error == GIT_OK) {
            git_oid_cpy(out_oid, short_oid);
        }
        return error;
    }
    return GIT_ERROR;
}

static int sqlite_odb_backend__exists(git_odb_backend *_backend, const git_oid *oid)
{
    sqlite_odb_backend *backend;
    int found;

    assert(_backend && oid);

    backend = (sqlite_odb_backend *)_backend;
    found = 0;

    if (sqlite3_bind_text(backend->st_read_header, 1, (char *)oid->id, 20, SQLITE_TRANSIENT) == SQLITE_OK) {
        if (sqlite3_step(backend->st_read_header) == SQLITE_ROW) {
            found = 1;
            assert(sqlite3_step(backend->st_read_header) == SQLITE_DONE);
        }
    }

    sqlite3_reset(backend->st_read_header);
    return found;
}

static int sqlite_odb_backend__write(git_odb_backend *_backend, const git_oid *id, const void *data, size_t len, git_otype type)
{
    int error;
    sqlite_odb_backend *backend;

    assert(id && _backend && data);

    backend = (sqlite_odb_backend *)_backend;

    if ((error = git_odb_hash(const_cast<git_oid*>(id), data, len, type)) < 0) {
        return error;
    }

    error = SQLITE_ERROR;

    if (sqlite3_bind_text(backend->st_write, 1, (char *)id->id, 20, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int(backend->st_write, 2, (int)type) == SQLITE_OK &&
        sqlite3_bind_int(backend->st_write, 3, len) == SQLITE_OK &&
        sqlite3_bind_blob(backend->st_write, 4, data, len, SQLITE_TRANSIENT) == SQLITE_OK) {
            error = sqlite3_step(backend->st_write);
    }

    sqlite3_reset(backend->st_write);
    if (error == SQLITE_DONE) {
        return GIT_OK;
    } else {
        giterr_set_str(GITERR_ODB, "Error writing object to Sqlite ODB backend");
        return GIT_ERROR;
    }
}

static void sqlite_odb_backend__free(git_odb_backend *_backend)
{
    sqlite_odb_backend *backend = (sqlite_odb_backend *)_backend;
    assert(backend);

    sqlite3_finalize(backend->st_read);
    sqlite3_finalize(backend->st_read_header);
    sqlite3_finalize(backend->st_write);
    sqlite3_close(backend->db);

    free(backend);
}

static int create_table(sqlite3 *db)
{
    static const std::string sql_create =
        "CREATE TABLE " + GIT2_ODB_TABLE_NAME +" ("
        "'oid' CHARACTER(20) PRIMARY KEY NOT NULL,"
        "'type' INTEGER NOT NULL,"
        "'size' INTEGER NOT NULL,"
        "'data' BLOB);";

    if (sqlite3_exec(db, sql_create.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        giterr_set_str(GITERR_ODB, "Error creating table for Sqlite ODB backend");
        return GIT_ERROR;
    }

    return GIT_OK;
}

static int init_db(sqlite3 *db)
{
    static const std::string sql_check =
        "SELECT name FROM sqlite_master WHERE type='table' AND name='" + GIT2_ODB_TABLE_NAME + "';";

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

static int init_statements(sqlite_odb_backend *backend)
{
    static const std::string sql_read =
        "SELECT type, size, data FROM "+ GIT2_ODB_TABLE_NAME +" WHERE oid = ?;";

    static const std::string sql_read_header =
        "SELECT type, size FROM " + GIT2_ODB_TABLE_NAME +" WHERE oid = ?;";

    static const std::string sql_write =
        "INSERT OR IGNORE INTO " + GIT2_ODB_TABLE_NAME + " VALUES (?, ?, ?, ?);";

    if (sqlite3_prepare_v2(backend->db, sql_read.c_str(), -1, &backend->st_read, nullptr) != SQLITE_OK) {
        return GIT_ERROR;
    }

    if (sqlite3_prepare_v2(backend->db, sql_read_header.c_str(), -1, &backend->st_read_header, nullptr) != SQLITE_OK) {
        return GIT_ERROR;
    }

    if (sqlite3_prepare_v2(backend->db, sql_write.c_str(), -1, &backend->st_write, nullptr) != SQLITE_OK) {
        return GIT_ERROR;
    }

    return GIT_OK;
}

int git_odb_backend_sqlite(git_odb_backend **backend_out, const char *sqlite_db)
{
    sqlite_odb_backend *backend;
    int error;

    backend = (sqlite_odb_backend*) calloc(1, sizeof(sqlite_odb_backend));
    if (backend == nullptr) {
        return -1;
    }

    backend->parent.version = GIT_ODB_BACKEND_VERSION;

    error = sqlite3_open(sqlite_db, &backend->db);
    if (error != SQLITE_OK) {
        goto cleanup;
    }

    error = init_db(backend->db);
    if (error < 0) {
        goto cleanup;
    }

    error = init_statements(backend);
    if (error < 0) {
        goto cleanup;
    }

    backend->parent.read = &sqlite_odb_backend__read;
    backend->parent.write = &sqlite_odb_backend__write;
    backend->parent.read_prefix = &sqlite_odb_backend__read_prefix;
    backend->parent.read_header = &sqlite_odb_backend__read_header;
    backend->parent.exists = &sqlite_odb_backend__exists;
    backend->parent.free = &sqlite_odb_backend__free;

    *backend_out = (git_odb_backend *)backend;
    return 0;

cleanup:
    sqlite_odb_backend__free((git_odb_backend *)backend);
    return error;
}
