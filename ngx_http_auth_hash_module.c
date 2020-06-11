#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <openssl/sha.h>
#include <time.h>

typedef struct {
    ngx_str_t key;
    ngx_regex_compile_t *book_id_regex;
    time_t expires;
    ngx_flag_t ignore;
} ngx_http_auth_hash_conf_t;

static ngx_int_t ngx_http_auth_hash_handler(ngx_http_request_t *r);
static void ngx_http_auth_hash_set_no_cache(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_hash_validate_request(ngx_http_request_t *r, ngx_http_auth_hash_conf_t *ahcf, ngx_str_t book_id, ngx_str_t *key);
static ngx_int_t ngx_http_auth_hash_sha256_string(u_char *buffer, int len, ngx_pool_t *pool, u_char **hash);
static ngx_int_t ngx_http_auth_hash_get_book_id(ngx_regex_compile_t *rc, ngx_str_t *out, ngx_http_request_t *r);
static void *ngx_http_auth_hash_create_conf(ngx_conf_t *cf);
static char *ngx_http_auth_hash_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_auth_hash_book_id_regex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auth_hash_init(ngx_conf_t *cf);

static ngx_str_t ngx_http_auth_hash_cookie_name = ngx_string("book_key");
static ngx_str_t ngx_http_auth_hash_cache_control_key = ngx_string("Cache-Control");
static ngx_str_t ngx_http_auth_hash_cache_control_value = ngx_string("no-cache");

static ngx_command_t ngx_http_auth_hash_commands[] = {
    {
        ngx_string("auth_hash"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_hash_conf_t, key),
        NULL
    },
    {
        ngx_string("auth_hash_exp_time"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_sec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_hash_conf_t, expires),
        NULL
    },
    {
        ngx_string("auth_hash_book_id_regex"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_auth_hash_book_id_regex,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("auth_hash_ignore"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_hash_conf_t, ignore),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_hash_module_ctx = {
    NULL,
    ngx_http_auth_hash_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_auth_hash_create_conf,
    ngx_http_auth_hash_merge_conf
};

ngx_module_t ngx_http_auth_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_hash_module_ctx,
    ngx_http_auth_hash_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_auth_hash_handler(ngx_http_request_t *r)
{
    ngx_http_auth_hash_conf_t *ahcf;

    ahcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_hash_module);

    if (ahcf->key.len == 0) {
        return NGX_DECLINED;
    }

    if (ahcf->book_id_regex == NGX_CONF_UNSET_PTR) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "auth_hash_book_id_regex is missing");
        if (ahcf->ignore)
          return NGX_DECLINED;
        ngx_http_auth_hash_set_no_cache(r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ahcf->expires == NGX_CONF_UNSET) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "auth_hash_expires is missing");
        if (ahcf->ignore)
          return NGX_DECLINED;
        ngx_http_auth_hash_set_no_cache(r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_t book_id = ngx_null_string;
    if (ngx_http_auth_hash_get_book_id(ahcf->book_id_regex, &book_id, r) != NGX_OK || book_id.data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "could not find book id");
        return NGX_DECLINED;
    }

    ngx_str_t key;
    ngx_int_t n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &ngx_http_auth_hash_cookie_name, &key);

    if (n == NGX_DECLINED) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "cookie not found");
        return NGX_ERROR;
    }

    ngx_str_t key_copy = key;

    if (ngx_http_auth_hash_validate_request(r, ahcf, book_id, &key) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "[AHFAIL] client provided a bad key (%V)", &key_copy);
        if (ahcf->ignore)
          return NGX_DECLINED;
        ngx_http_auth_hash_set_no_cache(r);
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}

static void
ngx_http_auth_hash_set_no_cache(ngx_http_request_t *r)
{
    ngx_array_t *cc = &r->headers_out.cache_control;

    if (cc->elts == NULL) {
        if (ngx_array_init(cc, r->pool, 1, sizeof(ngx_table_elt_t *)) != NGX_OK) {
            // this is an error
            return;
        }
    }

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        // this is an error
        return;
    }

    h->hash = 1;
    h->key = ngx_http_auth_hash_cache_control_key;
    h->value = ngx_http_auth_hash_cache_control_value;

    ngx_table_elt_t **ph = ngx_array_push(cc);
    if (ph == NULL) {
        // this is an error
        return;
    }

    *ph = h;
}

static ngx_int_t
ngx_http_auth_hash_sha256_string(u_char *buffer, int len, ngx_pool_t *pool, u_char **hash)
{
    *hash = ngx_pnalloc(pool, SHA256_DIGEST_LENGTH);
    if (*hash == NULL)
        return NGX_ERROR;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, len);
    SHA256_Final(*hash, &sha256);
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_hash_get_book_id(ngx_regex_compile_t *rc, ngx_str_t *out, ngx_http_request_t *r)
{
    int captures_len = (1 + rc->captures) * 3;
    int *captures = ngx_pnalloc(r->pool, captures_len * sizeof(int));

    ngx_int_t n = ngx_regex_exec(rc->regex, &r->uri, captures, captures_len);
    if (n >= 0) {
        out->len = captures[3] - captures[2];
        out->data = r->uri.data + captures[2];
        return NGX_OK;
    } else {
        return NGX_ERROR;
    }
}

static ngx_int_t
ngx_http_auth_hash_validate_request(ngx_http_request_t *r, ngx_http_auth_hash_conf_t *ahcf, ngx_str_t book_id, ngx_str_t *key)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "validating the request by hash...");
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "provided key: %V", key);

    u_char *unescaped_key = ngx_pnalloc(r->pool, key->len + 1);
    if (unescaped_key == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "couldn't allocate buffer for unescaping key parameter");
        return NGX_ERROR;
    }
    u_char *unescaped_copy = unescaped_key;
    ngx_unescape_uri(&unescaped_copy, &key->data, key->len, 0);
    *unescaped_copy = '\0';
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "unescaped key parameter: %s", unescaped_key);

    ngx_str_t base64_key;
    base64_key.len = ngx_strlen(unescaped_key);
    base64_key.data = unescaped_key;
    if (base64_key.len != 56 || base64_key.data[55] != '=' || base64_key.data[54] != '=') {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "received base64 is invalid");
        return NGX_ERROR;
    }

    ngx_str_t received_token;
    received_token.len = SHA256_DIGEST_LENGTH + 8;
    received_token.data = ngx_pnalloc(r->pool, received_token.len);
    if (received_token.data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "couldn't allocate buffer for received token");
        return NGX_ERROR;
    }
    ngx_decode_base64(&received_token, &base64_key);

    unsigned long long received_timestamp = 0;
    for (int i = 0; i < 8; ++i) {
        received_timestamp += ((unsigned long long) received_token.data[i]) << (i * 8);
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "received timestamp: %l", received_timestamp);

    time_t current_time;
    time(&current_time);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "got the time");
    if ((unsigned long long) current_time - received_timestamp > (unsigned long long) ahcf->expires) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "invalid time difference");
        return NGX_ERROR;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "time ok");

    int hashed_data_len = 8 /* timestamp len */ + r->connection->addr_text.len + ahcf->key.len + book_id.len;
    u_char *hashed_data = ngx_pnalloc(r->pool, hashed_data_len);
    if (hashed_data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "couldn't allocate buffer for hashed data");
        return NGX_ERROR;
    }

    u_char *hashed_next = ngx_copy(hashed_data, received_token.data, 8);
    hashed_next = ngx_copy(hashed_next, r->connection->addr_text.data, r->connection->addr_text.len);
    hashed_next = ngx_copy(hashed_next, ahcf->key.data, ahcf->key.len);
    hashed_next = ngx_copy(hashed_next, book_id.data, book_id.len);

    u_char *hash;
    if (ngx_http_auth_hash_sha256_string(hashed_data, hashed_data_len, r->pool, &hash) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "couldn't hash the data");
        return NGX_ERROR;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "hashed the data");

    if (ngx_memcmp(hash, received_token.data + 8, SHA256_DIGEST_LENGTH) != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "hashes differ");
        return NGX_ERROR;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request is valid");

    return NGX_OK;
}

static char *
ngx_http_auth_hash_book_id_regex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_hash_conf_t *ahcf = conf;

    if (ahcf->book_id_regex != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    ngx_str_t *value = cf->args->elts;

    ngx_regex_compile_t *rc = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t));

    u_char errstr[NGX_MAX_CONF_ERRSTR];

    rc->pattern = value[1];
    rc->pool = cf->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NGX_CONF_ERROR;
    }

    ahcf->book_id_regex = rc;

    return NGX_CONF_OK;
}

static void *
ngx_http_auth_hash_create_conf(ngx_conf_t *cf)
{
    ngx_http_auth_hash_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_hash_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->expires = NGX_CONF_UNSET;
    conf->ignore = NGX_CONF_UNSET;
    conf->book_id_regex = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_auth_hash_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_hash_conf_t *prev = parent;
    ngx_http_auth_hash_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->key, prev->key, "");

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_hash_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_hash_handler;

    return NGX_OK;
}
