
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Modified by Adnan Selimovic
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>

#include "hiredis.h"

#define NGX_HTTP_AUTH_BUF_SIZE  2048


typedef struct {
		ngx_str_t                  redis_host;
    ngx_int_t  								 redis_port;
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t   user_file;
} ngx_http_auth_basic_loc_conf_t;


static ngx_int_t ngx_http_auth_basic_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_basic_crypt_handler(ngx_http_request_t *r, ngx_str_t *passwd, ngx_str_t *realm);
static ngx_int_t ngx_http_auth_basic_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);
//static void ngx_http_auth_basic_close(ngx_file_t *file);
static void *ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_basic_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_basic_init(ngx_conf_t *cf);
static char *ngx_http_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_auth_basic_commands[] = {
		{ ngx_string("auth_basic_redis_host"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, redis_host),
      NULL },
      
    { ngx_string("auth_basic_redis_port"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, redis_port),
      NULL },
	
    { ngx_string("auth_basic"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, realm),
      NULL },

    { ngx_string("auth_basic_user_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_basic_user_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, user_file),
      NULL },
     
      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_basic_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_basic_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_basic_create_loc_conf,   /* create location configuration */
    ngx_http_auth_basic_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_basic_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_basic_module_ctx,       /* module context */
    ngx_http_auth_basic_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_basic_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_str_t                        pwd;
    ngx_str_t                        realm, user_file;
    ngx_http_auth_basic_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_module);

    if (alcf->realm == NULL || alcf->user_file.value.data == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_auth_basic_user(r);
    
    if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for basic authentication");

        return ngx_http_auth_basic_set_realm(r, &realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_complex_value(r, &alcf->user_file, &user_file) != NGX_OK) {
        return NGX_ERROR;
    }
    
    redisContext *c;
    redisReply *reply;
    
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
		c = redisConnectWithTimeout((char *)alcf->redis_host.data, alcf->redis_port, timeout);
		
		// convert ngx_str_t to char*
		unsigned int i;
		char username[r->headers_in.user.len+1];
				
		for(i=0;i<r->headers_in.user.len;i++)
			username[i] = r->headers_in.user.data[i];
			
		username[r->headers_in.user.len] = '\0';
						
		reply = redisCommand(c,"HGETALL user:%s", username);
				
		unsigned int j;
		
		if ( reply->type == REDIS_REPLY_ERROR ) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Reply error: %s'", reply->str);
		} else if ( reply->type == REDIS_REPLY_NIL ) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "User not found in db: %s", username);
		} else if ( reply->type != REDIS_REPLY_ARRAY ) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Unexpected type: %d'", reply->type);		
		} else {
        for (j = 0; j < reply->elements; j+=2) {
					if(strcmp(reply->element[j]->str, "password") == 0){
						u_char temp[strlen(reply->element[j+1]->str)+1];
						
						for(i=0;i<strlen(reply->element[j+1]->str);i++)
							temp[i] = reply->element[j+1]->str[i];
						
						temp[strlen(reply->element[j+1]->str)] = '\0';
						
						pwd.data = &temp[0];
						pwd.len = strlen(reply->element[j+1]->str)+1;
						
						freeReplyObject(reply);
						redisFree(c);
						
						return ngx_http_auth_basic_crypt_handler(r, &pwd, &realm);
					}
        }
    }
		         
    freeReplyObject(reply);
    redisFree(c);
    
    return ngx_http_auth_basic_set_realm(r, &realm);
}


static ngx_int_t
ngx_http_auth_basic_crypt_handler(ngx_http_request_t *r, ngx_str_t *passwd,
    ngx_str_t *realm)
{
    ngx_int_t   rc;
    u_char     *encrypted;

    rc = ngx_crypt(r->pool, r->headers_in.passwd.data, passwd->data,
                   &encrypted);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rc: %i user: \"%V\" salt: \"%s\"",
                   rc, &r->headers_in.user, passwd->data);

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_strcmp(encrypted, passwd->data) == 0) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "encrypted: \"%s\"", encrypted);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "user \"%V\": password mismatch",
                  &r->headers_in.user);

    return ngx_http_auth_basic_set_realm(r, realm);
}


static ngx_int_t
ngx_http_auth_basic_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = ngx_pnalloc(r->pool, len);
    if (basic == NULL) {
        r->headers_out.www_authenticate->hash = 0;
        r->headers_out.www_authenticate = NULL;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}

/*static void
ngx_http_auth_basic_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}*/


static void *
ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_basic_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    
    conf->redis_port = NGX_CONF_UNSET_UINT;
   
    return conf;
}


static char *
ngx_http_auth_basic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_basic_loc_conf_t  *prev = parent;
    ngx_http_auth_basic_loc_conf_t  *conf = child;

    if (conf->realm == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }
    
    

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_basic_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_basic_handler;

    return NGX_OK;
}


static char *
ngx_http_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_basic_loc_conf_t *alcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (alcf->user_file.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
