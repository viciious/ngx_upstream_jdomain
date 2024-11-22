#ifndef NGX_UPSTREAM_JDOMAIN_H
#define NGX_UPSTREAM_JDOMAIN_H

#include <ngx_config.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_core.h>
#include <nginx.h>

#define NGX_JDOMAIN_STATUS_DONE 0
#define NGX_JDOMAIN_STATUS_WAIT 1

typedef struct {
	struct sockaddr	sockaddr;
	struct sockaddr_in6	padding;

	socklen_t	socklen;

	time_t		checked;
	ngx_uint_t	fails;

	ngx_str_t	name;
	u_char		ipstr[NGX_SOCKADDR_STRLEN + 1];

#if (NGX_HTTP_SSL)
	ngx_ssl_session_t	*ssl_session;   /* local to a process */
#endif
} ngx_upstream_jdomain_peer_t;

typedef struct ngx_upstream_jdomain_srv_conf {
	ngx_upstream_jdomain_peer_t		*peers;
	ngx_upstream_jdomain_peer_t		*temp_peers;
	ngx_uint_t		default_port;

	ngx_uint_t		resolved_max_ips;
	ngx_uint_t		resolved_num;
	ngx_str_t		resolved_domain;
	ngx_int_t		resolved_status;
	ngx_uint_t		resolved_index;
	time_t 			resolved_access;
	time_t			resolved_interval;

	time_t			fail_timeout;
	ngx_uint_t		max_fails;

	ngx_uint_t		upstream_retry;
	ngx_str_t		upstream_backup_file;
	ngx_str_t		upstream_temp_backup_dir;
	ngx_uint_t		upstream_backup_fsync:1;

	ngx_resolver_t	*resolver;
	ngx_msec_t		resolver_timeout;
	ngx_event_t		refresh;

	struct ngx_upstream_jdomain_srv_conf *next;
} ngx_upstream_jdomain_srv_conf_t;

typedef struct {
	struct ngx_upstream_jdomain_srv_conf	*urcf_first;
} ngx_upstream_jdomain_main_conf_t;

typedef struct {
	ngx_upstream_jdomain_srv_conf_t	*conf;

	ngx_int_t			current;
} ngx_upstream_jdomain_peer_data_t;

ngx_int_t ngx_upstream_jdomain_init(ngx_conf_t *cf, ngx_upstream_jdomain_main_conf_t *jmcf, ngx_upstream_jdomain_srv_conf_t *urcf);
ngx_int_t ngx_upstream_jdomain_init_process(ngx_cycle_t *cycle, ngx_upstream_jdomain_main_conf_t *jmcf);
ngx_int_t ngx_upstream_jdomain_init_peer(ngx_pool_t *pool, ngx_peer_connection_t *pc, ngx_upstream_jdomain_srv_conf_t *urcf);
char *ngx_upstream_jdomain(ngx_conf_t *cf, ngx_command_t *cmd, ngx_upstream_jdomain_srv_conf_t *urcf);
char *ngx_upstream_jdomain_resolver(ngx_conf_t *cf, ngx_command_t *cmd, ngx_upstream_jdomain_srv_conf_t *urcf);

#endif /* NGX_UPSTREAM_JDOMAIN_H */
