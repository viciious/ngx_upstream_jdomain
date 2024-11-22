#include "ngx_upstream_jdomain.h"

#ifndef ngx_sync_file
#define ngx_sync_file fsync
#endif

#if (NGX_SSL)
ngx_int_t
    ngx_upstream_set_jdomain_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_upstream_save_jdomain_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static ngx_int_t ngx_upstream_jdomain_get_peer(ngx_peer_connection_t *pc,
	void *data);

static void ngx_upstream_jdomain_free_peer(ngx_peer_connection_t *pc,
	void *data, ngx_uint_t state);

static void ngx_upstream_jdomain_handler(ngx_resolver_ctx_t *ctx);

static ngx_int_t
ngx_upstream_jdomain_dump_peers(ngx_upstream_jdomain_srv_conf_t *urcf, ngx_log_t *log)
{
	ngx_uint_t i;
	u_char buf[ngx_pagesize], *buf_pos, *buf_last;
	ssize_t buf_len;
	u_char tempfile[ngx_pagesize], *tempfile_pos, *tempfile_last;
	ssize_t tempfile_len;
	ngx_file_t file;

	if (urcf->upstream_temp_backup_dir.len == 0 || urcf->upstream_backup_file.len == 0) {
		return NGX_OK;
	}

	ngx_memzero(&file, sizeof(ngx_file_t));
	file.fd = NGX_INVALID_FILE;
	file.log = log;
	file.name = urcf->upstream_backup_file;

	*tempfile = '\0';
	tempfile_pos = tempfile;
	tempfile_last = tempfile + sizeof(tempfile) - 1;
	tempfile_len = 0;

	if (urcf->resolved_num == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"upstream_jdomain_dump_peers: there are no peers to dump");
		goto error;
	}

	tempfile_pos = ngx_snprintf(tempfile_pos, tempfile_last - tempfile_pos, "%V/jdomain_%V_%d.tmp%Z", 
		&urcf->upstream_temp_backup_dir, &urcf->resolved_domain, (unsigned)getpid());
	tempfile_len = tempfile_pos - tempfile;

	file.fd = ngx_open_file(tempfile,
						NGX_FILE_TRUNCATE,
						NGX_FILE_WRONLY,
						NGX_FILE_DEFAULT_ACCESS);
	if (file.fd == NGX_INVALID_FILE) {
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "upstream_jdomain_dump_peers: "
						"open dump file \"%s\" failed",
						tempfile);
		goto error;
	}

	*buf = '\0';
	buf_pos = buf;
	buf_last = buf + sizeof(buf) - 1;
	buf_len = 0;

	buf_pos = ngx_snprintf(buf_pos, buf_last - buf_pos, 
							"# domain %V\n", 
							&urcf->resolved_domain);
	for (i = 0; i < urcf->resolved_num; i++) {
		ngx_upstream_jdomain_peer_t *peer;

		peer = &urcf->peers[i];

		buf_pos = ngx_snprintf(buf_pos, buf_last - buf_pos,
								"server %V;\n", &peer->name);
	}

	buf_len = buf_pos - buf;

	if (ngx_write_file(&file, buf, buf_len, 0) != buf_len) {
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "upstream_jdomain_dump_peers: "
							"write file failed %V",
							&urcf->upstream_backup_file);
		goto error;
	}

	if (urcf->upstream_backup_fsync) {
		ngx_sync_file(file.fd);
	}

	ngx_close_file(file.fd);
	file.fd = NGX_INVALID_FILE;

	if (ngx_rename_file(tempfile, urcf->upstream_backup_file.data) != 0) {
		ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "upstream_jdomain_dump_peers: "
				"renaming \"%s\" to \"%V\" failed",
				tempfile, &urcf->upstream_backup_file);
		goto error;
	}

	ngx_log_error(NGX_LOG_NOTICE, log, 0, "upstream_jdomain_dump_peers: "
				"dump conf file \"%V\" succeeded, number of peers is %d",
				&urcf->upstream_backup_file, urcf->resolved_num);
	return NGX_OK;

error:
	if (file.fd != NGX_INVALID_FILE) {
		ngx_close_file(file.fd);
		file.fd = NGX_INVALID_FILE;
	}

	if (tempfile_len > 0) {
		ngx_delete_file(tempfile);
	}

	return NGX_ERROR;
}

static ngx_int_t
ngx_upstream_jdomain_load_peers(ngx_upstream_jdomain_srv_conf_t *urcf, ngx_pool_t *pool, ngx_log_t *log)
{
	ngx_uint_t i;
	ssize_t buf_len;
	char buf[ngx_pagesize], *buf_pos;
	char *line_end, *line_pos;
	ngx_uint_t line_len;
	ngx_file_t file;

	if (urcf->upstream_backup_file.len == 0) {
		return NGX_OK;
	}
	if (urcf->resolved_num != 0) {
		return NGX_OK;
	}

	ngx_memzero(&file, sizeof(ngx_open_file_t));
	file.log = log;
	file.name = urcf->upstream_backup_file;
	file.fd = ngx_open_file(urcf->upstream_backup_file.data,
										NGX_FILE_OPEN,
										NGX_FILE_RDONLY,
										NGX_FILE_DEFAULT_ACCESS);
	if (file.fd == NGX_INVALID_FILE) {
		if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOPATH) {
			return NGX_OK;
		}
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
				"upstream_jdomain_load_peers: opening dump file \"%V\" failed",
				&urcf->upstream_backup_file);
		goto error;
	}

	buf_len = ngx_read_file(&file, (u_char *)buf, sizeof(buf) - 2, 0);
	if (buf_len < 0) {
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
				"upstream_jdomain_load_peers: reading dump file \"%V\" failed",
				&urcf->upstream_backup_file);
		goto error;
	}
	buf[buf_len] = '\n';
	buf[buf_len+1] = '\0';

	ngx_close_file(file.fd);

	buf_pos = buf;
	if (strlen(buf_pos) <= sizeof("# domain ") - 1 || 
		ngx_strncmp(buf_pos, "# domain ", sizeof("# domain ") - 1) != 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "upstream_jdomain_load_peers: \"%V\": "
				"syntax error near %.10s, expected \"# domain \"",
				&urcf->upstream_backup_file, buf_pos);
		goto error;
	}
	buf_pos += sizeof("# domain ") - 1;

	if (strlen(buf_pos) < urcf->resolved_domain.len || 
		ngx_strncmp(buf_pos, urcf->resolved_domain.data, 
			urcf->resolved_domain.len) != 0 ||
		buf_pos[urcf->resolved_domain.len] != '\n') {
		ngx_log_error(NGX_LOG_ERR, log, 0,
				"upstream_jdomain_load_peers: \"%V\" domain name mismatch",
				&urcf->upstream_backup_file);
		goto error;
	}
	buf_pos += urcf->resolved_domain.len + 1;

	for (; (line_end = strchr(buf_pos, '\n')) != NULL; buf_pos = line_end + 1) {
		struct sockaddr *addr;
		ngx_upstream_jdomain_peer_t *peer;
		ngx_url_t u;

		peer = &urcf->peers[urcf->resolved_num];
		addr = &peer->sockaddr;

		*line_end = '\0';
		line_len = (ngx_uint_t)(line_end - buf_pos);
		line_pos = buf_pos;

		if (line_len == 0) {
			continue;
		}
		if (*line_pos == '#') {
			continue;
		}
		if (line_len <= sizeof("server ") - 1 || 
			ngx_strncmp(line_pos, "server ", sizeof("server ") - 1) != 0) {
			continue;
		}

		line_pos += sizeof("server ") - 1;
		line_len -= sizeof("server ") - 1;
		while (*line_pos == ' ') {
			line_pos++, line_len--;
		}

		if (line_len == 0) {
			continue;
		}

		for (i = 0; i <= line_len; i++) {
			if (i == NGX_SOCKADDR_STRLEN) {
				break;
			}
			if (line_pos[i] == '\0' || line_pos[i] == ' ' || line_pos[i] == ';') {
				break;
			}
			peer->ipstr[i] = line_pos[i];
		}
		peer->ipstr[i] = '\0';

		ngx_memzero(&u, sizeof(ngx_url_t));
		u.url.data = peer->ipstr;
		u.url.len = strlen((char *)peer->ipstr);
		u.default_port = (in_port_t)urcf->default_port;
		u.no_resolve = 1;

		if (ngx_parse_url(pool, &u) != NGX_OK) {
			if (u.err) {
				ngx_log_error(NGX_LOG_EMERG, log, 0,
					"upstream_jdomain_load_peers: %s in upstream \"%V\"", u.err, &u.url);
			}
			continue;
		}
		if (u.naddrs == 0) {
			continue;
		}

		ngx_memcpy(addr, u.addrs[0].sockaddr, u.addrs[0].socklen);

#if (nginx_version) < 1005008
		if (addr->sa_family != AF_INET) {
			continue;
		}
		((struct sockaddr_in6*)addr)->sin6_port = htons((u_short) urcf->default_port);
#else
		peer->socklen = u.addrs[0].socklen;

		switch (addr->sa_family) {
		case AF_INET6:
			((struct sockaddr_in6*)addr)->sin6_port = htons((u_short) urcf->default_port);
			break;
		default:
			((struct sockaddr_in*)addr)->sin_port = htons((u_short) urcf->default_port);
		}
#endif
		peer->name.data = peer->ipstr;
		peer->name.len =
#if (nginx_version) <= 1005002
			ngx_sock_ntop(addr, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);
#else
			ngx_sock_ntop(addr, peer->socklen, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);
#endif

		ngx_log_error(NGX_LOG_NOTICE, log, 0,
				"upstream_jdomain_load_peers: adding peer %s", peer->ipstr);

		urcf->resolved_num++;
		if (urcf->resolved_num == urcf->resolved_max_ips) {
			break;
		}
	}

	ngx_log_error(NGX_LOG_NOTICE, log, 0, "upstream_jdomain_dump_peers: "
				"dump conf file %V succeeded, number of peers is %d",
				&urcf->upstream_backup_file, urcf->resolved_num);
	return NGX_OK;

error:
	if (file.fd != NGX_INVALID_FILE) {
		ngx_close_file(file.fd);
		file.fd = NGX_INVALID_FILE;
	}
	return NGX_ERROR;
}

ngx_int_t ngx_upstream_jdomain_init(ngx_conf_t *cf, ngx_upstream_jdomain_main_conf_t *jmcf, ngx_upstream_jdomain_srv_conf_t *urcf)
{
	ngx_upstream_jdomain_srv_conf_t	*urcf_next;

	if (urcf->resolver == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no jdomain resolver");
		return NGX_ERROR;
	}
	if (urcf->resolver_timeout == NGX_CONF_UNSET_MSEC) {
		urcf->resolver_timeout = 30000;
	}
	urcf->resolved_status = NGX_JDOMAIN_STATUS_DONE;
	urcf->refresh.log = urcf->resolver->log;

	urcf_next = jmcf->urcf_first;
	jmcf->urcf_first = urcf;
	urcf->next = urcf_next;

	return NGX_OK;
}

ngx_int_t ngx_upstream_jdomain_init_peer(ngx_pool_t *pool, ngx_peer_connection_t *pc, ngx_upstream_jdomain_srv_conf_t *urcf)
{
	ngx_upstream_jdomain_peer_data_t	*urpd;

	urpd = ngx_pcalloc(pool, sizeof(ngx_upstream_jdomain_peer_data_t));
	if(urpd == NULL) {
		return NGX_ERROR;
	}
	
	urpd->conf = urcf;
	urpd->current = -1;
	
	pc->data = urpd;
	pc->free = ngx_upstream_jdomain_free_peer;
	pc->get = ngx_upstream_jdomain_get_peer;

	if(urcf->upstream_retry){
		pc->tries = (urcf->resolved_num != 1) ? urcf->resolved_num : 2;
	}else{
		pc->tries = 1;
	}

#if (NGX_SSL)
	pc->set_session = ngx_upstream_set_jdomain_peer_session;
	pc->save_session = ngx_upstream_save_jdomain_peer_session;
#endif

	return NGX_OK;
}

static void
ngx_upstream_jdomain_timer_restart(
	ngx_upstream_jdomain_srv_conf_t *urcf, time_t refresh_interval)
{
	if (!ngx_exiting) {
		ngx_resolver_t *r = urcf->resolver;
		ngx_log_error(NGX_LOG_INFO, r->log, 0,
			          "ngx_upstream_jdomain_timer_restart: restart resolving after %ds",
			          refresh_interval);
		ngx_add_timer(&urcf->refresh, refresh_interval * 1000);
	}
}

static void
ngx_upstream_jdomain_resolve_start(
	ngx_upstream_jdomain_srv_conf_t *urcf, ngx_resolver_t *resolver,
	ngx_msec_t resolver_timeout, ngx_log_t *log, ngx_uint_t force)
{
	ngx_resolver_ctx_t	*ctx;

	if(urcf->resolved_status == NGX_JDOMAIN_STATUS_WAIT){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
			"upstream_jdomain: resolving"); 
		return;
	}

	if (!force &&
	    ngx_time() <= urcf->resolved_access + urcf->resolved_interval) {
		return;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
		"upstream_jdomain: update from DNS cache"); 

	ctx = resolver ? ngx_resolve_start(resolver, NULL) : NGX_NO_RESOLVER;
	if(ctx == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
			"upstream_jdomain: resolve_start fail"); 
		return;
	}

	if(ctx == NGX_NO_RESOLVER) {
		ngx_log_error(NGX_LOG_ALERT, log, 0,
			"upstream_jdomain: no resolver"); 
		return;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
		"upstream_jdomain: resolve_start ok"); 

	ctx->name = urcf->resolved_domain;
#if (nginx_version) < 1005008
	ctx->type = NGX_RESOLVE_A;
#endif
	ctx->handler = ngx_upstream_jdomain_handler;
	ctx->data = urcf;
	ctx->timeout = resolver_timeout;

	urcf->resolved_status = NGX_JDOMAIN_STATUS_WAIT;
	if(ngx_resolve_name(ctx) != NGX_OK) {
		ngx_log_error(NGX_LOG_ALERT, log, 0,
			"upstream_jdomain: resolve name \"%V\" fail", &ctx->name);
		urcf->resolved_access = ngx_time();
		urcf->resolved_status = NGX_JDOMAIN_STATUS_DONE;
		ngx_upstream_jdomain_timer_restart(urcf, urcf->resolved_interval);
	}
}

static ngx_int_t
ngx_upstream_jdomain_get_peer(ngx_peer_connection_t *pc, void *data)
{
	ngx_upstream_jdomain_peer_data_t	*urpd = data;
	ngx_upstream_jdomain_srv_conf_t	*urcf = urpd->conf;
	ngx_upstream_jdomain_peer_t		*peer = NULL;
	time_t now = ngx_time();
	ngx_uint_t i;

	pc->cached = 0;
	pc->connection = NULL;

	ngx_upstream_jdomain_resolve_start(urcf,
		urcf->resolver,
		urcf->resolver_timeout,
		pc->log,
		0);

	/* If the resolution failed during startup or if resolution returned no entries,
	   fail all requests until it recovers */
	if (urcf->resolved_num == 0) {
		ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
			"upstream_jdomain: no resolved entry for \"%V\" fail", &urcf->resolved_domain);
		return NGX_ERROR;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		"upstream_jdomain: resolved_num=%ud", urcf->resolved_num); 

	for (i = 0; i < urcf->resolved_num; i++) {
		ngx_upstream_jdomain_peer_t *ipeer;

		if(urpd->current == -1){
			urcf->resolved_index = (urcf->resolved_index + 1) % urcf->resolved_num;

			urpd->current = urcf->resolved_index;
		}else{
			urpd->current = (urpd->current + 1) % urcf->resolved_num;
		}
		ipeer = &(urcf->peers[urpd->current]);
		if (urcf->max_fails
			&& ipeer->fails >= urcf->max_fails
			&& now - ipeer->checked <= urcf->fail_timeout) {

			continue;
		}
		peer = ipeer;
		break;
	}

	if (peer == NULL) {
		ngx_log_error(NGX_LOG_ERR, pc->log, 0,
			"upstream_jdomain: no active peers for \"%V\"", &urcf->resolved_domain);
		/* we don't return NGX_BUSY here to not allow nginx to try other servers in the upstream */
		return NGX_ERROR;
	}

	pc->sockaddr = &peer->sockaddr;
	pc->socklen = peer->socklen;
	pc->name = &peer->name;

	if (now - peer->checked > urcf->fail_timeout) {
		peer->checked = now;
	}

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		"upstream_jdomain: upstream to DNS peer (%s:%ud)",
		inet_ntoa(((struct sockaddr_in*)(pc->sockaddr))->sin_addr),
		ntohs((unsigned short)((struct sockaddr_in*)(pc->sockaddr))->sin_port));

	return NGX_OK;
}

static void
ngx_upstream_jdomain_free_peer(ngx_peer_connection_t *pc, void *data,ngx_uint_t state)
{
	ngx_upstream_jdomain_peer_data_t	*urpd = data;
	ngx_upstream_jdomain_srv_conf_t	*urcf = urpd->conf;
	ngx_upstream_jdomain_peer_t		*peer = &(urcf->peers[urpd->current]);

	if (state & NGX_PEER_FAILED) {
		if (urcf->max_fails) {
			time_t now = ngx_time();

			peer->fails++;
			peer->checked = now;
			if (peer->fails >= urcf->max_fails) {
				ngx_log_error(NGX_LOG_WARN, pc->log, 0,
								"upstream jdomain peer temporarily disabled");
			}
		}
	} else {
		peer->fails = 0;
	}
	if(pc->tries > 0)
		pc->tries--;
}

char *
ngx_upstream_jdomain(ngx_conf_t *cf, ngx_command_t *cmd, ngx_upstream_jdomain_srv_conf_t *urcf)
{
	time_t			interval, fail_timeout;
	ngx_str_t		*value, domain, s, backup_file, temp_backup_dir;
	ngx_int_t		default_port, max_ips, max_fails;
	ngx_uint_t		retry, fail;
	ngx_upstream_jdomain_peer_t		*paddr;
	ngx_url_t		u;
	ngx_uint_t		i;
	ngx_uint_t		backup_fsync;

	interval = 1;
	default_port = 80;
	max_ips = 20;
	max_fails = 0;
	fail_timeout = 10;
	retry = 1;
	fail = 1;
	domain.data = NULL;
	domain.len = 0;
	backup_file.data = NULL;
	backup_file.len = 0;
	temp_backup_dir.data = NULL;
	temp_backup_dir.len = 0;
	backup_fsync = 0;

	value = cf->args->elts;

	for (i=2; i < cf->args->nelts; i++) {
		if (value[i].len >= 5 && ngx_strncmp(value[i].data, "port=", 5) == 0) {
			default_port = ngx_atoi(value[i].data+5, value[i].len - 5);

			if ( default_port == NGX_ERROR || default_port < 1 ||
							default_port > 65535) {
				goto invalid;
			}

			continue;
		}

		if (value[i].len >= 9 && ngx_strncmp(value[i].data, "interval=", 9) == 0) {
			s.len = value[i].len - 9;
			s.data = &value[i].data[9];
			
			interval = ngx_parse_time(&s, 1);
			
			if (interval == (time_t) NGX_ERROR) {
				goto invalid;
			}
			
			continue;
		}

		if (value[i].len >= 8 && ngx_strncmp(value[i].data, "max_ips=", 8) == 0) {
			max_ips = ngx_atoi(value[i].data + 8, value[i].len - 8);

			if ( max_ips == NGX_ERROR || max_ips < 1) {
				goto invalid;
			}

			continue;
		}

		if (value[i].len == 9 && ngx_strncmp(value[i].data, "retry_off", 9) == 0) {
			retry = 0;

			continue;
		}

		if (ngx_strncmp(value[i].data, "no_fail", 7) == 0) {
			fail = 0;

			continue;
		}

		if (ngx_strncmp(value[i].data, "backup_file=", 12) == 0) {
			backup_file.len = value[i].len - 12;
			backup_file.data = &value[i].data[12];

			continue;
		}

		if (ngx_strncmp(value[i].data, "temp_backup_dir=", 16) == 0) {
			temp_backup_dir.len = value[i].len - 16;
			temp_backup_dir.data = &value[i].data[16];

			continue;
		}

		if (ngx_strncmp(value[i].data, "backup_fsync", 12) == 0) {
			backup_fsync = 1;

			continue;
		}

		if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {
			max_fails = ngx_atoi(value[i].data + 10, value[i].len - 10);

			if (max_fails < 0) {
				goto invalid;
			}
#if (nginx_version) < 1005008
			/* we do not support nonzero max_fails feature for old nginx versions */
			if (max_fails) {
				goto invalid;
			}
#endif

			continue;
		}

		if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {
			s.len = value[i].len - 13;
			s.data = &value[i].data[13];

			fail_timeout = ngx_parse_time(&s, 1);

			if (fail_timeout == (time_t) NGX_ERROR) {
				goto invalid;
			}

			continue;
		}

		goto invalid;

	}

	domain.data = value[1].data;
	domain.len  = value[1].len;

	urcf->peers = ngx_pcalloc(cf->pool,
			max_ips * sizeof(ngx_upstream_jdomain_peer_t));
	urcf->temp_peers = ngx_pcalloc(cf->pool,
			max_ips * sizeof(ngx_upstream_jdomain_peer_t));

	if (urcf->peers == NULL || urcf->temp_peers == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"ngx_palloc peers fail");

		return NGX_CONF_ERROR;
	}

	if (backup_file.len == 0) {
		temp_backup_dir.len = 0;
		temp_backup_dir.data = NULL;
	}

	urcf->resolved_interval = interval;
	urcf->resolved_domain = domain;
	urcf->default_port = default_port;
	urcf->resolved_max_ips = max_ips;
	urcf->max_fails = max_fails;
	urcf->fail_timeout = fail_timeout;
	urcf->upstream_retry = retry;
	urcf->upstream_backup_file = backup_file;
	urcf->upstream_temp_backup_dir = temp_backup_dir;
	urcf->upstream_backup_fsync = backup_fsync;

	urcf->resolved_num = 0;
	/*urcf->resolved_index = 0;*/
	urcf->resolved_access = 0;

	ngx_memzero(&u, sizeof(ngx_url_t));
	u.url = value[1];
	u.default_port = (in_port_t) urcf->default_port;

	// in no-fail (fail=0) mode, perform two-pass URL parsing:
	// validate upstream URL on the first pass and exit on error
	// perform domain name resolution on the second pass with jdomain_resolver
	// by each worker in ngx_http_upstream_jdomain_init_process() but do *not*
	// exit with error on failure
	//
	// in default (fail=1) mode, skip the first pass, resolve with the system
	// resolver immediatelly and exit on error
	u.no_resolve = !fail;
	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"%s in upstream \"%V\"", u.err, &u.url);
		}
		return NGX_CONF_ERROR;
	}

	for(i = 0; i < u.naddrs ;i++){
		paddr = &urcf->peers[urcf->resolved_num];
		ngx_memcpy(&paddr->sockaddr, u.addrs[i].sockaddr, u.addrs[i].socklen);
		paddr->socklen = u.addrs[i].socklen; 

		paddr->name.data = paddr->ipstr;
		paddr->name.len = 
#if (nginx_version) <= 1005002
			ngx_sock_ntop(&paddr->sockaddr, paddr->ipstr, NGX_SOCKADDR_STRLEN, 1);
#else
			ngx_sock_ntop(&paddr->sockaddr, paddr->socklen, paddr->ipstr, NGX_SOCKADDR_STRLEN, 1);
#endif

		urcf->resolved_num++;

		if (urcf->resolved_num >= urcf->resolved_max_ips)
			break;
	}

	if (u.naddrs > 0 && !u.no_resolve) {
		urcf->resolved_access = ngx_time();
		ngx_upstream_jdomain_dump_peers(urcf, cf->log);
	}
	else if (ngx_upstream_jdomain_load_peers(urcf, cf->temp_pool, cf->log) != NGX_OK) {
		if (fail) {
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;

invalid:
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		"invalid parameter \"%V\"", &value[i]);

	return NGX_CONF_ERROR;
}

void
ngx_upstream_jdomain_refresh(ngx_event_t *ev)
{
	ngx_upstream_jdomain_srv_conf_t *urcf = ev->data;
	ngx_resolver_t *r = urcf->resolver;
	ngx_log_error(NGX_LOG_INFO, r->log, 0,
	              "ngx_http_upstream_jdomain_refresh: timer expired, restart resolving");

	ngx_upstream_jdomain_resolve_start(urcf,
		urcf->resolver,
		urcf->resolver_timeout,
		r->log,
		1);
}

char *
ngx_upstream_jdomain_resolver(ngx_conf_t *cf, ngx_command_t *cmd, ngx_upstream_jdomain_srv_conf_t *urcf)
{
	ngx_str_t  *value;

	if (urcf->resolver) {
		return "is duplicate";
	}

	value = cf->args->elts;

	urcf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
	if (urcf->resolver == NULL) {
		return NGX_CONF_ERROR;
	}

	urcf->refresh.handler = ngx_upstream_jdomain_refresh;
	urcf->refresh.data = urcf;
	urcf->refresh.cancelable = 1;

	return NGX_CONF_OK;
}

static time_t ngx_upstream_jdomain_next_resolve(ngx_resolver_ctx_t *ctx)
{
	/* We couldn't directly get ngx_resolver_node_t::ttl, but ctx->valid should be
	   filled with ngx_time() + min_ttl */
	return (ctx->valid > ngx_time()) ? (ctx->valid - ngx_time()) : 1;
}

static void
ngx_upstream_jdomain_handler(ngx_resolver_ctx_t *ctx)
{
	struct sockaddr		*addr;
	ngx_uint_t		i;
	ngx_resolver_t		*r;
	ngx_upstream_jdomain_peer_t		*peer;
	ngx_upstream_jdomain_srv_conf_t	*urcf = ctx->data;
#if (nginx_version) >= 1005008
	ngx_uint_t		j, temp_peers_from;
	ngx_uint_t		resolved_num_orig = urcf->resolved_num;
#endif
	time_t next_resolve;

	r = ctx->resolver;

	ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
			"upstream_jdomain: \"%V\" resolved state(%i: %s)",
			&ctx->name, ctx->state,
			ngx_resolver_strerror(ctx->state));

	if (ctx->state || ctx->naddrs == 0) {
		ngx_log_error(NGX_LOG_ERR, r->log, 0,
			"upstream_jdomain: resolver failed ,\"%V\" (%i: %s))",
			&ctx->name, ctx->state,
			ngx_resolver_strerror(ctx->state));

		goto end;
	}

#if (nginx_version) >= 1005008
	if (urcf->max_fails) {
		ngx_memcpy(urcf->temp_peers, urcf->peers, resolved_num_orig * sizeof(ngx_upstream_jdomain_peer_t));
		temp_peers_from = 0;
	} else {
		/* max_fails feature is not enabled, skip searching in urcf->temp_peers */
		temp_peers_from = resolved_num_orig;
	}
#endif
	urcf->resolved_num = 0;

	for (i = 0; i < ctx->naddrs; i++) {
		socklen_t socklen;

#if (nginx_version) < 1005008
		socklen = sizeof(struct sockaddr);
#else
		socklen = ctx->addrs[i].socklen;
#endif

		peer = &urcf->peers[urcf->resolved_num];
		addr = &peer->sockaddr;

		peer->fails = 0;
		peer->checked = 0;
		peer->socklen = socklen;
#if (nginx_version) < 1005008
		((struct sockaddr_in*)addr)->sin_family = AF_INET;
		((struct sockaddr_in*)addr)->sin_addr.s_addr = ctx->addrs[i];
		((struct sockaddr_in*)addr)->sin_port = htons(urcf->default_port);
#else
		ngx_memcpy(addr, ctx->addrs[i].sockaddr, socklen);

		switch (addr->sa_family) {
		case AF_INET6:
			((struct sockaddr_in6*)addr)->sin6_port = htons((u_short) urcf->default_port);
			break;
		default:
			((struct sockaddr_in*)addr)->sin_port = htons((u_short) urcf->default_port);
		}

		for (j = temp_peers_from; j < resolved_num_orig; j++) {
			ngx_upstream_jdomain_peer_t *temp_peer = &urcf->temp_peers[j];
			struct sockaddr *temp_addr = &temp_peer->sockaddr;
			if (temp_peer->socklen == socklen && !ngx_memcmp(temp_addr, addr, socklen)) {
				/* partially copy data for the peer from the previous peer instance */
				peer->fails = temp_peer->fails;
				peer->checked = temp_peer->checked;

				if (j != temp_peers_from) {
					/* swap two peers in urcf->temp_peers to skip found peers on the next records of ctx->addrs */
					ngx_upstream_jdomain_peer_t temp_peer_copy = *temp_peer;
					*temp_peer = urcf->temp_peers[temp_peers_from];
					urcf->temp_peers[temp_peers_from] = temp_peer_copy;
				}
				temp_peers_from++;
				break;
			}
		}
#endif
		peer->name.data = peer->ipstr;
		peer->name.len = 
#if (nginx_version) <= 1005002
			ngx_sock_ntop(addr, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);
#else
			ngx_sock_ntop(addr, peer->socklen, peer->ipstr, NGX_SOCKADDR_STRLEN, 1);
#endif

		urcf->resolved_num++;

		if( urcf->resolved_num >= urcf->resolved_max_ips)
			break;
	}

	ngx_upstream_jdomain_dump_peers(urcf, r->log);

end:
	next_resolve = ngx_upstream_jdomain_next_resolve(ctx);
	ngx_resolve_name_done(ctx);

	ngx_upstream_jdomain_timer_restart(urcf, next_resolve);
	urcf->resolved_access = ngx_time();
	urcf->resolved_status = NGX_JDOMAIN_STATUS_DONE;
}

ngx_int_t
ngx_upstream_jdomain_init_process(ngx_cycle_t *cycle, ngx_upstream_jdomain_main_conf_t *jmcf)
{
	ngx_upstream_jdomain_srv_conf_t	*urcf;
	ngx_pool_t *temp_pool;

	if (jmcf == NULL) {
		return NGX_OK;
	}

	ngx_time_update();

	temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cycle->log);
	if (temp_pool == NULL) {
		return NGX_ERROR;
	}

	for (urcf = jmcf->urcf_first; urcf != NULL; urcf = urcf->next) {
		ngx_upstream_jdomain_load_peers(urcf, temp_pool, cycle->log);

		ngx_upstream_jdomain_resolve_start(urcf,
			urcf->resolver, urcf->resolver_timeout, cycle->log, 1);
	}
	ngx_destroy_pool(temp_pool);

	return NGX_OK;
}


#if (NGX_SSL)

ngx_int_t
ngx_upstream_set_jdomain_peer_session(ngx_peer_connection_t *pc,
	void *data)
{
	ngx_upstream_jdomain_peer_data_t  *urpd = data;

	ngx_int_t                     rc;
	ngx_ssl_session_t            *ssl_session;
	ngx_upstream_jdomain_peer_t  *peer;

	peer = &urpd->conf->peers[urpd->current];

	ssl_session = peer->ssl_session;

	rc = ngx_ssl_set_session(pc->connection, ssl_session);

	return rc;
}

void
ngx_upstream_save_jdomain_peer_session(ngx_peer_connection_t *pc,
	void *data)
{
	ngx_upstream_jdomain_peer_data_t  *urpd = data;

	ngx_ssl_session_t            *old_ssl_session, *ssl_session;
	ngx_upstream_jdomain_peer_t  *peer;

	ssl_session = ngx_ssl_get_session(pc->connection);

	if (ssl_session == NULL) {
		return;
	}

	peer = &urpd->conf->peers[urpd->current];

	old_ssl_session = peer->ssl_session;
	peer->ssl_session = ssl_session;


	if (old_ssl_session) {

		ngx_ssl_free_session(old_ssl_session);
	}
}

#endif
