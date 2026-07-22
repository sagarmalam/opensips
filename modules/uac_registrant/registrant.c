/*
 * registrant module
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2011-02-11  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../timer.h"
#include "../../db/db.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_authenticate.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_min_expires.h"
#include "../../parser/parse_expires.h"
#include "../uac_auth/uac_auth.h"
#include "../../lib/digest_auth/digest_auth.h"
#include "../../globals.h"
#include "reg_records.h"
#include "reg_db_handler.h"
#include "clustering.h"

/* Function declarations */
static int extract_identifier(const str *uri, str *identifier);

#define UAC_REGISTRAR_URI_PARAM              1
#define UAC_PROXY_URI_PARAM                  2
#define UAC_AOR_URI_PARAM                    3
#define UAC_THIRD_PARTY_REGISTRANT_URI_PARAM 4
#define UAC_AUTH_USER_PARAM                  5
#define UAC_AUTH_PASSWORD_PARAM              6
#define UAC_CONTACT_URI_PARAM                7
#define UAC_CONTACT_PARAMS_PARAM             8
#define UAC_EXPIRES_PARAM                    9
#define UAC_FORCED_SOCKET_PARAM             10
#define UAC_MAX_PARAMS_NO                   11

#define UAC_REG_NOT_REGISTERED_STATE    "NOT_REGISTERED_STATE"
#define UAC_REG_REGISTERING_STATE       "REGISTERING_STATE"
#define UAC_REG_AUTHENTICATING_STATE    "AUTHENTICATING_STATE"
#define UAC_REG_REGISTERED_STATE        "REGISTERED_STATE"
#define UAC_REG_REGISTER_TIMEOUT_STATE  "REGISTER_TIMEOUT_STATE"
#define UAC_REG_INTERNAL_ERROR_STATE    "INTERNAL_ERROR_STATE"
#define UAC_REG_WRONG_CREDENTIALS_STATE "WRONG_CREDENTIALS_STATE"
#define UAC_REG_REGISTRAR_ERROR_STATE   "REGISTRAR_ERROR_STATE"
#define UAC_REG_UNREGISTERING_STATE		"UNREGISTERING_STATE"
#define UAC_REG_AUTHENTICATING_UNREGISTER_STATE	"AUTHENTICATING_UNREGISTER_STATE"
#define UAC_REG_UNREGISTERED_STATE	"UNREGISTERED_STATE"

const str uac_reg_state[]={
	str_init(UAC_REG_NOT_REGISTERED_STATE),
	str_init(UAC_REG_REGISTERING_STATE),
	str_init(UAC_REG_AUTHENTICATING_STATE),
	str_init(UAC_REG_REGISTERED_STATE),
	str_init(UAC_REG_REGISTER_TIMEOUT_STATE),
	str_init(UAC_REG_INTERNAL_ERROR_STATE),
	str_init(UAC_REG_WRONG_CREDENTIALS_STATE),
	str_init(UAC_REG_REGISTRAR_ERROR_STATE),
	str_init(UAC_REG_UNREGISTERING_STATE),
	str_init(UAC_REG_AUTHENTICATING_UNREGISTER_STATE),
	str_init(UAC_REG_UNREGISTERED_STATE),
};

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);

void timer_check(unsigned int ticks, void* hash_counter);
void handle_shtag_change(str *tag_name, int state, int c_id, void *param);

static mi_response_t *mi_reg_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reg_list_record(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reg_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reg_reload_record(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reg_enable(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reg_disable(const mi_params_t *params,
								struct mi_handler *async_hdl);

int send_register(unsigned int hash_index, reg_record_t *rec, str *auth_hdr);
int send_unregister(unsigned int hash_index, reg_record_t *rec, str *auth_hdr,
	unsigned int all_contacts);


/** Global variables */

uac_auth_api_t uac_auth_api;

unsigned int default_expires = 3600;
unsigned int timer_interval = 100;

reg_table_t reg_htable = NULL;
unsigned int reg_hsize = 1;
unsigned int run_db_custom_updates = 0;
unsigned int enable_custom_user_agent = 0;
unsigned int auto_disable_on_failure = 0;
/* When enabled, a 503/408 final reply clears the pinned destination
 * (forced_to_su) so the next REGISTER re-resolves the FQDN/SRV and can
 * fail over to another server. A timeout/no-response (FAKED_REPLY) always
 * clears the pin regardless of this flag. Disabled by default to preserve
 * the "keep re-registering on the same server for FQDNs" behavior. */
unsigned int enable_failover = 0;

static str db_url = {NULL, 0};

static str register_method = str_init("REGISTER");
static str contact_hdr = str_init("Contact: ");
static str expires_hdr = str_init("Expires: ");
static str expires_param = str_init(";expires=");
static str user_agent_hdr = str_init("User-Agent: ");
static str true_test = str_init("true");
static str false_test = str_init("false");

char extra_hdrs_buf[1024];
static str extra_hdrs={extra_hdrs_buf, 1024};

static char custom_ua_buf[512];
static str custom_ua_hdr = {custom_ua_buf, 0};


/* TM bind */
struct tm_binds tmb;


typedef struct reg_tm_cb {
	unsigned int hash_index;
	reg_record_t *uac;
}reg_tm_cb_t;

/** Exported parameters */
static const param_export_t params[]= {
	{"hash_size",		INT_PARAM,			&reg_hsize},
	{"run_db_custom_updates",		INT_PARAM,			&run_db_custom_updates},
	{"auto_disable_on_failure",	INT_PARAM,			&auto_disable_on_failure},
	{"enable_failover",	INT_PARAM,			&enable_failover},
	{"default_expires",	INT_PARAM,			&default_expires},
	{"timer_interval",	INT_PARAM,			&timer_interval},
	{"enable_clustering",	INT_PARAM,			&enable_clustering},
	{"db_url",		STR_PARAM,			&db_url.s},
	{"table_name",		STR_PARAM,			&reg_table_name.s},
	{"registrar_column",	STR_PARAM,			&registrar_column.s},
	{"proxy_column",	STR_PARAM,			&proxy_column.s},
	{"aor_column",		STR_PARAM,			&aor_column.s},
	{"third_party_registrant_column",STR_PARAM,&third_party_registrant_column.s},
	{"username_column",	STR_PARAM,		&username_column.s},
	{"password_column",	STR_PARAM,		&password_column.s},
	{"binding_URI_column",	STR_PARAM,		&binding_URI_column.s},
	{"binding_params_column",	STR_PARAM,	&binding_params_column.s},
	{"expiry_column",	STR_PARAM,		&expiry_column.s},
	{"forced_socket_column",	STR_PARAM,	&forced_socket_column.s},
	{"cluster_shtag_column",	STR_PARAM,	&cluster_shtag_column.s},
	{"state_column",	STR_PARAM,		&state_column.s},
	{"user_agent_column",	STR_PARAM,	&user_agent_column.s},
	{"enable_custom_user_agent",	INT_PARAM,	&enable_custom_user_agent},
	{0,0,0}
};


/** MI commands */
static const mi_export_t mi_cmds[] = {
	{ "reg_list", 0, 0, 0, {
		{mi_reg_list, {0}},
		{mi_reg_list_record, {"aor", "contact", "registrar", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "reg_reload", 0, 0, 0, {
		{mi_reg_reload, {0}},
		{mi_reg_reload_record, {"aor", "contact", "registrar", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "reg_enable", 0, 0, 0, {
		{mi_reg_enable, {"aor", "contact", "registrar", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "reg_disable", 0, 0, 0, {
		{mi_reg_disable, {"aor", "contact", "registrar", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",       DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "uac_auth", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "enable_clustering", get_deps_clusterer},
		{ NULL, NULL },
	},
};

/** Module interface */
struct module_exports exports= {
	"uac_registrant",		/* module name */
	MOD_TYPE_DEFAULT,       /* class of this module */
	MODULE_VERSION,			/* module version */
	DEFAULT_DLFLAGS,		/* dlopen flags */
	0,						/* load function */
	&deps,					/* OpenSIPS module dependencies */
	0,					/* exported functions */
	0,					/* exported async functions */
	params,				/* exported parameters */
	NULL,				/* exported statistics */
	mi_cmds,			/* exported MI functions */
	NULL,				/* exported pseudo-variables */
	0,					/* exported transformations */
	0,					/* extra processes */
	0,					/* module pre-initialization function */
	mod_init,			/* module initialization function */
	(response_function) NULL,	/* response handling function */
	(destroy_function) mod_destroy,	/* destroy function */
	child_init,			/* per-child init function */
	0					/* reload confirm function */
};


/** Module init function */
static int mod_init(void)
{
	unsigned int _timer;
	int *param;

	if(load_uac_auth_api(&uac_auth_api)<0){
		LM_ERR("Failed to load uac_auth api\n");
		return -1;
	}

	/* load all TM stuff */
	if(load_tm_api(&tmb)==-1) {
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	if (enable_clustering && ureg_init_cluster( handle_shtag_change )<0) {
		LM_ERR("failed to initialized clustering support\n");
		return -1;
	}

	if(default_expires<15){
		LM_ERR("default_expires to short: [%d]<15\n", default_expires);
		return -1;
	}
	if(timer_interval<10){
		LM_ERR("timer_interval to short: [%d]<10\n", timer_interval);
		return -1;
	}
	if(reg_hsize<1 || reg_hsize>20) {
		LM_ERR("Wrong hash size: 20<[%d]<1\n", reg_hsize);
	}
	reg_hsize = 1<<reg_hsize;

	if(init_reg_htable()<0) {
		LM_ERR("Failed to initialize registrant hash table\n");
		return -1;
	}

	reg_table_name.len = strlen(reg_table_name.s);
	registrar_column.len = strlen(registrar_column.s);
	proxy_column.len = strlen(proxy_column.s);
	aor_column.len = strlen(aor_column.s);
	third_party_registrant_column.len =
		strlen(third_party_registrant_column.s);
	username_column.len = strlen(username_column.s);
	password_column.len = strlen(password_column.s);
	binding_URI_column.len = strlen(binding_URI_column.s);
	binding_params_column.len = strlen(binding_params_column.s);
	expiry_column.len = strlen(expiry_column.s);
	forced_socket_column.len = strlen(forced_socket_column.s);
	cluster_shtag_column.len = strlen(cluster_shtag_column.s);
	state_column.len = strlen(state_column.s);
	init_db_url(db_url , 0 /*cannot be null*/);
	if (init_reg_db(&db_url) != 0) {
		LM_ERR("failed to initialize the DB support\n");
		return -1;
	}

	/* allocate a shm variable to keep the counter used by the timer
	 * routine - it must be shared as the routine get executed
	 * in different processes */
	if (NULL==(param=(int*) shm_malloc(sizeof(int)))) {
		LM_ERR("cannot allocate shm memory for keepalive counter\n");
		return -1;
	}
	*param = 0;

	_timer = timer_interval/reg_hsize;
	if (_timer) {
		register_timer("uac_reg_check", timer_check, (void*)(long)param, _timer,
			TIMER_FLAG_DELAY_ON_DELAY);
	} else {
		LM_ERR("timer_interval=[%d] MUST be at least as big as reg_hsize=[%d]\n",
			timer_interval, reg_hsize);
		return -1;
	}

	return 0;
}


static void mod_destroy(void)
{
	destroy_reg_htable();

	LM_DBG("done\n");
	return;
}

static int child_init(int rank)
{
	if (db_url.s != NULL && connect_reg_db(&db_url)) {
		LM_ERR("failed to connect to db (rank=%d)\n",rank);
		return -1;
	}
	return 0;
}


struct reg_tm_cback_data {
	struct cell *t;
	struct tmcb_params *ps;
	time_t now;
	reg_tm_cb_t *cb_param;
};

int get_cur_time_s(str *str_now, time_t now)
{
	char *p;
	int len;

	p = int2str((unsigned long)(now), &len);
	if (p && len>0) {
		str_now->s = (char *)pkg_malloc(len);
		if (str_now->s) {
			memcpy(str_now->s, p, len);
			str_now->len = len;
		} else {
			LM_ERR("oom\n");
			return -1;
		}
	} else {
		return -1;
	}

	return 0;
}

int run_reg_tm_cback(void *e_data, void *data, void *r_data)
{
	struct sip_msg *msg;
	str msg_body;
	int statuscode = 0;
	unsigned int exp = 0;
	exp_body_t *header_exp = NULL;
	unsigned int bindings_counter = 0;
	reg_record_t *rec = (reg_record_t*)e_data;
	struct hdr_field *c_ptr, *head_contact;
	struct uac_credential crd;
	contact_t *contact;
	struct authenticate_body *auth = NULL;
	static struct authenticate_nc_cnonce auth_nc_cnonce;
	struct digest_auth_response response;
	str *new_hdr;
	struct reg_tm_cback_data *tm_cback_data = (struct reg_tm_cback_data*)data;
	struct cell *t;
	struct tmcb_params *ps;
	time_t now;
	str str_now = {NULL, 0};
	reg_tm_cb_t *cb_param;

	cb_param = tm_cback_data->cb_param;
	if (rec!=cb_param->uac) {
		/* no action on current list elemnt */
		return 0; /* continue list traversal */
	}

	t = tm_cback_data->t;
	ps = tm_cback_data->ps;
	now = tm_cback_data->now;

	reg_print_record(rec);

	/* Clear the pinned destination so the next REGISTER re-resolves the
	 * FQDN/SRV and can fail over to another server:
	 *   - always on FAKED_REPLY (timeout / no response), and
	 *   - on a 503 or 408 final reply when failover is enabled.
	 * Otherwise, pin the destination that was just used (FQDN stickiness). 
	 * Changes For SRV Failover
	 * TRAG-15815*/
	if (ps->rpl==FAKED_REPLY)
		memset(&rec->td.forced_to_su, 0, sizeof(union sockaddr_union));
	else if (rec->td.forced_to_su.s.sa_family == AF_UNSPEC || (enable_failover && (t->uac[0].last_received == 503 || t->uac[0].last_received == 408)))
		rec->td.forced_to_su = t->uac[0].request.dst.to;

	statuscode = ps->code;
	switch(statuscode) {
	case 200:
		if(rec->td.send_sock ){
       			LM_DBG("Local Port used to send register request =[%d]\n", rec->td.send_sock->last_local_real_port);
			rec->local_src_port=rec->td.send_sock->last_local_real_port;
		} else {
			LM_DBG("rec or rec->td.send_sock does not existing. So cannot set local port\n");
			rec->local_src_port=0;
		}
		msg = ps->rpl;
		if(msg==FAKED_REPLY) {
			LM_ERR("FAKED_REPLY\n");
			goto done;
		}
		if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
			LM_ERR("failed to parse headers\n");
			goto done;
		}
	// ******* Changes made for registrant- invalid  reasons with 'ok' response ****
		str*  msg_rep_reason =&msg->first_line.u.reply.reason;
//      LM_DBG(" Reply-reason:%s\n",msg_rep_reason->s);
		if(strncasecmp(msg_rep_reason->s,"ok",msg_rep_reason->len)!=0)
		{
				if(strncasecmp(msg_rep_reason->s,"authorization failure",msg_rep_reason->len)==0)
				{
						rec->state = WRONG_CREDENTIALS_STATE;
						LM_WARN(" State changed to WRONG_CREDENTIALS due to :%s\n",msg_rep_reason->s);
				}
				else
				{
						rec->state = UNREGISTERED_STATE;
						LM_WARN(" State Changed  to UNREGISTERED due to :%s\n",msg_rep_reason->s);
				}
				break;
		}
		//*************

	if(rec->expires==0){
		rec->state = UNREGISTERED_STATE;
		break;
	}
				
		if (msg->contact) {
			c_ptr = msg->contact;
			while(c_ptr) {
				if (c_ptr->type == HDR_CONTACT_T) {
					if (!c_ptr->parsed && (parse_contact(c_ptr)<0)) {
						LM_ERR("failed to parse Contact body\n");
						goto done;
					}
				}
				c_ptr = c_ptr->next;
			}
		} else {
			switch(rec->state) {
			case UNREGISTERING_STATE:
			case AUTHENTICATING_UNREGISTER_STATE:
				if (!(rec->flags&REG_ENABLED)) {
					/* succesfully unREGISTERED */
					rec->state = NOT_REGISTERED_STATE;
					rec->registration_timeout = 0;
				} else {
					/* registrant got enabled while waiting for a reply to
					 * a previous unregister */
					if (get_cur_time_s(&str_now, now) < 0) {
						LM_ERR("Failed to get current time string\n");
						goto done;
					}
					new_call_id_ftag_4_record(rec, &str_now);
					if(send_register(cb_param->hash_index, rec, NULL)==1) {
						rec->last_register_sent = now;
						rec->state = REGISTERING_STATE;
					} else {
						rec->registration_timeout = now + rec->expires - timer_interval;
						rec->state = INTERNAL_ERROR_STATE;
					}
				}

				break;
			default:
				LM_ERR("No contact header in received 200ok in state [%d] So we will not extract expires from contact header\n",
					rec->state);
				goto setexpires;
			}
			break; /* done with 200ok handling */
		}
			
				

		if (rec->flags&FORCE_SINGLE_REGISTRATION &&
			(rec->state == REGISTERING_STATE ||
			 rec->state == AUTHENTICATING_STATE)) {
			head_contact = msg->contact;
			contact = ((contact_body_t*)msg->contact->parsed)->contacts;
			while (contact) {
				bindings_counter++;
				if (contact->next == NULL) {
					contact = NULL;
					c_ptr = head_contact->next;
					while(c_ptr) {
						if (c_ptr->type == HDR_CONTACT_T) {
							head_contact = c_ptr;
							contact = ((contact_body_t*)c_ptr->parsed)->contacts;
							break;
						}
						c_ptr = c_ptr->next;
					}
				} else {
					contact = contact->next;
				}
			}
			if (bindings_counter>1) {
				LM_DBG("got [%d] bindings\n", bindings_counter);
				if(send_unregister(cb_param->hash_index, rec, NULL, 1)==1) {
					rec->state = UNREGISTERING_STATE;
				} else {
					rec->state = INTERNAL_ERROR_STATE;
				}
				break;
			}
		}
			
		if(strncmp(rec->server_expiry.s,"false",rec->server_expiry.len)==0){
			LM_ERR("We will not respect expires from server side because it is disabled for aor [%.*s] ",rec->td.rem_uri.len, rec->td.rem_uri.s);
			goto setexpires;
		}

		head_contact = msg->contact;
		contact = ((contact_body_t*)msg->contact->parsed)->contacts;
		while (contact) {
			/* Check both full URI match and identifier match */
			str contact_id = {0}, rec_id = {0};
			int id_match = 0;
			
			/* First try exact match */
			if (contact->uri.len == rec->contact_uri.len &&
				contact->uri.s && rec->contact_uri.s &&
				strncmp(contact->uri.s, rec->contact_uri.s, contact->uri.len) == 0) {
				id_match = 1;
			} else {
				/* Try to match by identifier */
				if (extract_identifier(&contact->uri, &contact_id) == 0 &&
					extract_identifier(&rec->contact_uri, &rec_id) == 0 &&
					contact_id.s && rec_id.s) {
					if (contact_id.len == rec_id.len &&
						contact_id.len > 0 &&
						strncmp(contact_id.s, rec_id.s, contact_id.len) == 0) {
						id_match = 1;
					}
				}
			}
			
			if (id_match) {
				if (contact->expires && contact->expires->body.len) {
					if (str2int(&contact->expires->body, &exp) < 0) {
						LM_ERR("Unable to extract expires from [%.*s]"
							" for binding [%.*s]\n",
							contact->expires->body.len,
							contact->expires->body.s,
							contact->uri.len, contact->uri.s);
					}
				}
				break;
			}

			/* get the next contact */
			if (contact->next == NULL) {
				contact = NULL;
				c_ptr = head_contact->next;
				while(c_ptr) {
					if (c_ptr->type == HDR_CONTACT_T) {
						head_contact = c_ptr;
						contact = ((contact_body_t*)c_ptr->parsed)->contacts;
						break;
					}
					c_ptr = c_ptr->next;
				}
			} else {
				contact = contact->next;
			}
		}
		setexpires:
		// if there is no expires in contact, try parse expires from header
		if (exp == 0 && msg->expires) {
			if (parse_expires(msg->expires) < 0) {
				LM_ERR("failed to parse Expires header\n");
			} else {
				header_exp = (exp_body_t*)msg->expires->parsed;
				exp = header_exp->val;
			}
		}

		if (!(rec->flags&REG_ENABLED)) {
			if (rec->state==REGISTERING_STATE ||
				rec->state==AUTHENTICATING_STATE) {
				/* registrant got disabled while waiting for a reply to
				 * a previous register */
				if(send_unregister(cb_param->hash_index, rec, NULL, 0)==1) {
					rec->state = UNREGISTERING_STATE;
				} else {
					rec->state = INTERNAL_ERROR_STATE;
				}
			} else {
				/* succesfully unREGISTERED */
				rec->state = NOT_REGISTERED_STATE;
				rec->registration_timeout = 0;
			}
		} else {
			if (rec->state == UNREGISTERING_STATE ||
				rec->state == AUTHENTICATING_UNREGISTER_STATE) {
				/* registrant got enabled while waiting for a reply to
				 * a previous unregister */
				if (get_cur_time_s(&str_now, now) < 0) {
					LM_ERR("Failed to get current time string\n");
					goto done;
				}
				new_call_id_ftag_4_record(rec, &str_now);
				if(send_register(cb_param->hash_index, rec, NULL)==1) {
					rec->last_register_sent = now;
					rec->state = REGISTERING_STATE;
				} else {
					rec->registration_timeout = now + rec->expires - timer_interval;
					rec->state = INTERNAL_ERROR_STATE;
				}
			} else {
				/* succesfully REGISTERED */
				rec->state = REGISTERED_STATE;
				if (exp) rec->expires = exp;
				if (rec->expires <= timer_interval) {
					LM_ERR("Please decrease timer_interval=[%u]"
						" - imposed server expires [%u] to small for AOR=[%.*s]\n",
						timer_interval, rec->expires,
						rec->td.rem_uri.len, rec->td.rem_uri.s);
				}
				rec->registration_timeout = now + rec->expires - timer_interval;
			}
		}

		break;
	case WWW_AUTH_CODE:
	case PROXY_AUTH_CODE:
		msg = ps->rpl;
		if(msg==FAKED_REPLY) {
			LM_ERR("FAKED_REPLY\n");
			goto done;
		}

		if (rec->auth_user.s==NULL || rec->auth_user.len==0 ||
			rec->auth_password.s==NULL || rec->auth_password.len==0) {
			LM_ERR("Credentials not provisioned\n");
			rec->state = WRONG_CREDENTIALS_STATE;
			rec->registration_timeout = 0;
			/* action successfully completed on current list element */
			return 1; /* exit list traversal */
		}

		if (statuscode==WWW_AUTH_CODE) {
			parse_www_authenticate_header(msg,
			    DAUTH_AHFM_ANYSUP, &auth);
		} else if (statuscode==PROXY_AUTH_CODE) {
			parse_proxy_authenticate_header(msg,
			    DAUTH_AHFM_ANYSUP, &auth);
		}
		if (auth == NULL) {
			LM_ERR("Unable to extract authentication info\n");
			goto done;
		}
		LM_DBG("flags=[%d] realm=[%.*s] domain=[%.*s] nonce=[%.*s]"
			" opaque=[%.*s] qop=[%.*s]\n",
			auth->flags,
			auth->realm.len, auth->realm.s,
			auth->domain.len, auth->domain.s,
			auth->nonce.len, auth->nonce.s,
			auth->opaque.len, auth->opaque.s,
			auth->qop.len, auth->qop.s);

		switch(rec->state) {
		case REGISTERING_STATE:
		case UNREGISTERING_STATE:
			break;
		case AUTHENTICATING_STATE:
		case AUTHENTICATING_UNREGISTER_STATE:
			/* We already sent an authenticated REGISTER and we are still challanged! */
			LM_WARN("Wrong credentials for [%.*s]\n",
				rec->td.rem_uri.len, rec->td.rem_uri.s);
			rec->state = WRONG_CREDENTIALS_STATE;
			rec->registration_timeout = 0;
			/* action successfully completed on current list element */
			return 1; /* exit list traversal */
		default:
			LM_ERR("Unexpected [%d] notification cb in state [%d]\n",
				statuscode, rec->state);
			goto done;
		}

		/* perform authentication */
		if (auth->realm.s && auth->realm.len) {
			crd.auth_data.realm = auth->realm;
		} else {
			LM_ERR("No realm found\n");
			goto done;
		}
		crd.auth_data.user = rec->auth_user;
		crd.auth_data.passwd = rec->auth_password;

		if ((auth->flags & QOP_AUTH_INT) && get_body(msg, &msg_body) < 0) {
			LM_ERR("Failed to get message body\n");
			goto done;
		}

		memset(&auth_nc_cnonce, 0, sizeof(struct authenticate_nc_cnonce));
		if (uac_auth_api._do_uac_auth(&msg_body, &register_method,
		    &rec->td.rem_target, &crd, auth, &auth_nc_cnonce, &response) != 0) {
			LM_ERR("Failed in do_uac_auth()\n");
			goto done;
		}
		new_hdr = uac_auth_api._build_authorization_hdr(statuscode, &rec->td.rem_target,
					&crd, auth, &auth_nc_cnonce, &response);
		if (!new_hdr) {
			LM_ERR("failed to build authorization hdr\n");
			goto done;
		}
		switch(rec->state) {
		case REGISTERING_STATE:
			if(send_register(cb_param->hash_index, rec, new_hdr)==1) {
				rec->state = AUTHENTICATING_STATE;
			} else {
				rec->state = INTERNAL_ERROR_STATE;
			}
			break;
		case UNREGISTERING_STATE:
			if(send_unregister(cb_param->hash_index, rec, new_hdr, 0)==1) {
				rec->state = AUTHENTICATING_UNREGISTER_STATE;
			} else {
				rec->state = INTERNAL_ERROR_STATE;
			}
			break;
		default:
			LM_ERR("Unexpected [%d] notification cb in state [%d]\n",
				statuscode, rec->state);
			goto done;
		}
		pkg_free(new_hdr->s);
		new_hdr->s = NULL; new_hdr->len = 0;
		break;

	case 423: /* Interval Too Brief */
		msg = ps->rpl;
		if(msg==FAKED_REPLY) {
			LM_ERR("FAKED_REPLY\n");
			goto done;
		}
		if (0 == parse_min_expires(msg)) {
			if(msg && msg->min_expires && msg->min_expires->parsed){
				rec->expires = (unsigned int)(long)msg->min_expires->parsed;
			} else {
				rec->expires = 3600;
				LM_ERR("Got 423 but No Min Expires header\n");
			}
			if(send_register(cb_param->hash_index, rec, NULL)==1)
				rec->state = REGISTERING_STATE;
			else
				rec->state = INTERNAL_ERROR_STATE;
		} else {
			rec->state = REGISTRAR_ERROR_STATE;
			rec->registration_timeout = now + rec->expires - timer_interval;
		}
		break;

	case 408: /* Interval Too Brief */
		rec->state = REGISTER_TIMEOUT_STATE;
		rec->registration_timeout = now + rec->expires - timer_interval;
		break;

	default:
		if(statuscode<400 && statuscode>=300) {
			LM_ERR("Redirection not implemented yet\n");
			rec->state = INTERNAL_ERROR_STATE;
		} else {
			/* we got an error from the server */
			rec->state = REGISTRAR_ERROR_STATE;
			rec->registration_timeout = now + rec->expires - timer_interval;

		}
	}
	if(run_db_custom_updates){
		reg_update_db_state(rec);
	}
	/* action successfully completed on current list element */
	return 1; /* exit list traversal */
done:
	rec->state = INTERNAL_ERROR_STATE;
	rec->registration_timeout = now + rec->expires;
	if(run_db_custom_updates){
		reg_update_db_state(rec);
	}	
	return -1; /* exit list traversal */
}



void reg_tm_cback(struct cell *t, int type, struct tmcb_params *ps)
{
	reg_tm_cb_t *cb_param;
	int statuscode = 0;
	int ret;
	time_t now;
	struct reg_tm_cback_data tm_cback_data;

	if(ps==NULL || ps->rpl==NULL) {
		LM_ERR("wrong ps parameter\n");
		return;
	}
	if(ps->param==NULL || *ps->param==NULL) {
		LM_ERR("null callback parameter\n");
		return;
	}
	cb_param = (reg_tm_cb_t *)*ps->param;
	if(cb_param->uac == NULL) {
		LM_ERR("null record\n");
		return;
	}
	statuscode = ps->code;
	now = time(0);
	LM_DBG("tm [%p] notification cb for %s [%d] reply at [%d]\n",
			t, (ps->rpl==FAKED_REPLY)?"FAKED_REPLY":"",
			statuscode, (unsigned int)now);

	if(statuscode<200) return;

	/* Initialize slinkedl run traversal data */
	tm_cback_data.t = t;
    tm_cback_data.ps = ps;
    tm_cback_data.cb_param = cb_param;
	tm_cback_data.now = now;

	lock_get(&reg_htable[cb_param->hash_index].lock);
	ret = slinkedl_traverse(reg_htable[cb_param->hash_index].p_list,
						&run_reg_tm_cback, (void*)&tm_cback_data, NULL);
	lock_release(&reg_htable[cb_param->hash_index].lock);

	if (ret==0) {
		LM_ERR("record [%p] not found on hash index [%d]\n",
		cb_param->uac, cb_param->hash_index);
	}

	return;
}


int send_register(unsigned int hash_index, reg_record_t *rec, str *auth_hdr)
{
	int result, expires_len;
	reg_tm_cb_t *cb_param;
	char *p, *expires;

	/* Allocate space for tm callback params */
	cb_param = shm_malloc(sizeof(reg_tm_cb_t));
	if (!cb_param) {
		LM_ERR("oom\n");
		return -1;
	}
	cb_param->hash_index = hash_index;
	cb_param->uac = rec;

	/* get the string version of expires */
	expires = int2str((unsigned long)(rec->expires), &expires_len);

	p = extra_hdrs.s;
	memcpy(p, contact_hdr.s, contact_hdr.len);
	p += contact_hdr.len;
	*p = '<'; p++;
	memcpy(p, rec->contact_uri.s, rec->contact_uri.len);
	p += rec->contact_uri.len;
	*p = '>'; p++;
	memcpy(p, rec->contact_params.s, rec->contact_params.len);
	p += rec->contact_params.len;
	if (1) {
		/* adding exiration time as a parameter */
		memcpy(p, expires_param.s, expires_param.len);
		p += expires_param.len;
	} else {
		/* adding exiration time as a header */
		memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;
		memcpy(p, expires_hdr.s, expires_hdr.len);
		p += expires_hdr.len;
	}
	memcpy(p, expires, expires_len);
	p += expires_len;
	memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;

	if (auth_hdr) {
		memcpy(p, auth_hdr->s, auth_hdr->len);
		p += auth_hdr->len;
	}
	extra_hdrs.len = (int)(p - extra_hdrs.s);

	LM_DBG("extra_hdrs=[%p][%d]->[%.*s]\n",
		extra_hdrs.s, extra_hdrs.len, extra_hdrs.len, extra_hdrs.s);

	/* Temporarily swap global User-Agent if per-registrant value is set */
	str saved_ua = {NULL, 0};
	int ua_swapped = 0;
	if (rec->user_agent.s && rec->user_agent.len) {
		saved_ua = *user_agent_header;
		memcpy(custom_ua_buf, user_agent_hdr.s, user_agent_hdr.len);
		memcpy(custom_ua_buf + user_agent_hdr.len, rec->user_agent.s,
			rec->user_agent.len);
		custom_ua_hdr.len = user_agent_hdr.len + rec->user_agent.len;
		user_agent_header->s = custom_ua_hdr.s;
		user_agent_header->len = custom_ua_hdr.len;
		ua_swapped = 1;
	}

	if ( !push_new_global_context() ) {

		LM_ERR("failed to alloc new ctx in pkg\n");
		result = 0;

	} else {

		/* reset the new to-be-used CTX */
		memset( current_processing_ctx, 0, context_size(CONTEXT_GLOBAL) );

		/* send the request within the new context */
		result=tmb.t_request_within(
			&register_method,	/* method */
			&extra_hdrs,		/* extra headers*/
			NULL,			/* body */
			&rec->td,		/* dialog structure*/
			reg_tm_cback,		/* callback function */
			(void *)cb_param,	/* callback param */
			osips_shm_free);	/* function to release the parameter */

		pop_pushed_global_context();
	}

	/* Restore original User-Agent */
	if (ua_swapped) {
		user_agent_header->s = saved_ua.s;
		user_agent_header->len = saved_ua.len;
	}

	if (result < 1)
		shm_free(cb_param);

	LM_DBG("result=[%d]\n", result);
	return result;
}

int send_unregister(unsigned int hash_index, reg_record_t *rec, str *auth_hdr,
	unsigned int all_contacts)
{
	int result,expires_len;
	reg_tm_cb_t *cb_param;
	char *p,*expires;

	/* Allocate space for tm callback params */
	cb_param = shm_malloc(sizeof(reg_tm_cb_t));
	if (!cb_param) {
		LM_ERR("oom\n");
		return -1;
	}
	cb_param->hash_index = hash_index;
	cb_param->uac = rec;
	/*There are custom changes in this section which we are not overwriting in 3.4.main*/
    /* get the string version of expires */
	expires = int2str((unsigned long)(rec->expires), &expires_len);
	p = extra_hdrs.s;
	memcpy(p, contact_hdr.s, contact_hdr.len);
	p += contact_hdr.len;
	/**p = '*'; p++;
	memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;*/
	*p = '<'; p++;
	memcpy(p, rec->contact_uri.s, rec->contact_uri.len);
	p += rec->contact_uri.len;
	*p = '>'; p++;
	memcpy(p, rec->contact_params.s, rec->contact_params.len);
	p += rec->contact_params.len;
	if (1) {
		/* adding exiration time as a parameter */
		memcpy(p, expires_param.s, expires_param.len);
		p += expires_param.len;
	} else {
		/* adding exiration time as a header */
		memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;
		memcpy(p, expires_hdr.s, expires_hdr.len);
		p += expires_hdr.len;
	}
	//Hardcoding expires to 0 for unregister packet. These chnages were not there in 3.1 version but added as custom in 3.4
	// memcpy(p, expires, expires_len);
	// p += expires_len;
	memcpy(p, "0", 1); 
        p++;
	////////////////////////////////////////////
	memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;
	/* adding exires header */
	memcpy(p, expires_hdr.s, expires_hdr.len);
	p += expires_hdr.len;
	memcpy(p, "0", 1);
        p++;
	memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;
	/*There are custom changes in this section which we are not overwriting in 3.4.main*/

	if (auth_hdr) {
		memcpy(p, auth_hdr->s, auth_hdr->len);
		p += auth_hdr->len;
	}
	extra_hdrs.len = (int)(p - extra_hdrs.s);

	LM_DBG("extra_hdrs=[%p][%d]->[%.*s]\n",
		extra_hdrs.s, extra_hdrs.len, extra_hdrs.len, extra_hdrs.s);

	/* Temporarily swap global User-Agent if per-registrant value is set */
	str saved_ua = {NULL, 0};
	int ua_swapped = 0;
	if (rec->user_agent.s && rec->user_agent.len) {
		saved_ua = *user_agent_header;
		memcpy(custom_ua_buf, user_agent_hdr.s, user_agent_hdr.len);
		memcpy(custom_ua_buf + user_agent_hdr.len, rec->user_agent.s,
			rec->user_agent.len);
		custom_ua_hdr.len = user_agent_hdr.len + rec->user_agent.len;
		user_agent_header->s = custom_ua_hdr.s;
		user_agent_header->len = custom_ua_hdr.len;
		ua_swapped = 1;
	}

	result=tmb.t_request_within(
		&register_method,	/* method */
		&extra_hdrs,		/* extra headers*/
		NULL,			/* body */
		&rec->td,		/* dialog structure*/
		reg_tm_cback,		/* callback function */
		(void *)cb_param,	/* callback param */
		osips_shm_free);	/* function to release the parameter */

	/* Restore original User-Agent */
	if (ua_swapped) {
		user_agent_header->s = saved_ua.s;
		user_agent_header->len = saved_ua.len;
	}

	if (result < 1)
		shm_free(cb_param);

	LM_DBG("result=[%d]\n", result);
	return result;
}

struct timer_check_data {
	time_t now;
	str *s_now;
	int hash_counter;
};

int run_timer_check(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	struct timer_check_data *t_check_data = (struct timer_check_data*)data;
	time_t now = t_check_data->now;
	str *s_now = t_check_data->s_now;
	unsigned int i = t_check_data->hash_counter;

	if (!ureg_cluster_shtag_is_active( &rec->cluster_shtag, rec->cluster_id))
		return 0;
	/* TRAG-15021 */
	if (auto_disable_on_failure && !(rec->flags & REG_ENABLED) &&
		(rec->state == WRONG_CREDENTIALS_STATE ||
		 rec->state == REGISTRAR_ERROR_STATE)) {
		return 0;
	}

	switch(rec->state){
	case REGISTERING_STATE:
	case UNREGISTERING_STATE:
	case UNREGISTERED_STATE:
		break;
	case AUTHENTICATING_STATE:
	case AUTHENTICATING_UNREGISTER_STATE:
		break;
	case WRONG_CREDENTIALS_STATE:
	case REGISTER_TIMEOUT_STATE:
	case INTERNAL_ERROR_STATE:
	case REGISTRAR_ERROR_STATE:
		reg_print_record(rec);
		rec->failed_attempts++;
		if(rec->failed_attempts > 4){
			LM_ERR("Max failed attempts exceeded for rec [%p]\n", rec);
			break;
		}
		if (rec->flags&REG_ENABLED) {
			new_call_id_ftag_4_record(rec, s_now);
			if(send_register(i, rec, NULL)==1) {
				rec->last_register_sent = now;
				rec->state = REGISTERING_STATE;
			} else {
				rec->registration_timeout = now + rec->expires - timer_interval;
				rec->state = INTERNAL_ERROR_STATE;
			}
		} else {
			if(send_unregister(i, rec, NULL, 0)==1) {
				rec->state = UNREGISTERING_STATE;
			} else {
				rec->state = INTERNAL_ERROR_STATE;
			}
		}
		break;
	case REGISTERED_STATE:
		/* check if we need to re-register */
		if (now < rec->registration_timeout) {
			break;
		}
	case NOT_REGISTERED_STATE:
		rec->failed_attempts=0;
		if(rec->expires==0){
			if(send_unregister(i, rec, NULL,0)==1) {
				rec->state = UNREGISTERING_STATE;
			} else {
				rec->state = INTERNAL_ERROR_STATE;
			}
		}else{
		if (rec->flags&REG_ENABLED) {
			if(send_register(i, rec, NULL)==1) {
				rec->last_register_sent = now;
				rec->state = REGISTERING_STATE;
			} else {
				rec->registration_timeout = now + rec->expires - timer_interval;
				rec->state = INTERNAL_ERROR_STATE;
			}
		}
		}
		break;
	default:
		LM_ERR("Unexpected state [%d] for rec [%p]\n", rec->state, rec);
	}

	return 0; /* continue list traversal */
}

void timer_check(unsigned int ticks, void* hash_counter)
{
	unsigned int i=*(unsigned*)(unsigned long*)hash_counter;
	int ret;
	time_t now;
	str str_now = {NULL, 0};
	struct timer_check_data t_check_data;

	*(unsigned*)(unsigned long*)hash_counter = (i+1)%reg_hsize;

	now = time(0);
	if (get_cur_time_s(&str_now, now) < 0) {
		LM_ERR("Failed to get current time string\n");
		return;
	}

	/* Initialize slinkedl run traversal data */
	t_check_data.now = now;
	t_check_data.s_now = &str_now;
	t_check_data.hash_counter = i;

	LM_DBG("checking ... [%d] on htable[%d]\n", (unsigned int)now, i);
	lock_get(&reg_htable[i].lock);
	ret = slinkedl_traverse(reg_htable[i].p_list, &run_timer_check,
							(void*)&t_check_data, NULL);
	if (ret<0) LM_CRIT("Unexpected return code %d\n", ret);
	lock_release(&reg_htable[i].lock);

	if (str_now.s) {pkg_free(str_now.s);}

	return;
}


struct shtag_check_data {
	str *tag;
	int c_id;
};

static int cluster_shtag_check(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	struct shtag_check_data *shtag_data = (struct shtag_check_data*)data;

	LM_DBG("checking record with cluster_id [%d] and shtag [%.*s]\n",
		rec->cluster_id, rec->cluster_shtag.len, rec->cluster_shtag.s);
	if (rec->cluster_id==shtag_data->c_id &&
		rec->cluster_shtag.s && rec->cluster_shtag.len &&
		rec->cluster_shtag.len==shtag_data->tag->len &&
		0==memcmp(rec->cluster_shtag.s, shtag_data->tag->s, shtag_data->tag->len)) {
		/* this record matches the shtag + cluster_id, so we need to de-active it */
		LM_DBG("Moving record to NOT_REGISTERED_STATE\n");
		rec->state = NOT_REGISTERED_STATE;
	}


	return 0;
}


void handle_shtag_change(str *tag_name, int state, int c_id, void *param)
{
	struct shtag_check_data shtag_data;
	int ret, i;

	if (state!=SHTAG_STATE_BACKUP)
		return;

	shtag_data.c_id = c_id;
	shtag_data.tag = tag_name;

	/* a shatg in cluster became backup on local node-> check if
	 * one of our uac reg depends on it */
	LM_DBG("checking for shtag [%.*s] in cluster [%d]\n",
		shtag_data.tag->len, shtag_data.tag->s, shtag_data.c_id);

	for( i=0 ; i<reg_hsize ; i++) {

		lock_get(&reg_htable[i].lock);
		ret = slinkedl_traverse(reg_htable[i].p_list, &cluster_shtag_check,
							(void*)&shtag_data, NULL);
		if (ret<0) LM_CRIT("Unexpected return code %d\n", ret);
		lock_release(&reg_htable[i].lock);

	}
}


/*** MI **/
int run_mi_reg_list(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	int len;
	char* p;
	char cbuf[26];
	struct ip_addr addr;
	mi_item_t *arr_obj_item = (mi_item_t *)data;
	mi_item_t *record_item;

	if (MI_ITEM_IS_ARRAY(arr_obj_item)) {
		record_item = add_mi_object(arr_obj_item, NULL, 0);
		if (!record_item)
			goto error;
	} else
		record_item = arr_obj_item;

	if (add_mi_string(record_item, MI_SSTR("AOR"),
		rec->td.rem_uri.s, rec->td.rem_uri.len) < 0)
		goto error;

	if (add_mi_number(record_item, MI_SSTR("expires"), rec->expires) < 0)
		goto error;

	if (add_mi_string(record_item, MI_SSTR("state"),
		uac_reg_state[rec->state].s, uac_reg_state[rec->state].len) < 0)
		goto error;

	if (add_mi_string_fmt(record_item, MI_SSTR("enabled"),
		"%s", rec->flags&REG_ENABLED ? "yes" : "no") < 0)
		goto error;

	ctime_r(&rec->last_register_sent, cbuf);
	if (add_mi_string(record_item, MI_SSTR("last_register_sent"),
		cbuf, strlen(cbuf) - 1) < 0)
		goto error;

	ctime_r(&rec->registration_timeout, cbuf);
	if (add_mi_string(record_item, MI_SSTR("registration_t_out"),
		cbuf, strlen(cbuf) - 1) < 0)
		goto error;

	if (add_mi_string(record_item, MI_SSTR("registrar"),
		rec->td.rem_target.s, rec->td.rem_target.len) < 0)
		goto error;

	if (add_mi_string(record_item, MI_SSTR("binding"),
		rec->contact_uri.s, rec->contact_uri.len) < 0)
		goto error;

	if(rec->contact_params.s && rec->contact_params.len)
		if (add_mi_string(record_item, MI_SSTR("binding_params"),
			rec->contact_params.s, rec->contact_params.len) < 0)
			goto error;
	//Always print third party registrant value 
	if(rec->third_party_registrant.s && rec->third_party_registrant.len)
		if (add_mi_string(record_item, MI_SSTR("third_party_registrant"),
			rec->third_party_registrant.s, rec->third_party_registrant.len) < 0)
			goto error;

	if (rec->td.obp.s && rec->td.obp.len)
		if (add_mi_string(record_item, MI_SSTR("proxy"),
			rec->td.obp.s, rec->td.obp.len) < 0)
			goto error;

	switch(rec->td.forced_to_su.s.sa_family) {
	case AF_UNSPEC:
		if(rec->dest_ip.s){
			if (add_mi_string(record_item, MI_SSTR("ip"), rec->dest_ip.s,rec->dest_ip.len) < 0)
			goto error;
		}
		break;
	case AF_INET:
	case AF_INET6:
		if (add_mi_string(record_item, MI_SSTR("dst_IP"),
			(rec->td.forced_to_su.s.sa_family==AF_INET)?"IPv4":"IPv6", 4) < 0)
			goto error;
		sockaddr2ip_addr(&addr, &rec->td.forced_to_su.s);
		p = ip_addr2a(&addr);
		if (p == NULL) goto error;
		len = strlen(p);
		rec->dest_ip.s=p;
		rec->dest_ip.len=len;
		if (add_mi_string(record_item, MI_SSTR("ip"), p, len) < 0)
			goto error;
		break;
	default:
		LM_ERR("unexpected sa_family [%d]\n", rec->td.forced_to_su.s.sa_family);
		if (add_mi_string(record_item, MI_SSTR("dst_IP"), "Error", 5) < 0)
			goto error;

		if (add_mi_number(record_item, MI_SSTR("sa_family"),
			rec->td.forced_to_su.s.sa_family) < 0)
			goto error;
	}

	if (rec->cluster_shtag.s && rec->cluster_shtag.len) {
		if (add_mi_string(record_item, MI_SSTR("shtag"),
			rec->cluster_shtag.s, rec->cluster_shtag.len) < 0)
			goto error;
		if (add_mi_number(record_item, MI_SSTR("cluster_id"), rec->cluster_id) < 0)
			goto error;
		}
	if (add_mi_number(record_item, MI_SSTR("local_port"), rec->local_src_port) < 0)
		goto error;

	if (rec->user_agent.s && rec->user_agent.len)
		if (add_mi_string(record_item, MI_SSTR("user_agent"),
			rec->user_agent.s, rec->user_agent.len) < 0)
			goto error;

	/* action successfully completed on current list element */
	return 0; /* continue list traversal */

error:
	LM_ERR("Unable to create reply\n");
	return -1; /* exit list traversal */
}


static mi_response_t *mi_reg_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int i, ret;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *records_arr;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	records_arr = add_mi_array(resp_obj, MI_SSTR("Records"));
	if (!records_arr)
		goto error;

	for(i=0; i<reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);
		ret = slinkedl_traverse(reg_htable[i].p_list,
						&run_mi_reg_list, (void*)records_arr, NULL);
		lock_release(&reg_htable[i].lock);
		if (ret<0) {
			LM_ERR("Unable to create reply\n");
			goto error;
		}
	}

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}

int run_mi_reg_list_record(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	record_coords_t *coords = (record_coords_t *)data;

	// if (!str_strcmp(&coords->contact, &rec->contact_uri) &&
	// 	!str_strcmp(&coords->registrar, &rec->td.rem_target)) {
	if (!str_strcmp(&coords->contact, &rec->third_party_registrant)) {
		return run_mi_reg_list(rec, coords->extra, NULL) ? -1 : 1;
	} else
		return 0;  /* continue search */
}

static mi_response_t *mi_get_coords(const mi_params_t *params, record_coords_t *coords)
{
	if (get_mi_string_param(params, "aor", &coords->aor.s, &coords->aor.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "contact",
		&coords->contact.s, &coords->contact.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "registrar",
		&coords->registrar.s, &coords->registrar.len) < 0)
		return init_mi_param_error();

	return NULL;
}

static mi_response_t *mi_reg_list_record(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *reg_obj;
	record_coords_t coords;
	int rc;
	unsigned int hash_code;

	if ((resp = mi_get_coords(params, &coords)))
		return resp;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	reg_obj = add_mi_object(resp_obj, MI_SSTR("Registrant"));
	if (!reg_obj)
		goto error;

	coords.extra = reg_obj;

	hash_code = core_hash(&coords.aor, NULL, reg_hsize);

	lock_get(&reg_htable[hash_code].lock);
	rc = slinkedl_traverse(reg_htable[hash_code].p_list,
					&run_mi_reg_list_record, &coords, NULL);
	lock_release(&reg_htable[hash_code].lock);

	if (rc < 0)
		goto error;
	else if (rc == 0) {
		free_mi_response(resp);
		return init_mi_error(404, MI_SSTR("No such registrant"));
	}

	return resp;
error:
	free_mi_response(resp);
	return NULL;
}

int run_compare_rec(void *e_data, void *data, void *r_data)
{
	reg_record_t *old_rec = (reg_record_t*)e_data;
	reg_record_t *new_rec = (reg_record_t*)data;

	if (((old_rec->state == REGISTERED_STATE) || (old_rec->state == UNREGISTERED_STATE)) &&
	    (str_strcmp(&old_rec->td.rem_uri, &new_rec->td.rem_uri) == 0) && (str_strcmp(&old_rec->contact_uri, &new_rec->contact_uri) == 0) && (str_strcmp(&old_rec->proxy_uri, &new_rec->proxy_uri) == 0) && (str_strcmp(&old_rec->server_expiry, &new_rec->server_expiry) == 0)) {
		memcpy(new_rec->td.id.call_id.s, old_rec->td.id.call_id.s,
		    new_rec->td.id.call_id.len);
		memcpy(new_rec->td.id.loc_tag.s, old_rec->td.id.loc_tag.s,
		    new_rec->td.id.loc_tag.len);
		new_rec->td.loc_seq.value = old_rec->td.loc_seq.value;
		new_rec->last_register_sent = old_rec->last_register_sent;
		new_rec->registration_timeout = old_rec->registration_timeout;
		memcpy(new_rec->dest_ip.s, old_rec->dest_ip.s,
		    new_rec->dest_ip.len);
		new_rec->dest_ip = old_rec->dest_ip;
		new_rec->local_src_port = old_rec->local_src_port;
		new_rec->td.forced_to_su=old_rec->td.forced_to_su;
		LM_DBG("Inside run compare rec function\n Old Expires=%d , New Expires=%d \n Old Server Expiry= [%.*s] , New Server Expiry=[%.*s]",old_rec->expires,new_rec->expires,old_rec->server_expiry.len,old_rec->server_expiry.s,new_rec->server_expiry.len,new_rec->server_expiry.s);
		
		if (old_rec->state == REGISTERED_STATE){

			if(str_strcmp(&new_rec->server_expiry,&false_test) == 0 && new_rec->expires!=old_rec->expires){
				LM_DBG("In false test");
				new_rec->state = NOT_REGISTERED_STATE;
				new_rec->registration_timeout = old_rec->last_register_sent;
			} else if(str_strcmp(&new_rec->server_expiry,&true_test) == 0 && new_rec->expires==0) {
				LM_DBG("In True Test");
				new_rec->state = NOT_REGISTERED_STATE;
				new_rec->registration_timeout = old_rec->last_register_sent;
			} else {
				new_rec->state = old_rec->state;

			}
		} else {
			if(new_rec->expires!=0) {
				new_rec->state = NOT_REGISTERED_STATE;
				new_rec->registration_timeout = old_rec->last_register_sent;
			} else {
				new_rec->state = old_rec->state;
			}

		}
		new_rec->failed_attempts=0; //In case of reg reload, reset failed attempts
	}
	return 0;
}

int run_find_same_rec(void *e_data, void *data, void *r_data)
{
	reg_record_t *new_rec = (reg_record_t*)e_data;
	int i = *(int*)data;

	slinkedl_traverse(reg_htable[i].p_list, &run_compare_rec, new_rec, NULL);
	return 0;
}

static mi_response_t *mi_reg_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int i;
	int err = 0;

	for(i=0; i<reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);
		if (reg_htable[i].s_list!=NULL) {
			LM_ERR("Found non NULL s_list\n");
			slinkedl_list_destroy(reg_htable[i].s_list);
			reg_htable[i].s_list = NULL;
		}
		reg_htable[i].s_list = slinkedl_init(&reg_alloc, &reg_free);
		if (reg_htable[i].p_list == NULL) {
			LM_ERR("oom while allocating list\n");
			err = 1;
		}
		lock_release(&reg_htable[i].lock);
		if (err) goto error;
	}
	/* Load registrants into the secondary list */
	if(load_reg_info_from_db(REG_DB_RELOAD, NULL) !=0){
		LM_ERR("unable to reload the registrant data\n");
		goto error;
	}
	/* Swap the lists: secondary will become primary */
	for(i=0; i<reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);

		slinkedl_traverse(reg_htable[i].s_list, &run_find_same_rec, &i, NULL);

		slinkedl_list_destroy(reg_htable[i].p_list);
		reg_htable[i].p_list = reg_htable[i].s_list;
		reg_htable[i].s_list = NULL;
		lock_release(&reg_htable[i].lock);
	}

	return init_mi_result_ok();

error:
	for(i=0; i<reg_hsize; i++) {
		lock_get(&reg_htable[i].lock);
		if (reg_htable[i].s_list) slinkedl_list_destroy(reg_htable[i].s_list);
		reg_htable[i].s_list = NULL;
		lock_release(&reg_htable[i].lock);
	}
	return NULL;
}

static mi_response_t *mi_reg_reload_record(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	record_coords_t coords;
	mi_response_t *resp;
	int rc;

	if ((resp = mi_get_coords(params, &coords)))
		return resp;

	rc = load_reg_info_from_db(REG_DB_LOAD_RECORD, &coords);
	if (rc == -2) {
		return init_mi_error(404, MI_SSTR("No such registrant in database"));
	} else if (rc < 0) {
		LM_ERR("unable to reload the registrant data\n");
		return NULL;
	}

	return init_mi_result_ok();
}

int run_mi_reg_enable(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	record_coords_t *coords = (record_coords_t *)data;
	str str_now = {NULL, 0};
	time_t now;

	// if (!str_strcmp(&coords->contact, &rec->contact_uri) &&
	// 	!str_strcmp(&coords->registrar, &rec->td.rem_target)) {
	if (!str_strcmp(&coords->contact, &rec->third_party_registrant)) {
		if (!(rec->flags&REG_ENABLED)) {
			if (rec->state == NOT_REGISTERED_STATE) {
				now = time(0);
				if (get_cur_time_s(&str_now, now) < 0) {
					LM_ERR("Failed to get current time string\n");
					return -1;
				}
				new_call_id_ftag_4_record(rec, &str_now);

				if(send_register((unsigned long)coords->extra, rec, NULL)==1) {
					rec->last_register_sent = now;
					rec->state = REGISTERING_STATE;
				} else {
					rec->registration_timeout = now + rec->expires - timer_interval;
					rec->state = INTERNAL_ERROR_STATE;
				}
			} else if (rec->state != AUTHENTICATING_STATE && rec->state != REGISTERING_STATE && rec->state != AUTHENTICATING_UNREGISTER_STATE && rec->state != UNREGISTERING_STATE) {
				if(send_register((unsigned long)coords->extra, rec, NULL)==1) {
					rec->last_register_sent = now;
					rec->state = REGISTERING_STATE;
				} else {
					rec->registration_timeout = now + rec->expires - timer_interval;
					rec->state = INTERNAL_ERROR_STATE;
				}
			} else {
				LM_ERR("Invalid state for reg enable\n");
			}

			rec->flags |= REG_ENABLED;

			reg_update_db_state(rec);
		}

		return 1;
	} else
		return 0;  /* continue search */
}

int run_mi_reg_disable(void *e_data, void *data, void *r_data)
{
	reg_record_t *rec = (reg_record_t*)e_data;
	record_coords_t *coords = (record_coords_t *)data;

	if (!str_strcmp(&coords->contact, &rec->third_party_registrant)) {
		if (rec->flags&REG_ENABLED) {
			if (rec->state == REGISTERED_STATE) {
				if(send_unregister((unsigned long)coords->extra, rec, NULL, 0)==1)
					rec->state = UNREGISTERING_STATE;
				else
					rec->state = INTERNAL_ERROR_STATE;
			}

			rec->flags &= ~REG_ENABLED;

			reg_update_db_state(rec);
		}

		return 1;
	} else
		return 0;  /* continue search */
}

static mi_response_t *mi_reg_enable(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	record_coords_t coords;
	int rc;
	unsigned int hash_code;

	if ((resp = mi_get_coords(params, &coords)))
		return resp;

	hash_code = core_hash(&coords.aor, NULL, reg_hsize);
	coords.extra = (void*)(unsigned long)hash_code;

	lock_get(&reg_htable[hash_code].lock);
	rc = slinkedl_traverse(reg_htable[hash_code].p_list,
					&run_mi_reg_enable, &coords, NULL);
	lock_release(&reg_htable[hash_code].lock);

	if (rc < 0)
		return NULL;
	else if (rc == 0)
		return init_mi_error(404, MI_SSTR("No such registrant"));

	return init_mi_result_ok();
}

static mi_response_t *mi_reg_disable(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	record_coords_t coords;
	int rc;
	unsigned int hash_code;

	if ((resp = mi_get_coords(params, &coords)))
		return resp;

	hash_code = core_hash(&coords.aor, NULL, reg_hsize);
	coords.extra = (void*)(unsigned long)hash_code;

	lock_get(&reg_htable[hash_code].lock);
	rc = slinkedl_traverse(reg_htable[hash_code].p_list,
					&run_mi_reg_disable, &coords, NULL);
	lock_release(&reg_htable[hash_code].lock);

	if (rc < 0)
		return NULL;
	else if (rc == 0)
		return init_mi_error(404, MI_SSTR("No such registrant"));

	return init_mi_result_ok();
}

/* Helper function to extract identifier from URI */
static int extract_identifier(const str *uri, str *identifier) {
    char *start, *end;
    size_t remaining_len;
    
    if (!uri || !uri->s || !uri->len) {
        return -1;
    }
    
    if (!identifier) {
        return -1;
    }
    
    /* Initialize identifier to empty */
    identifier->s = NULL;
    identifier->len = 0;
    
    /* Find the start of the identifier (after sip:) */
    start = memchr(uri->s, ':', uri->len);
    if (!start) {
        return -1;
    }
    
    /* Calculate remaining length after ':' */
    remaining_len = uri->s + uri->len - start;
    if (remaining_len <= 1) { /* Check if we have any characters after ':' */
        return -1;
    }
    start++; /* Skip the ':' */
    
    /* Find the end of the identifier (before @) */
    end = memchr(start, '@', remaining_len - 1);
    if (!end) {
        return -1;
    }
    
    /* Verify the extracted length is valid */
    if (end <= start) {
        return -1;
    }
    
    identifier->s = start;
    identifier->len = end - start;
    return 0;
}
