/*
 * $Id$
 *
 * dialog module - basic support for dialog tracking
 *
 * Copyright (C) 2009 Voice Sistem SRL
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-01-12 initial version (bogdan)
 */

#include "../../mem/shm_mem.h"
#include "dlg_vals.h"
#include "dlg_hash.h"

#define dlg_val_lock(_dlg) \
	dlg_lock( d_table, &(d_table->entries[_dlg->h_entry]))
#define dlg_val_unlock(_dlg) \
	dlg_unlock( d_table, &(d_table->entries[_dlg->h_entry]))


static inline unsigned int _get_name_id(str *name)
{
	char *p;
	unsigned short id;

	id=0;
	for( p=name->s+name->len-1 ; p>=name->s ; p-- )
		id ^= *p;
	return id;
}



static inline struct dlg_val *new_dlg_val(str *name, str *val)
{
	struct dlg_val *dv;

	LM_DBG("inserting <%.*s>=<%.*s>\n",name->len,name->s,val->len,val->s);
	dv =(struct dlg_val*)shm_malloc(sizeof(struct dlg_val)+name->len+val->len);
	if (dv==NULL) {
		LM_ERR("no more shm mem\n");
		return NULL;
	}
	dv->id = _get_name_id(name);
	dv->next = NULL;
	/* set name */
	dv->name.len = name->len;
	dv->name.s = (char*)(dv + 1);
	memcpy(dv->name.s, name->s, name->len);
	/* set value */
	dv->val.len = val->len;
	dv->val.s = ((char*)(dv + 1)) + name->len;
	memcpy(dv->val.s, val->s, val->len);
	return dv;
}


int store_dlg_value(struct dlg_cell *dlg, str *name, str *val)
{
	struct dlg_val *dv;

	if ( (dv=new_dlg_val(name,val))==NULL) {
		LM_ERR("failed to create new dialog value\n");
		return -1;
	}

	/* lock dialog */
	dlg_val_lock( dlg );

	/* insert at the beginning of the list */
	dv->next = dlg->vals;
	dlg->vals = dv;

	/* unlock dialog */
	dlg_val_unlock( dlg );

	return 0;
}


static char *val_buf = NULL;
static int val_buf_len = 0;


int fetch_dlg_value(struct dlg_cell *dlg, str *name, str *val)
{
	struct dlg_val *dv;
	unsigned int id;

	LM_DBG("looking for <%.*s>\n",name->len,name->s);

	id = _get_name_id(name);

	/* lock dialog */
	dlg_val_lock( dlg );

	/* iterate the list */
	for( dv=dlg->vals ; dv ; dv=dv->next) {
		if (id==dv->id && name->len==dv->name.len &&
		memcmp(name->s,dv->name.s,name->len)==0 ) {
			LM_DBG("var found-> <%.*s>!\n",dv->val.len,dv->val.s);
			/* found -> make a copy of the value under lock */
			if (dv->val.len > val_buf_len) {
				val_buf = (char*)pkg_realloc(val_buf,dv->val.len);
				if (val_buf==NULL) {
					dlg_val_unlock( dlg );
					LM_ERR("failed to do realloc for %d\n",dv->val.len);
					return -1;
				}
			}
			memcpy( val_buf, dv->val.s, dv->val.len );
			/* return */
			val->s = val_buf;
			val->len = dv->val.len;

			/* unlock dialog */
			dlg_val_unlock( dlg );
			return 0;
		}
	}

	/* unlock dialog */
	dlg_val_unlock( dlg );
	LM_DBG("var NOT found!\n");

	return -1;
}



int pv_parse_name(pv_spec_p sp, str *in)
{
	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	sp->pvp.pvn.u.isname.name.s = *in;

	return 0;
}



int pv_get_dlg_val(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	struct dlg_cell *dlg;
	str val;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	if (param==NULL || param->pvn.type!=PV_NAME_INTSTR ||
	param->pvn.u.isname.type!=AVP_NAME_STR ||
	param->pvn.u.isname.name.s.s==NULL ) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if (fetch_dlg_value( dlg, &param->pvn.u.isname.name.s, &val)!=0)
		return pv_get_null(msg, param, res);

	res->flags = PV_VAL_STR|PV_TYPE_INT;
	res->rs = val;
	return 0;
}


int pv_set_dlg_val(struct sip_msg* msg, pv_param_t *param, int op,
															pv_value_t *val)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL )
		return -1;

	if (param==NULL || param->pvn.type!=PV_NAME_INTSTR ||
	param->pvn.u.isname.type!=AVP_NAME_STR ||
	param->pvn.u.isname.name.s.s==NULL ) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if ( !(val->flags&PV_VAL_STR)) {
		LM_ERR("non-string values are not supported\n");
		return -1;
	}

	if (store_dlg_value( dlg, &param->pvn.u.isname.name.s, &val->rs)!=0) {
		LM_ERR("failed to store dialog values <%.*s>\n",
			param->pvn.u.isname.name.s.len,param->pvn.u.isname.name.s.s);
		return -1;
	}

	return 0;
}


