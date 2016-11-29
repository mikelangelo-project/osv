/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <alloca.h>
#include <string.h>

#include <infiniband/verbs.h>
#include <infiniband/kern-abi.h>
#include <linux/err.h>

#include <drivers/virtio-rdma.hh>

#include <ibverbs.h>

BEGIN_C_DECLS

extern int abi_ver;

#define IBV_INIT_CMD(cmd, size, opcode)					\
	do {								\
		if (abi_ver > 2)					\
			(cmd)->command = IB_USER_VERBS_CMD_##opcode;	\
		else							\
			(cmd)->command = IB_USER_VERBS_CMD_##opcode##_V2; \
		(cmd)->in_words  = (size) / 4;				\
		(cmd)->out_words = 0;					\
	} while (0)

#define IBV_INIT_CMD_RESP(cmd, size, opcode, out, outsize)		\
	do {								\
		if (abi_ver > 2)					\
			(cmd)->command = IB_USER_VERBS_CMD_##opcode;	\
		else							\
			(cmd)->command = IB_USER_VERBS_CMD_##opcode##_V2; \
		(cmd)->in_words  = (size) / 4;				\
		(cmd)->out_words = (outsize) / 4;			\
		(cmd)->response  = (uintptr_t) (out);			\
	} while (0)

#define INIT_UDATA(udata, ibuf, obuf, ilen, olen)			\
	do {								\
		(udata)->inbuf  = (void *) (ibuf);		\
		(udata)->outbuf = (void *) (obuf);		\
		(udata)->inlen  = (ilen);				\
		(udata)->outlen = (olen);				\
	} while (0)

using namespace virtio;

rdma *rdma_drv = rdma::instance();

// static int ibv_cmd_get_context_v2(struct ibv_context *context,
// 				  struct ibv_get_context *new_cmd,
// 				  size_t new_cmd_size,
// 				  struct ibv_get_context_resp *resp,
// 				  size_t resp_size)
// {
	// struct ibv_abi_compat_v2 *t;
	// struct ibv_get_context_v2 *cmd;
	// size_t cmd_size;
	// uint32_t cq_fd;

	// t = (struct ibv_abi_compat_v2 *) malloc(sizeof *t);
	// if (!t)
	// 	return ENOMEM;
	// pthread_mutex_init(&t->in_use, NULL);

	// cmd_size = sizeof *cmd + new_cmd_size - sizeof *new_cmd;
	// cmd      = alloca(cmd_size);
	// memcpy(cmd->driver_data, new_cmd->driver_data, new_cmd_size - sizeof *new_cmd);

	// IBV_INIT_CMD_RESP(cmd, cmd_size, GET_CONTEXT, resp, resp_size);
	// cmd->cq_fd_tab = (uintptr_t) &cq_fd;

	// if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	// context->async_fd         = resp->async_fd;
	// context->num_comp_vectors = 1;
	// t->channel.context        = context;
	// t->channel.fd		  = cq_fd;
	// t->channel.refcnt	  = 0;
	// context->abi_compat       = t;

// 	return 0;
// }

int ibv_cmd_get_context(struct ibv_context *context, struct ibv_get_context *cmd,
			size_t cmd_size, struct ibv_get_context_resp *resp,
			size_t resp_size)
{

	struct ib_udata ibudata;
	int ret=0;
	struct ib_ucontext		 *ucontext;
	struct ib_uverbs_get_context      kcmd;
	struct ib_uverbs_get_context_resp kresp;

	debug("ibv_cmd_get_context\n");

	IBV_INIT_CMD_RESP(cmd, cmd_size, GET_CONTEXT, resp, resp_size);

	INIT_UDATA(&ibudata, cmd + sizeof(kcmd),
			   kcmd.response + sizeof(kresp),
			   cmd_size - sizeof(kcmd), /*in_len*/
			   resp_size - sizeof(kresp)); /*out_len*/

	ucontext = rdma_drv->vrdma_alloc_ucontext(&ibudata);
	if (IS_ERR(ucontext)) {
		ret = PTR_ERR(ucontext);
	}

	INIT_LIST_HEAD(&ucontext->pd_list);
	INIT_LIST_HEAD(&ucontext->mr_list);
	INIT_LIST_HEAD(&ucontext->mw_list);
	INIT_LIST_HEAD(&ucontext->cq_list);
	INIT_LIST_HEAD(&ucontext->qp_list);
	INIT_LIST_HEAD(&ucontext->srq_list);
	INIT_LIST_HEAD(&ucontext->ah_list);
	INIT_LIST_HEAD(&ucontext->xrcd_list);
	ucontext->closing = 0;

	context->async_fd         = resp->async_fd;
	context->num_comp_vectors = resp->num_comp_vectors;

	return ret;
}

int ibv_cmd_query_device(struct ibv_context *context,
			 struct ibv_device_attr *device_attr,
			 uint64_t *raw_fw_ver,
			 struct ibv_query_device *cmd, size_t cmd_size)
{
	ib_uverbs_query_device_resp *attr;
	int ret, hret;

	debug("ibv_cmd_query_device\n");

	attr = (ib_uverbs_query_device_resp*) kmalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		debug("could not allocate device attr\n");
		return -ENOMEM;
	}

	ret = rdma_drv->vrdma_query_device(attr, &hret);
	if (ret || hret) {
		debug("could not query device on host\n");
		kfree(attr);
		return ret ? ret : hret;
	}

	memset(device_attr->fw_ver, 0, sizeof device_attr->fw_ver);
	*raw_fw_ver			       = attr->fw_ver;
	device_attr->node_guid 		       = attr->node_guid;
	device_attr->sys_image_guid 	       = attr->sys_image_guid;
	device_attr->max_mr_size 	       = attr->max_mr_size;
	device_attr->page_size_cap 	       = attr->page_size_cap;
	device_attr->vendor_id 		       = attr->vendor_id;
	device_attr->vendor_part_id 	       = attr->vendor_part_id;
	device_attr->hw_ver 		       = attr->hw_ver;
	device_attr->max_qp 		       = attr->max_qp;
	device_attr->max_qp_wr 		       = attr->max_qp_wr;
	device_attr->device_cap_flags 	       = attr->device_cap_flags;
	device_attr->max_sge 		       = attr->max_sge;
	device_attr->max_sge_rd 	       = attr->max_sge_rd;
	device_attr->max_cq 		       = attr->max_cq;
	device_attr->max_cqe 		       = attr->max_cqe;
	device_attr->max_mr 		       = attr->max_mr;
	device_attr->max_pd 		       = attr->max_pd;
	device_attr->max_qp_rd_atom 	       = attr->max_qp_rd_atom;
	device_attr->max_ee_rd_atom 	       = attr->max_ee_rd_atom;
	device_attr->max_res_rd_atom 	       = attr->max_res_rd_atom;
	device_attr->max_qp_init_rd_atom       = attr->max_qp_init_rd_atom;
	device_attr->max_ee_init_rd_atom       = attr->max_ee_init_rd_atom;
	device_attr->atomic_cap 	       = (ibv_atomic_cap) attr->atomic_cap;
	device_attr->max_ee 		       = attr->max_ee;
	device_attr->max_rdd 		       = attr->max_rdd;
	device_attr->max_mw 		       = attr->max_mw;
	device_attr->max_raw_ipv6_qp 	       = attr->max_raw_ipv6_qp;
	device_attr->max_raw_ethy_qp 	       = attr->max_raw_ethy_qp;
	device_attr->max_mcast_grp 	       = attr->max_mcast_grp;
	device_attr->max_mcast_qp_attach       = attr->max_mcast_qp_attach;
	device_attr->max_total_mcast_qp_attach = attr->max_total_mcast_qp_attach;
	device_attr->max_ah 		       = attr->max_ah;
	device_attr->max_fmr 		       = attr->max_fmr;
	device_attr->max_map_per_fmr 	       = attr->max_map_per_fmr;
	device_attr->max_srq 		       = attr->max_srq;
	device_attr->max_srq_wr 	       = attr->max_srq_wr;
	device_attr->max_srq_sge 	       = attr->max_srq_sge;
	device_attr->max_pkeys 		       = attr->max_pkeys;
	device_attr->local_ca_ack_delay        = attr->local_ca_ack_delay;
	device_attr->phys_port_cnt	       = attr->phys_port_cnt;

	kfree(attr);
	return 0;
}

int ibv_cmd_query_port(struct ibv_context *context, uint8_t port_num,
		       struct ibv_port_attr *port_attr,
		       struct ibv_query_port *cmd, size_t cmd_size)
{
	ib_uverbs_query_port_resp *attr;
	int ret, hret;

	debug("ibv_cmd_query_port\n");

	attr = (ib_uverbs_query_port_resp*) kmalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		debug("could not allocate device attr.\n");
		return -ENOMEM;
	}

	ret = rdma_drv->vrdma_query_port(attr, port_num, &hret);
	if (ret || hret) {
		debug("could not query port on host\n");
		kfree(attr);
		return ret ? ret : hret;
	}

	port_attr->state      	   = (ibv_port_state) attr->state;
	port_attr->max_mtu         = (ibv_mtu) attr->max_mtu;
	port_attr->active_mtu      = (ibv_mtu) attr->active_mtu;
	port_attr->gid_tbl_len     = attr->gid_tbl_len;
	port_attr->port_cap_flags  = attr->port_cap_flags;
	port_attr->max_msg_sz      = attr->max_msg_sz;
	port_attr->bad_pkey_cntr   = attr->bad_pkey_cntr;
	port_attr->qkey_viol_cntr  = attr->qkey_viol_cntr;
	port_attr->pkey_tbl_len    = attr->pkey_tbl_len;
	port_attr->lid 	      	   = attr->lid;
	port_attr->sm_lid 	   = attr->sm_lid;
	port_attr->lmc 	      	   = attr->lmc;
	port_attr->max_vl_num      = attr->max_vl_num;
	port_attr->sm_sl      	   = attr->sm_sl;
	port_attr->subnet_timeout  = attr->subnet_timeout;
	port_attr->init_type_reply = attr->init_type_reply;
	port_attr->active_width    = attr->active_width;
	port_attr->active_speed    = attr->active_speed;
	port_attr->phys_state      = attr->phys_state;
	port_attr->link_layer      = attr->link_layer;

	kfree(attr);
	return 0;
}

int ibv_cmd_alloc_pd(struct ibv_context *context, struct ibv_pd *pd,
		     struct ibv_alloc_pd *cmd, size_t cmd_size,
		     struct ibv_alloc_pd_resp *resp, size_t resp_size)
{
	struct ib_uverbs_alloc_pd      kcmd;
	struct ib_uverbs_alloc_pd_resp kresp;
	struct ib_udata                ibudata;
	struct ib_uobject             *uobj;
	struct ib_pd                  *kpd;

	debug("ibv_cmd_alloc_pd\n");

    IBV_INIT_CMD_RESP(cmd, cmd_size, ALLOC_PD, resp, resp_size);
	INIT_UDATA(&ibudata, cmd + sizeof(kcmd),
			   kcmd.response + sizeof(kresp),
			   cmd_size - sizeof(kcmd), /*cmd_size = in_len*/
			   resp_size - sizeof(kresp)); /*resp_size = out_len*/

	uobj = (struct ib_uobject*) kmalloc(sizeof *uobj, GFP_KERNEL);
	if (!uobj)
		return -ENOMEM;

	kpd = rdma_drv->vrdma_alloc_pd(&ibudata);
	kpd->uobject = uobj;
	resp->pd_handle = uobj->id;

	pd->handle  = resp->pd_handle;
	pd->context = context;

	printf("pd->handle: %d\n", pd->handle);
	printf("pd->context: %p\n", pd->context);

	return 0;
}

int ibv_cmd_dealloc_pd(struct ibv_pd *pd)
{
	// dprint(DBG_IBV, "\n");
	// struct ibv_dealloc_pd cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, DEALLOC_PD);
	// cmd.pd_handle = pd->handle;

	// if (write(pd->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	return 0;
}

int ibv_cmd_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
		   uint64_t hca_va, int access,
		   struct ibv_mr *mr, struct ibv_reg_mr *cmd,
		   size_t cmd_size,
		   struct ibv_reg_mr_resp *resp, size_t resp_size)
{
	debug("ibv_cmd_reg_mr\n");
	// dprint(DBG_IBV, "\n");
	// IBV_INIT_CMD_RESP(cmd, cmd_size, REG_MR, resp, resp_size);

	// cmd->start 	  = (uintptr_t) addr;
	// cmd->length 	  = length;
	// cmd->hca_va 	  = hca_va;
	// cmd->pd_handle 	  = pd->handle;
	// cmd->access_flags = access;

	// if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	// mr->handle  = resp->mr_handle;
	// mr->lkey    = resp->lkey;
	// mr->rkey    = resp->rkey;
	// mr->context = pd->context;

	return 0;
}

int ibv_cmd_dereg_mr(struct ibv_mr *mr)
{
	// dprint(DBG_IBV, "\n");
	// struct ibv_dereg_mr cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, DEREG_MR);
	// cmd.mr_handle = mr->handle;

	// if (write(mr->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	return 0;
}

// static int ibv_cmd_create_cq_v2(struct ibv_context *context, int cqe,
// 				struct ibv_cq *cq,
// 				struct ibv_create_cq *new_cmd, size_t new_cmd_size,
// 				struct ibv_create_cq_resp *resp, size_t resp_size)
// {
	// dprint(DBG_IBV, "\n");
	// struct ibv_create_cq_v2 *cmd;
	// size_t cmd_size;

	// cmd_size = sizeof *cmd + new_cmd_size - sizeof *new_cmd;
	// cmd      = alloca(cmd_size);
	// memcpy(cmd->driver_data, new_cmd->driver_data, new_cmd_size - sizeof *new_cmd);

	// IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_CQ, resp, resp_size);
	// cmd->user_handle   = (uintptr_t) cq;
	// cmd->cqe           = cqe;
	// cmd->event_handler = 0;

	// if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	// cq->handle  = resp->cq_handle;
	// cq->cqe     = resp->cqe;
	// cq->context = context;

// 	return 0;
// }

int ibv_cmd_create_cq(struct ibv_context *context, int cqe,
		      struct ibv_comp_channel *channel,
		      int comp_vector, struct ibv_cq *cq,
		      struct ibv_create_cq *cmd, size_t cmd_size,
		      struct ibv_create_cq_resp *resp, size_t resp_size)
{
	// dprint(DBG_IBV, "\n");
	// if (abi_ver <= 2)
	// 	return ibv_cmd_create_cq_v2(context, cqe, cq,
	// 				    cmd, cmd_size, resp, resp_size);

	// IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_CQ, resp, resp_size);
	// cmd->user_handle   = (uintptr_t) cq;
	// cmd->cqe           = cqe;
	// cmd->comp_vector   = comp_vector;
	// cmd->comp_channel  = channel ? channel->fd : -1;
	// cmd->reserved      = 0;

	// if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	// cq->handle  = resp->cq_handle;
	// cq->cqe     = resp->cqe;
	// cq->context = context;

	return 0;
}

int ibv_cmd_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	// dprint(DBG_IBV, "\n");
	// struct ibv_poll_cq       cmd;
    // struct ibv_poll_cq_resp *resp;
	// int                      i;
	// int                      rsize;
    int                      ret = 0;

	// rsize = sizeof *resp + ne * sizeof(struct ibv_kern_wc);
	// resp  = (struct ibv_poll_cq_resp *) malloc(rsize);
	// if (!resp)
	// 	return -1;

	// IBV_INIT_CMD_RESP(&cmd, sizeof cmd, POLL_CQ, resp, rsize);
	// cmd.cq_handle = ibcq->handle;
	// cmd.ne        = ne;

	// if (write(ibcq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd) {
	// 	ret = -1;
	// 	goto out;
	// }

	// VALGRIND_MAKE_MEM_DEFINED(resp, rsize);

	// for (i = 0; i < resp->count; i++) {
	// 	wc[i].wr_id 	     = resp->wc[i].wr_id;
	// 	wc[i].status 	     = (ibv_wc_status) resp->wc[i].status;
	// 	wc[i].opcode 	     = (ibv_wc_opcode) resp->wc[i].opcode;
	// 	wc[i].vendor_err     = resp->wc[i].vendor_err;
	// 	wc[i].byte_len 	     = resp->wc[i].byte_len;
	// 	wc[i].imm_data 	     = resp->wc[i].imm_data;
	// 	wc[i].qp_num 	     = resp->wc[i].qp_num;
	// 	wc[i].src_qp 	     = resp->wc[i].src_qp;
	// 	wc[i].wc_flags 	     = resp->wc[i].wc_flags;
	// 	wc[i].pkey_index     = resp->wc[i].pkey_index;
	// 	wc[i].slid 	     = resp->wc[i].slid;
	// 	wc[i].sl 	     = resp->wc[i].sl;
	// 	wc[i].dlid_path_bits = resp->wc[i].dlid_path_bits;
	// }

	// ret = resp->count;

// out:
// 	free(resp);
	return ret;
}

int ibv_cmd_req_notify_cq(struct ibv_cq *ibcq, int solicited_only)
{
	// dprint(DBG_IBV, "\n");
	// struct ibv_req_notify_cq cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, REQ_NOTIFY_CQ);
	// cmd.cq_handle = ibcq->handle;
	// cmd.solicited = !!solicited_only;

	// if (write(ibcq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	return 0;
}

int ibv_cmd_resize_cq(struct ibv_cq *cq, int cqe,
		      struct ibv_resize_cq *cmd, size_t cmd_size,
		      struct ibv_resize_cq_resp *resp, size_t resp_size)
{
	// dprint(DBG_IBV, "\n");
	// IBV_INIT_CMD_RESP(cmd, cmd_size, RESIZE_CQ, resp, resp_size);
	// cmd->cq_handle = cq->handle;
	// cmd->cqe       = cqe;

	// if (write(cq->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	// cq->cqe = resp->cqe;

	return 0;
}

// static int ibv_cmd_destroy_cq_v1(struct ibv_cq *cq)
// {
	// struct ibv_destroy_cq_v1 cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, DESTROY_CQ);
	// cmd.cq_handle = cq->handle;

	// if (write(cq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

// 	return 0;
// }

int ibv_cmd_destroy_cq(struct ibv_cq *cq)
{
	// dprint(DBG_IBV, "\n");
	// struct ibv_destroy_cq      cmd;
	// struct ibv_destroy_cq_resp resp;

	// if (abi_ver == 1)
	// 	return ibv_cmd_destroy_cq_v1(cq);

	// IBV_INIT_CMD_RESP(&cmd, sizeof cmd, DESTROY_CQ, &resp, sizeof resp);
	// cmd.cq_handle = cq->handle;
	// cmd.reserved  = 0;

	// if (write(cq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// pthread_mutex_lock(&cq->mutex);
	// while (cq->comp_events_completed  != resp.comp_events_reported ||
	//        cq->async_events_completed != resp.async_events_reported)
	// 	pthread_cond_wait(&cq->cond, &cq->mutex);
	// pthread_mutex_unlock(&cq->mutex);

	return 0;
}

int ibv_cmd_create_srq(struct ibv_pd *pd,
		       struct ibv_srq *srq, struct ibv_srq_init_attr *attr,
		       struct ibv_create_srq *cmd, size_t cmd_size,
		       struct ibv_create_srq_resp *resp, size_t resp_size)
{
	// IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_SRQ, resp, resp_size);
	// cmd->user_handle = (uintptr_t) srq;
	// cmd->pd_handle 	 = pd->handle;
	// cmd->max_wr      = attr->attr.max_wr;
	// cmd->max_sge     = attr->attr.max_sge;
	// cmd->srq_limit   = attr->attr.srq_limit;

	// if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	// srq->handle  = resp->srq_handle;
	// srq->context = pd->context;

	// if (abi_ver > 5) {
	// 	attr->attr.max_wr = resp->max_wr;
	// 	attr->attr.max_sge = resp->max_sge;
	// } else {
	// 	struct ibv_create_srq_resp_v5 *resp_v5 =
	// 		(struct ibv_create_srq_resp_v5 *) resp;

	// 	memmove((void *) resp + sizeof *resp,
	// 		(void *) resp_v5 + sizeof *resp_v5,
	// 		resp_size - sizeof *resp);
	// }

	return 0;
}

int ibv_cmd_create_xrc_srq(struct ibv_pd *pd,
		       struct ibv_srq *srq, struct ibv_srq_init_attr *attr,
		       uint32_t xrcd_handle, uint32_t xrc_cq,
		       struct ibv_create_xrc_srq *cmd, size_t cmd_size,
		       struct ibv_create_srq_resp *resp, size_t resp_size)
{
	// IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_XRC_SRQ, resp, resp_size);
	// cmd->user_handle = (uintptr_t) srq;
	// cmd->pd_handle 	 = pd->handle;
	// cmd->max_wr      = attr->attr.max_wr;
	// cmd->max_sge     = attr->attr.max_sge;
	// cmd->srq_limit   = attr->attr.srq_limit;
	// cmd->xrcd_handle = xrcd_handle;
	// cmd->xrc_cq	 = xrc_cq;

	// if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	// srq->handle  = resp->srq_handle;
	// srq->context = pd->context;
	// attr->attr.max_wr = resp->max_wr;
	// attr->attr.max_sge = resp->max_sge;

	return 0;
}

// static int ibv_cmd_modify_srq_v3(struct ibv_srq *srq,
// 				 struct ibv_srq_attr *srq_attr,
// 				 int srq_attr_mask,
// 				 struct ibv_modify_srq *new_cmd,
// 				 size_t new_cmd_size)
// {
	// struct ibv_modify_srq_v3 *cmd;
	// size_t cmd_size;

	// cmd_size = sizeof *cmd + new_cmd_size - sizeof *new_cmd;
    // cmd      = alloca(cmd_size);
	// memcpy(cmd->driver_data, new_cmd->driver_data, new_cmd_size - sizeof *new_cmd);

	// IBV_INIT_CMD(cmd, cmd_size, MODIFY_SRQ);

	// cmd->srq_handle	= srq->handle;
	// cmd->attr_mask	= srq_attr_mask;
	// cmd->max_wr	= srq_attr->max_wr;
	// cmd->srq_limit	= srq_attr->srq_limit;
	// cmd->max_sge	= 0;
	// cmd->reserved	= 0;

	// if (write(srq->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

// 	return 0;
// }

int ibv_cmd_modify_srq(struct ibv_srq *srq,
		       struct ibv_srq_attr *srq_attr,
		       int srq_attr_mask,
		       struct ibv_modify_srq *cmd, size_t cmd_size)
{
	// if (abi_ver == 3)
	// 	return ibv_cmd_modify_srq_v3(srq, srq_attr, srq_attr_mask,
	// 				     cmd, cmd_size);

	// IBV_INIT_CMD(cmd, cmd_size, MODIFY_SRQ);

	// cmd->srq_handle	= srq->handle;
	// cmd->attr_mask	= srq_attr_mask;
	// cmd->max_wr	= srq_attr->max_wr;
	// cmd->srq_limit	= srq_attr->srq_limit;

	// if (write(srq->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	return 0;
}

int ibv_cmd_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
		      struct ibv_query_srq *cmd, size_t cmd_size)
{
	// struct ibv_query_srq_resp resp;

	// IBV_INIT_CMD_RESP(cmd, cmd_size, QUERY_SRQ, &resp, sizeof resp);
	// cmd->srq_handle = srq->handle;
	// cmd->reserved   = 0;

	// if (write(srq->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp)
		;

	// srq_attr->max_wr    = resp.max_wr;
	// srq_attr->max_sge   = resp.max_sge;
	// srq_attr->srq_limit = resp.srq_limit;

	return 0;
}

// static int ibv_cmd_destroy_srq_v1(struct ibv_srq *srq)
// {
	// struct ibv_destroy_srq_v1 cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, DESTROY_SRQ);
	// cmd.srq_handle = srq->handle;

	// if (write(srq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

// 	return 0;
// }

int ibv_cmd_destroy_srq(struct ibv_srq *srq)
{
	// struct ibv_destroy_srq      cmd;
	// struct ibv_destroy_srq_resp resp;

	// if (abi_ver == 1)
	// 	return ibv_cmd_destroy_srq_v1(srq);

	// IBV_INIT_CMD_RESP(&cmd, sizeof cmd, DESTROY_SRQ, &resp, sizeof resp);
	// cmd.srq_handle = srq->handle;
	// cmd.reserved   = 0;

	// if (write(srq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// pthread_mutex_lock(&srq->mutex);
	// while (srq->events_completed != resp.events_reported)
	// 	pthread_cond_wait(&srq->cond, &srq->mutex);
	// pthread_mutex_unlock(&srq->mutex);

	return 0;
}

int ibv_cmd_create_qp(struct ibv_pd *pd,
		      struct ibv_qp *qp, struct ibv_qp_init_attr *attr,
		      struct ibv_create_qp *cmd, size_t cmd_size,
		      struct ibv_create_qp_resp *resp, size_t resp_size)
{
	// IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_QP, resp, resp_size);

	// cmd->user_handle     = (uintptr_t) qp;
	// cmd->pd_handle 	     = pd->handle;
	// cmd->send_cq_handle  = attr->send_cq->handle;
	// cmd->recv_cq_handle  = attr->recv_cq->handle;
	// cmd->max_send_wr     = attr->cap.max_send_wr;
	// cmd->max_recv_wr     = attr->cap.max_recv_wr;
	// cmd->max_send_sge    = attr->cap.max_send_sge;
	// cmd->max_recv_sge    = attr->cap.max_recv_sge;
	// cmd->max_inline_data = attr->cap.max_inline_data;
	// cmd->sq_sig_all	     = attr->sq_sig_all;
	// cmd->qp_type 	     = attr->qp_type;
	// cmd->is_srq 	     = !!attr->srq;
	// cmd->srq_handle      = attr->qp_type == IBV_QPT_XRC ?
	// 	(attr->xrc_domain ? attr->xrc_domain->handle : 0) :
	// 	(attr->srq ? attr->srq->handle : 0);
	// cmd->reserved	     = 0;

	// if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);

	// qp->handle 		  = resp->qp_handle;
	// qp->qp_num 		  = resp->qpn;
	// qp->context		  = pd->context;

	// if (abi_ver > 3) {
	// 	attr->cap.max_recv_sge    = resp->max_recv_sge;
	// 	attr->cap.max_send_sge    = resp->max_send_sge;
	// 	attr->cap.max_recv_wr     = resp->max_recv_wr;
	// 	attr->cap.max_send_wr     = resp->max_send_wr;
	// 	attr->cap.max_inline_data = resp->max_inline_data;
	// }

	// if (abi_ver == 4) {
	// 	struct ibv_create_qp_resp_v4 *resp_v4 =
	// 		(struct ibv_create_qp_resp_v4 *) resp;

	// 	memmove((void *) resp + sizeof *resp,
	// 		(void *) resp_v4 + sizeof *resp_v4,
	// 		resp_size - sizeof *resp);
	// } else if (abi_ver <= 3) {
	// 	struct ibv_create_qp_resp_v3 *resp_v3 =
	// 		(struct ibv_create_qp_resp_v3 *) resp;

	// 	memmove((void *) resp + sizeof *resp,
	// 		(void *) resp_v3 + sizeof *resp_v3,
	// 		resp_size - sizeof *resp);
	// }

	return 0;
}

int ibv_cmd_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		     int attr_mask,
		     struct ibv_qp_init_attr *init_attr,
		     struct ibv_query_qp *cmd, size_t cmd_size)
{
	// struct ibv_query_qp_resp resp;

	// IBV_INIT_CMD_RESP(cmd, cmd_size, QUERY_QP, &resp, sizeof resp);
	// cmd->qp_handle = qp->handle;
	// cmd->attr_mask = attr_mask;

	// if (write(qp->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// attr->qkey                          = resp.qkey;
	// attr->rq_psn                        = resp.rq_psn;
	// attr->sq_psn                        = resp.sq_psn;
	// attr->dest_qp_num                   = resp.dest_qp_num;
	// attr->qp_access_flags               = resp.qp_access_flags;
	// attr->pkey_index                    = resp.pkey_index;
	// attr->alt_pkey_index                = resp.alt_pkey_index;
	// attr->qp_state                      = (ibv_qp_state) resp.qp_state;
	// attr->cur_qp_state                  = (ibv_qp_state) resp.cur_qp_state;
	// attr->path_mtu                      = (ibv_mtu) resp.path_mtu;
	// attr->path_mig_state                = (ibv_mig_state) resp.path_mig_state;
	// attr->sq_draining                   = resp.sq_draining;
	// attr->max_rd_atomic                 = resp.max_rd_atomic;
	// attr->max_dest_rd_atomic            = resp.max_dest_rd_atomic;
	// attr->min_rnr_timer                 = resp.min_rnr_timer;
	// attr->port_num                      = resp.port_num;
	// attr->timeout                       = resp.timeout;
	// attr->retry_cnt                     = resp.retry_cnt;
	// attr->rnr_retry                     = resp.rnr_retry;
	// attr->alt_port_num                  = resp.alt_port_num;
	// attr->alt_timeout                   = resp.alt_timeout;
	// attr->cap.max_send_wr               = resp.max_send_wr;
	// attr->cap.max_recv_wr               = resp.max_recv_wr;
	// attr->cap.max_send_sge              = resp.max_send_sge;
	// attr->cap.max_recv_sge              = resp.max_recv_sge;
	// attr->cap.max_inline_data           = resp.max_inline_data;

	// memcpy(attr->ah_attr.grh.dgid.raw, resp.dest.dgid, 16);
	// attr->ah_attr.grh.flow_label        = resp.dest.flow_label;
	// attr->ah_attr.dlid                  = resp.dest.dlid;
	// attr->ah_attr.grh.sgid_index        = resp.dest.sgid_index;
	// attr->ah_attr.grh.hop_limit         = resp.dest.hop_limit;
	// attr->ah_attr.grh.traffic_class     = resp.dest.traffic_class;
	// attr->ah_attr.sl                    = resp.dest.sl;
	// attr->ah_attr.src_path_bits         = resp.dest.src_path_bits;
	// attr->ah_attr.static_rate           = resp.dest.static_rate;
	// attr->ah_attr.is_global             = resp.dest.is_global;
	// attr->ah_attr.port_num              = resp.dest.port_num;

	// memcpy(attr->alt_ah_attr.grh.dgid.raw, resp.alt_dest.dgid, 16);
	// attr->alt_ah_attr.grh.flow_label    = resp.alt_dest.flow_label;
	// attr->alt_ah_attr.dlid              = resp.alt_dest.dlid;
	// attr->alt_ah_attr.grh.sgid_index    = resp.alt_dest.sgid_index;
	// attr->alt_ah_attr.grh.hop_limit     = resp.alt_dest.hop_limit;
	// attr->alt_ah_attr.grh.traffic_class = resp.alt_dest.traffic_class;
	// attr->alt_ah_attr.sl                = resp.alt_dest.sl;
	// attr->alt_ah_attr.src_path_bits     = resp.alt_dest.src_path_bits;
	// attr->alt_ah_attr.static_rate       = resp.alt_dest.static_rate;
	// attr->alt_ah_attr.is_global         = resp.alt_dest.is_global;
	// attr->alt_ah_attr.port_num          = resp.alt_dest.port_num;

	// init_attr->qp_context               = qp->qp_context;
	// init_attr->send_cq                  = qp->send_cq;
	// init_attr->recv_cq                  = qp->recv_cq;
	// init_attr->srq                      = qp->srq;
	// init_attr->qp_type                  = qp->qp_type;
	// if (qp->qp_type == IBV_QPT_XRC)
	// 	init_attr->xrc_domain = qp->xrc_domain;
	// init_attr->cap.max_send_wr          = resp.max_send_wr;
	// init_attr->cap.max_recv_wr          = resp.max_recv_wr;
	// init_attr->cap.max_send_sge         = resp.max_send_sge;
	// init_attr->cap.max_recv_sge         = resp.max_recv_sge;
	// init_attr->cap.max_inline_data      = resp.max_inline_data;
	// init_attr->sq_sig_all               = resp.sq_sig_all;

	return 0;
}

int ibv_cmd_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		      int attr_mask,
		      struct ibv_modify_qp *cmd, size_t cmd_size)
{
	// IBV_INIT_CMD(cmd, cmd_size, MODIFY_QP);

	// cmd->qp_handle 		 = qp->handle;
	// cmd->attr_mask 		 = attr_mask;
	// cmd->qkey 		 = attr->qkey;
	// cmd->rq_psn 		 = attr->rq_psn;
	// cmd->sq_psn 		 = attr->sq_psn;
	// cmd->dest_qp_num 	 = attr->dest_qp_num;
	// cmd->qp_access_flags 	 = attr->qp_access_flags;
	// cmd->pkey_index		 = attr->pkey_index;
	// cmd->alt_pkey_index 	 = attr->alt_pkey_index;
	// cmd->qp_state 		 = attr->qp_state;
	// cmd->cur_qp_state 	 = attr->cur_qp_state;
	// cmd->path_mtu 		 = attr->path_mtu;
	// cmd->path_mig_state 	 = attr->path_mig_state;
	// cmd->en_sqd_async_notify = attr->en_sqd_async_notify;
	// cmd->max_rd_atomic 	 = attr->max_rd_atomic;
	// cmd->max_dest_rd_atomic  = attr->max_dest_rd_atomic;
	// cmd->min_rnr_timer 	 = attr->min_rnr_timer;
	// cmd->port_num 		 = attr->port_num;
	// cmd->timeout 		 = attr->timeout;
	// cmd->retry_cnt 		 = attr->retry_cnt;
	// cmd->rnr_retry 		 = attr->rnr_retry;
	// cmd->alt_port_num 	 = attr->alt_port_num;
	// cmd->alt_timeout 	 = attr->alt_timeout;

	// memcpy(cmd->dest.dgid, attr->ah_attr.grh.dgid.raw, 16);
	// cmd->dest.flow_label 	    = attr->ah_attr.grh.flow_label;
	// cmd->dest.dlid 		    = attr->ah_attr.dlid;
	// cmd->dest.reserved	    = 0;
	// cmd->dest.sgid_index 	    = attr->ah_attr.grh.sgid_index;
	// cmd->dest.hop_limit 	    = attr->ah_attr.grh.hop_limit;
	// cmd->dest.traffic_class     = attr->ah_attr.grh.traffic_class;
	// cmd->dest.sl 		    = attr->ah_attr.sl;
	// cmd->dest.src_path_bits     = attr->ah_attr.src_path_bits;
	// cmd->dest.static_rate 	    = attr->ah_attr.static_rate;
	// cmd->dest.is_global 	    = attr->ah_attr.is_global;
	// cmd->dest.port_num 	    = attr->ah_attr.port_num;

	// memcpy(cmd->alt_dest.dgid, attr->alt_ah_attr.grh.dgid.raw, 16);
	// cmd->alt_dest.flow_label    = attr->alt_ah_attr.grh.flow_label;
	// cmd->alt_dest.dlid 	    = attr->alt_ah_attr.dlid;
	// cmd->alt_dest.reserved	    = 0;
	// cmd->alt_dest.sgid_index    = attr->alt_ah_attr.grh.sgid_index;
	// cmd->alt_dest.hop_limit     = attr->alt_ah_attr.grh.hop_limit;
	// cmd->alt_dest.traffic_class = attr->alt_ah_attr.grh.traffic_class;
	// cmd->alt_dest.sl 	    = attr->alt_ah_attr.sl;
	// cmd->alt_dest.src_path_bits = attr->alt_ah_attr.src_path_bits;
	// cmd->alt_dest.static_rate   = attr->alt_ah_attr.static_rate;
	// cmd->alt_dest.is_global     = attr->alt_ah_attr.is_global;
	// cmd->alt_dest.port_num 	    = attr->alt_ah_attr.port_num;

	// cmd->reserved[0] = cmd->reserved[1] = 0;

	// if (write(qp->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	return errno;

	return 0;
}

int ibv_cmd_create_xrc_rcv_qp(struct ibv_qp_init_attr *init_attr,
			     uint32_t *xrc_rcv_qpn)
{
	// struct ibv_create_xrc_rcv_qp cmd;
	// struct ibv_create_xrc_rcv_qp_resp resp;

	// if (abi_ver < 6)
	// 	return ENOSYS;

	// IBV_INIT_CMD_RESP(&cmd, sizeof cmd, CREATE_XRC_RCV_QP, &resp,
	// 		  sizeof resp);

	// cmd.xrc_domain_handle = init_attr->xrc_domain->handle;
	// cmd.max_send_wr     = init_attr->cap.max_send_wr;
	// cmd.max_recv_wr     = init_attr->cap.max_recv_wr;
	// cmd.max_send_sge    = init_attr->cap.max_send_sge;
	// cmd.max_recv_sge    = init_attr->cap.max_recv_sge;
	// cmd.max_inline_data = init_attr->cap.max_inline_data;
	// cmd.sq_sig_all	     = init_attr->sq_sig_all;
	// cmd.qp_type 	     = init_attr->qp_type;
	// cmd.reserved[0] = cmd.reserved[1] = 0;

	// if (write(init_attr->xrc_domain->context->cmd_fd, &cmd, sizeof cmd) !=
	//     sizeof cmd)
	// 	return errno;

	// *xrc_rcv_qpn = resp.qpn;

	return 0;
}

int ibv_cmd_modify_xrc_rcv_qp(struct ibv_xrc_domain *d, uint32_t xrc_qp_num,
			      struct ibv_qp_attr *attr, int attr_mask)
{
	// struct ibv_modify_xrc_rcv_qp cmd;

	// if (abi_ver < 6)
	// 	return ENOSYS;

	// IBV_INIT_CMD(&cmd, sizeof cmd, MODIFY_XRC_RCV_QP);

	// cmd.xrc_domain_handle	 = d->handle;
	// cmd.qp_num 		 = xrc_qp_num;
	// cmd.attr_mask 		 = attr_mask;
	// cmd.qkey 		 = attr->qkey;
	// cmd.rq_psn 		 = attr->rq_psn;
	// cmd.sq_psn 		 = attr->sq_psn;
	// cmd.dest_qp_num 	 = attr->dest_qp_num;
	// cmd.qp_access_flags 	 = attr->qp_access_flags;
	// cmd.pkey_index		 = attr->pkey_index;
	// cmd.alt_pkey_index 	 = attr->alt_pkey_index;
	// cmd.qp_state 		 = attr->qp_state;
	// cmd.cur_qp_state 	 = attr->cur_qp_state;
	// cmd.path_mtu 		 = attr->path_mtu;
	// cmd.path_mig_state 	 = attr->path_mig_state;
	// cmd.en_sqd_async_notify  = attr->en_sqd_async_notify;
	// cmd.max_rd_atomic 	 = attr->max_rd_atomic;
	// cmd.max_dest_rd_atomic   = attr->max_dest_rd_atomic;
	// cmd.min_rnr_timer 	 = attr->min_rnr_timer;
	// cmd.port_num 		 = attr->port_num;
	// cmd.timeout 		 = attr->timeout;
	// cmd.retry_cnt 		 = attr->retry_cnt;
	// cmd.rnr_retry 		 = attr->rnr_retry;
	// cmd.alt_port_num 	 = attr->alt_port_num;
	// cmd.alt_timeout 	 = attr->alt_timeout;

	// memcpy(cmd.dest.dgid, attr->ah_attr.grh.dgid.raw, 16);
	// cmd.dest.flow_label 	    = attr->ah_attr.grh.flow_label;
	// cmd.dest.dlid 		    = attr->ah_attr.dlid;
	// cmd.dest.reserved	    = 0;
	// cmd.dest.sgid_index 	    = attr->ah_attr.grh.sgid_index;
	// cmd.dest.hop_limit 	    = attr->ah_attr.grh.hop_limit;
	// cmd.dest.traffic_class      = attr->ah_attr.grh.traffic_class;
	// cmd.dest.sl 		    = attr->ah_attr.sl;
	// cmd.dest.src_path_bits      = attr->ah_attr.src_path_bits;
	// cmd.dest.static_rate 	    = attr->ah_attr.static_rate;
	// cmd.dest.is_global 	    = attr->ah_attr.is_global;
	// cmd.dest.port_num 	    = attr->ah_attr.port_num;

	// memcpy(cmd.alt_dest.dgid, attr->alt_ah_attr.grh.dgid.raw, 16);
	// cmd.alt_dest.flow_label    = attr->alt_ah_attr.grh.flow_label;
	// cmd.alt_dest.dlid 	    = attr->alt_ah_attr.dlid;
	// cmd.alt_dest.reserved	    = 0;
	// cmd.alt_dest.sgid_index    = attr->alt_ah_attr.grh.sgid_index;
	// cmd.alt_dest.hop_limit     = attr->alt_ah_attr.grh.hop_limit;
	// cmd.alt_dest.traffic_class = attr->alt_ah_attr.grh.traffic_class;
	// cmd.alt_dest.sl 	    = attr->alt_ah_attr.sl;
	// cmd.alt_dest.src_path_bits = attr->alt_ah_attr.src_path_bits;
	// cmd.alt_dest.static_rate   = attr->alt_ah_attr.static_rate;
	// cmd.alt_dest.is_global     = attr->alt_ah_attr.is_global;
	// cmd.alt_dest.port_num 	    = attr->alt_ah_attr.port_num;

	// cmd.reserved[0] = cmd.reserved[1] = 0;

	// if (write(d->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	return 0;
}

int ibv_cmd_query_xrc_rcv_qp(struct ibv_xrc_domain *d, uint32_t xrc_qp_num,
			     struct ibv_qp_attr *attr, int attr_mask,
			     struct ibv_qp_init_attr *init_attr)
{
	// struct ibv_query_xrc_rcv_qp cmd;
	// struct ibv_query_qp_resp resp;

	// if (abi_ver < 6)
	// 	return ENOSYS;

	// IBV_INIT_CMD_RESP(&cmd, sizeof cmd, QUERY_XRC_RCV_QP, &resp,
	// 		  sizeof resp);
	// cmd.xrc_domain_handle = d->handle;
	// cmd.qp_num = xrc_qp_num;
	// cmd.attr_mask = attr_mask;

	// if (write(d->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// attr->qkey                          = resp.qkey;
	// attr->rq_psn                        = resp.rq_psn;
	// attr->sq_psn                        = resp.sq_psn;
	// attr->dest_qp_num                   = resp.dest_qp_num;
	// attr->qp_access_flags               = resp.qp_access_flags;
	// attr->pkey_index                    = resp.pkey_index;
	// attr->alt_pkey_index                = resp.alt_pkey_index;
	// attr->qp_state                      = (ibv_qp_state) resp.qp_state;
	// attr->cur_qp_state                  = (ibv_qp_state) resp.cur_qp_state;
	// attr->path_mtu                      = (ibv_mtu) resp.path_mtu;
	// attr->path_mig_state                = (ibv_mig_state) resp.path_mig_state;
	// attr->sq_draining                   = resp.sq_draining;
	// attr->max_rd_atomic                 = resp.max_rd_atomic;
	// attr->max_dest_rd_atomic            = resp.max_dest_rd_atomic;
	// attr->min_rnr_timer                 = resp.min_rnr_timer;
	// attr->port_num                      = resp.port_num;
	// attr->timeout                       = resp.timeout;
	// attr->retry_cnt                     = resp.retry_cnt;
	// attr->rnr_retry                     = resp.rnr_retry;
	// attr->alt_port_num                  = resp.alt_port_num;
	// attr->alt_timeout                   = resp.alt_timeout;
	// attr->cap.max_send_wr               = resp.max_send_wr;
	// attr->cap.max_recv_wr               = resp.max_recv_wr;
	// attr->cap.max_send_sge              = resp.max_send_sge;
	// attr->cap.max_recv_sge              = resp.max_recv_sge;
	// attr->cap.max_inline_data           = resp.max_inline_data;

	// memcpy(attr->ah_attr.grh.dgid.raw, resp.dest.dgid, 16);
	// attr->ah_attr.grh.flow_label        = resp.dest.flow_label;
	// attr->ah_attr.dlid                  = resp.dest.dlid;
	// attr->ah_attr.grh.sgid_index        = resp.dest.sgid_index;
	// attr->ah_attr.grh.hop_limit         = resp.dest.hop_limit;
	// attr->ah_attr.grh.traffic_class     = resp.dest.traffic_class;
	// attr->ah_attr.sl                    = resp.dest.sl;
	// attr->ah_attr.src_path_bits         = resp.dest.src_path_bits;
	// attr->ah_attr.static_rate           = resp.dest.static_rate;
	// attr->ah_attr.is_global             = resp.dest.is_global;
	// attr->ah_attr.port_num              = resp.dest.port_num;

	// memcpy(attr->alt_ah_attr.grh.dgid.raw, resp.alt_dest.dgid, 16);
	// attr->alt_ah_attr.grh.flow_label    = resp.alt_dest.flow_label;
	// attr->alt_ah_attr.dlid              = resp.alt_dest.dlid;
	// attr->alt_ah_attr.grh.sgid_index    = resp.alt_dest.sgid_index;
	// attr->alt_ah_attr.grh.hop_limit     = resp.alt_dest.hop_limit;
	// attr->alt_ah_attr.grh.traffic_class = resp.alt_dest.traffic_class;
	// attr->alt_ah_attr.sl                = resp.alt_dest.sl;
	// attr->alt_ah_attr.src_path_bits     = resp.alt_dest.src_path_bits;
	// attr->alt_ah_attr.static_rate       = resp.alt_dest.static_rate;
	// attr->alt_ah_attr.is_global         = resp.alt_dest.is_global;
	// attr->alt_ah_attr.port_num          = resp.alt_dest.port_num;

	// init_attr->cap.max_send_wr          = resp.max_send_wr;
	// init_attr->cap.max_recv_wr          = resp.max_recv_wr;
	// init_attr->cap.max_send_sge         = resp.max_send_sge;
	// init_attr->cap.max_recv_sge         = resp.max_recv_sge;
	// init_attr->cap.max_inline_data      = resp.max_inline_data;
	// init_attr->sq_sig_all               = resp.sq_sig_all;

	return 0;
}

// static int ibv_cmd_destroy_qp_v1(struct ibv_qp *qp)
// {
	// struct ibv_destroy_qp_v1 cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, DESTROY_QP);
	// cmd.qp_handle = qp->handle;

	// if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

// 	return 0;
// }

int ibv_cmd_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad_wr)
{
	// struct ibv_post_send     *cmd;
	// struct ibv_post_send_resp resp;
	// struct ibv_send_wr       *i;
	// struct ibv_kern_send_wr  *n, *tmp;
	// struct ibv_sge           *s;
	// unsigned                  wr_count = 0;
	// unsigned                  sge_count = 0;
	// int                       cmd_size;
    int                       ret = 0;

	// for (i = wr; i; i = i->next) {
	// 	wr_count++;
	// 	sge_count += i->num_sge;
	// }

	// cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	// cmd  = alloca(cmd_size);

	// IBV_INIT_CMD_RESP(cmd, cmd_size, POST_SEND, &resp, sizeof resp);
	// cmd->qp_handle = ibqp->handle;
	// cmd->wr_count  = wr_count;
	// cmd->sge_count = sge_count;
	// cmd->wqe_size  = sizeof *n;

	// n = (struct ibv_kern_send_wr *) ((void *) cmd + sizeof *cmd);
	// s = (struct ibv_sge *) (n + wr_count);

	// tmp = n;
	// for (i = wr; i; i = i->next) {
	// 	tmp->wr_id 	= i->wr_id;
	// 	tmp->num_sge 	= i->num_sge;
	// 	tmp->opcode 	= i->opcode;
	// 	tmp->send_flags = i->send_flags;
	// 	tmp->imm_data 	= i->imm_data;
	// 	if (ibqp->qp_type == IBV_QPT_UD) {
	// 		tmp->wr.ud.ah 	       = i->wr.ud.ah->handle;
	// 		tmp->wr.ud.remote_qpn  = i->wr.ud.remote_qpn;
	// 		tmp->wr.ud.remote_qkey = i->wr.ud.remote_qkey;
	// 	} else {
	// 		switch (i->opcode) {
	// 		case IBV_WR_RDMA_WRITE:
	// 		case IBV_WR_RDMA_WRITE_WITH_IMM:
	// 		case IBV_WR_RDMA_READ:
	// 			tmp->wr.rdma.remote_addr =
	// 				i->wr.rdma.remote_addr;
	// 			tmp->wr.rdma.rkey = i->wr.rdma.rkey;
	// 			break;
	// 		case IBV_WR_ATOMIC_CMP_AND_SWP:
	// 		case IBV_WR_ATOMIC_FETCH_AND_ADD:
	// 			tmp->wr.atomic.remote_addr =
	// 				i->wr.atomic.remote_addr;
	// 			tmp->wr.atomic.compare_add =
	// 				i->wr.atomic.compare_add;
	// 			tmp->wr.atomic.swap = i->wr.atomic.swap;
	// 			tmp->wr.atomic.rkey = i->wr.atomic.rkey;
	// 			break;
	// 		default:
	// 			break;
	// 		}
	// 	}

	// 	if (tmp->num_sge) {
	// 		memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
	// 		s += tmp->num_sge;
	// 	}

	// 	tmp++;
	// }

	// resp.bad_wr = 0;
	// if (write(ibqp->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	ret = errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// wr_count = resp.bad_wr;
	// if (wr_count) {
	// 	i = wr;
	// 	while (--wr_count)
	// 		i = i->next;
	// 	*bad_wr = i;
	// } else if (ret)
	// 	*bad_wr = wr;

	return ret;
}

int ibv_cmd_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	// struct ibv_post_recv     *cmd;
	// struct ibv_post_recv_resp resp;
	// struct ibv_recv_wr       *i;
	// struct ibv_kern_recv_wr  *n, *tmp;
	// struct ibv_sge           *s;
	// unsigned                  wr_count = 0;
	// unsigned                  sge_count = 0;
	// int                       cmd_size;
	int                       ret = 0;

	// for (i = wr; i; i = i->next) {
	// 	wr_count++;
	// 	sge_count += i->num_sge;
	// }

	// cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	// cmd  = alloca(cmd_size);

	// IBV_INIT_CMD_RESP(cmd, cmd_size, POST_RECV, &resp, sizeof resp);
	// cmd->qp_handle = ibqp->handle;
	// cmd->wr_count  = wr_count;
	// cmd->sge_count = sge_count;
	// cmd->wqe_size  = sizeof *n;

	// n = (struct ibv_kern_recv_wr *) ((void *) cmd + sizeof *cmd);
	// s = (struct ibv_sge *) (n + wr_count);

	// tmp = n;
	// for (i = wr; i; i = i->next) {
	// 	tmp->wr_id   = i->wr_id;
	// 	tmp->num_sge = i->num_sge;

	// 	if (tmp->num_sge) {
	// 		memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
	// 		s += tmp->num_sge;
	// 	}

	// 	tmp++;
	// }

	// resp.bad_wr = 0;
	// if (write(ibqp->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	ret = errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// wr_count = resp.bad_wr;
	// if (wr_count) {
	// 	i = wr;
	// 	while (--wr_count)
	// 		i = i->next;
	// 	*bad_wr = i;
	// } else if (ret)
	// 	*bad_wr = wr;

	return ret;
}

int ibv_cmd_post_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	// struct ibv_post_srq_recv *cmd;
	// struct ibv_post_srq_recv_resp resp;
	// struct ibv_recv_wr       *i;
	// struct ibv_kern_recv_wr  *n, *tmp;
	// struct ibv_sge           *s;
	// unsigned                  wr_count = 0;
	// unsigned                  sge_count = 0;
	// int                       cmd_size;
	int                       ret = 0;

	// for (i = wr; i; i = i->next) {
	// 	wr_count++;
	// 	sge_count += i->num_sge;
	// }

	// cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	// cmd  = alloca(cmd_size);

	// IBV_INIT_CMD_RESP(cmd, cmd_size, POST_SRQ_RECV, &resp, sizeof resp);
	// cmd->srq_handle = srq->handle;
	// cmd->wr_count  = wr_count;
	// cmd->sge_count = sge_count;
	// cmd->wqe_size  = sizeof *n;

	// n = (struct ibv_kern_recv_wr *) ((void *) cmd + sizeof *cmd);
	// s = (struct ibv_sge *) (n + wr_count);

	// tmp = n;
	// for (i = wr; i; i = i->next) {
	// 	tmp->wr_id = i->wr_id;
	// 	tmp->num_sge = i->num_sge;

	// 	if (tmp->num_sge) {
	// 		memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
	// 		s += tmp->num_sge;
	// 	}

	// 	tmp++;
	// }

	// resp.bad_wr = 0;
	// if (write(srq->context->cmd_fd, cmd, cmd_size) != cmd_size)
	// 	ret = errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// wr_count = resp.bad_wr;
	// if (wr_count) {
	// 	i = wr;
	// 	while (--wr_count)
	// 		i = i->next;
	// 	*bad_wr = i;
	// } else if (ret)
	// 	*bad_wr = wr;

	return ret;
}

int ibv_cmd_create_ah(struct ibv_pd *pd, struct ibv_ah *ah,
		      struct ibv_ah_attr *attr)
{
	// struct ibv_create_ah      cmd;
	// struct ibv_create_ah_resp resp;

	// IBV_INIT_CMD_RESP(&cmd, sizeof cmd, CREATE_AH, &resp, sizeof resp);
	// cmd.user_handle            = (uintptr_t) ah;
	// cmd.pd_handle              = pd->handle;
	// cmd.attr.dlid              = attr->dlid;
	// cmd.attr.sl                = attr->sl;
	// cmd.attr.src_path_bits     = attr->src_path_bits;
	// cmd.attr.static_rate       = attr->static_rate;
	// cmd.attr.is_global         = attr->is_global;
	// cmd.attr.port_num          = attr->port_num;
	// cmd.attr.grh.flow_label    = attr->grh.flow_label;
	// cmd.attr.grh.sgid_index    = attr->grh.sgid_index;
	// cmd.attr.grh.hop_limit     = attr->grh.hop_limit;
	// cmd.attr.grh.traffic_class = attr->grh.traffic_class;
	// memcpy(cmd.attr.grh.dgid, attr->grh.dgid.raw, 16);

	// if (write(pd->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// ah->handle  = resp.handle;
	// ah->context = pd->context;

	return 0;
}

int ibv_cmd_destroy_ah(struct ibv_ah *ah)
{
	// struct ibv_destroy_ah cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, DESTROY_AH);
	// cmd.ah_handle = ah->handle;

	// if (write(ah->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	return 0;
}

int ibv_cmd_destroy_qp(struct ibv_qp *qp)
{
	// struct ibv_destroy_qp      cmd;
	// struct ibv_destroy_qp_resp resp;

	// if (abi_ver == 1)
	// 	return ibv_cmd_destroy_qp_v1(qp);

	// IBV_INIT_CMD_RESP(&cmd, sizeof cmd, DESTROY_QP, &resp, sizeof resp);
	// cmd.qp_handle = qp->handle;
	// cmd.reserved  = 0;

	// if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	// VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// pthread_mutex_lock(&qp->mutex);
	// while (qp->events_completed != resp.events_reported)
	// 	pthread_cond_wait(&qp->cond, &qp->mutex);
	// pthread_mutex_unlock(&qp->mutex);

	return 0;
}

int ibv_cmd_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	// struct ibv_attach_mcast cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, ATTACH_MCAST);
	// memcpy(cmd.gid, gid->raw, sizeof cmd.gid);
	// cmd.qp_handle = qp->handle;
	// cmd.mlid      = lid;
	// cmd.reserved  = 0;

	// if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	return 0;
}

int ibv_cmd_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	// struct ibv_detach_mcast cmd;

	// IBV_INIT_CMD(&cmd, sizeof cmd, DETACH_MCAST);
	// memcpy(cmd.gid, gid->raw, sizeof cmd.gid);
	// cmd.qp_handle = qp->handle;
	// cmd.mlid      = lid;
	// cmd.reserved  = 0;

	// if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	return 0;
}

int ibv_cmd_open_xrc_domain(struct ibv_context *context, int fd, int oflag,
			    struct ibv_xrc_domain *d,
			    struct ibv_open_xrc_domain_resp *resp,
			    size_t resp_size)
{
	// struct ibv_open_xrc_domain cmd;

	// if (abi_ver < 6)
	// 	return ENOSYS;

	// IBV_INIT_CMD_RESP(&cmd, sizeof cmd, OPEN_XRC_DOMAIN, resp, resp_size);
	// cmd.fd = fd;
	// cmd.oflags = oflag;

	// if (write(context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;

	// d->handle = resp->xrcd_handle;

	return 0;
}

int ibv_cmd_close_xrc_domain(struct ibv_xrc_domain *d)
{
	// struct ibv_close_xrc_domain cmd;

	// if (abi_ver < 6)
	// 	return ENOSYS;

	// IBV_INIT_CMD(&cmd, sizeof cmd, CLOSE_XRC_DOMAIN);
	// cmd.xrcd_handle = d->handle;

	// if (write(d->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;
	return 0;
}

int ibv_cmd_reg_xrc_rcv_qp(struct ibv_xrc_domain *d, uint32_t xrc_qp_num)
{
	// struct ibv_reg_xrc_rcv_qp cmd;

	// if (abi_ver < 6)
	// 	return ENOSYS;

	// IBV_INIT_CMD(&cmd, sizeof cmd, REG_XRC_RCV_QP);
	// cmd.xrc_domain_handle = d->handle;
	// cmd.qp_num = xrc_qp_num;

	// if (write(d->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;
	return 0;
}

int ibv_cmd_unreg_xrc_rcv_qp(struct ibv_xrc_domain *d, uint32_t xrc_qp_num)
{
	// struct ibv_unreg_xrc_rcv_qp cmd;

	// if (abi_ver < 6)
	// 	return ENOSYS;

	// IBV_INIT_CMD(&cmd, sizeof cmd, UNREG_XRC_RCV_QP);
	// cmd.xrc_domain_handle = d->handle;
	// cmd.qp_num = xrc_qp_num;

	// if (write(d->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
	// 	return errno;
	return 0;
}

END_C_DECLS
