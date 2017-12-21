
#include <osv/mempool.hh>
#include <osv/interrupt.hh>
#include <osv/sched.hh>
#include <osv/ilog2.hh>
#include <linux/err.h>

#include "drivers/virtio-rdma.hh"

namespace virtio {

void rdma::copy_virt_conn_param_to_rdmacm(const struct vrdmacm_conn_param *src,
                               struct rdma_conn_param *dst)
{
    if (src->private_data_len) {
        dst->private_data = (__u8 *) malloc(src->private_data_len);
        memcpy((void *) dst->private_data, src->private_data,
               src->private_data_len);
    }

    dst->private_data_len = src->private_data_len;
    dst->responder_resources = src->responder_resources;
    dst->initiator_depth = src->initiator_depth;
    dst->flow_control = src->flow_control;
    dst->retry_count = src->retry_count;
    dst->rnr_retry_count = src->rnr_retry_count;
    dst->srq = src->srq;
    dst->qp_num = src->qp_num;
    // we don't have qkey member in the user space
    // dst->qkey = src->qkey;
}

void rdma::copy_rdmacm_conn_param_to_virt(const struct rdma_conn_param *src,
                               struct vrdmacm_conn_param *dst)
{
    if (src->private_data_len) {
        memcpy((void *) dst->private_data, src->private_data,
               src->private_data_len);
    }

    dst->private_data_len = src->private_data_len;
    dst->responder_resources = src->responder_resources;
    dst->initiator_depth = src->initiator_depth;
    dst->flow_control = src->flow_control;
    dst->retry_count = src->retry_count;
    dst->rnr_retry_count = src->rnr_retry_count;
    dst->srq = src->srq;
    dst->qp_num = src->qp_num;
    // we don't have qkey member in the user space
    // dst->qkey = src->qkey;
}

void rdma::copy_virt_event_to_rdmacm(const struct vrdmacm_event *vevent,
                                     struct rdma_cm_event *event)
{
    copy_virt_conn_param_to_rdmacm(&vevent->param.conn, &event->param.conn);

    event->event = (rdma_cm_event_type) vevent->event;
    event->status = vevent->status;
}

void rdma::copy_rdmacm_event_to_virt(const struct rdma_cm_event *event,
                                     vrdmacm_event *vevent)
{
    copy_rdmacm_conn_param_to_virt(&event->param.conn, &vevent->param.conn);

    vevent->event = event->event;
    vevent->status = event->status;
}

int rdma::post_event(struct vrdmacm_id_priv *priv_id)
{
    int ret;
    vrdmacm_event *event;

    debug("vRDMA: post_event\n");

    /* we might be in interrupt context */
    event = (vrdmacm_event *) kmalloc(sizeof(*event), GFP_ATOMIC);
    if (!event) {
        debug("could not allocate event\n");
        ret = -ENOMEM;
        goto fail;
    }

    {
        uint32_t i = 0;
        struct _args_t {
            struct hcall_async async;
            struct vrdmacm_post_event_copy_args copy_args;
            struct vrdmacm_post_event_result result;
            struct hcall_parg pargs[1];
        } *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), mem_flags);
        if (!_args) { return -ENOMEM; }

        _args->async.cb = true;
        _args->async.data = priv_id;
        _args->async.hret = (hcall_ret_header*) &_args->result.hdr;
        _args->async.pargs = _args->pargs;
        _args->pargs[i++] = (struct hcall_parg) { event, sizeof(*event) };
        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_POST_EVENT, 1, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };

        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));

        ret = do_hcall_async(hyv_dev.vg->vq_hcall, &_args->async, &_args->copy_args.hdr,
                                  sizeof(_args->copy_args), i, sizeof(_args->result));
        return ret;
    }
    if (ret) {
        debug("post event hypercall failed: %d!\n", ret);
        goto fail_event;
    }

    return 0;
fail_event:
    kfree(event);
fail:
    return ret;
}

int rdma::vrdmacm_create_id(struct rdma_event_channel *channel, void *context, uint64_t uid, enum rdma_port_space ps)
{
    struct vrdmacm_id_priv *priv_id;
    int ret, hret;
    enum ib_qp_type qp_type;

    debug("vRDMA: vrdmacm_create_id\n");

    switch (ps) {
    case RDMA_PS_TCP:
        qp_type = IB_QPT_RC;
        break;
    case RDMA_PS_UDP:
    case RDMA_PS_IPOIB:
        qp_type = IB_QPT_UD;
        break;
    case RDMA_PS_IB:
        // qp_type = cmd->qp_type;
        break;
    default:
        break;
    }

    priv_id = (struct vrdmacm_id_priv *) kzalloc(sizeof(*priv_id), GFP_KERNEL);
    if (!priv_id) {
        debug("could not allocate id\n");
        ret = -ENOMEM;
        goto fail;
    }

    priv_id->id.context = context;
//    priv_id->id.event_handler = event_handler;
    priv_id->id.ps = ps;
    priv_id->id.qp_type = (enum ibv_qp_type) qp_type;
    priv_id->conn_done = 0;

    {
        const struct hcall_parg pargs[] = { };
        struct _args_t {
            struct vrdmacm_create_id_copy_args copy_args;
            struct vrdmacm_create_id_result result;
        } *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), mem_flags);
        if (!_args) { ret = -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_CREATE_ID, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST,};

        memcpy(&_args->copy_args.guest_handle, &priv_id, sizeof(priv_id));
        memcpy(&_args->copy_args.port_space, &ps, sizeof(ps));
        memcpy(&_args->copy_args.qp_type, &qp_type, sizeof(qp_type));
        memcpy(&_args->copy_args.uid, &uid, sizeof(uid));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args),
                                pargs, (sizeof(pargs) / sizeof((pargs)[0])),
                                &_args->result.hdr, sizeof(_args->result));
        if (!ret)
            memcpy(&hret, &_args->result.value, sizeof(hret));
        kfree(_args);
    }
    if (ret || hret < 0) {
        debug("could not create id on host: ret: %d, hret: %d\n", ret, hret);
        ret = ret ? ret : hret;
        goto fail_id;
    }

    // used as ucma_context->cm_id
    priv_id->host_handle = hret;

    // set up the event channel using host_handle
    channel->fd = priv_id->host_handle;

    post_event(priv_id);

    return hret;
fail_id:
    kfree(priv_id);
fail:
    return -EFAULT;
}

struct rdma::vrdmacm_id_priv* rdma::rdmacm_id_to_priv(struct rdma_cm_id *id)
{
    return container_of(id, struct vrdmacm_id_priv, id);
}

struct ib_device * rdma::rdmacm_get_ibdev(__be64 node_guid)
{
    if (hyv_dev.ib_dev.node_guid == node_guid) {
        return &hyv_dev.ib_dev;
    }
    return NULL;
}

int rdma::vrdmacm_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
    struct vrdmacm_id_priv *priv_id = rdmacm_id_to_priv(id);
    int ret, hret;
    __be64 *node_guid;
    struct sockaddr *src_addr;

    debug("vRDMA: vrdmacm_bind_addr\n");

    node_guid = (__be64 *) kmalloc(sizeof(*node_guid), GFP_KERNEL);
    src_addr = (struct sockaddr *) kmalloc(sizeof(*src_addr), GFP_KERNEL);
    memcpy(src_addr, addr, sizeof(*src_addr));

    {
        int src_available = addr!=NULL?1:0;
        const struct hcall_parg pargs[] = {
            { src_addr, sizeof(*src_addr) } ,
            { node_guid, sizeof(*node_guid) } ,
            { &id->route, sizeof(id->route) } ,
            { &id->port_num, sizeof(id->port_num) } , };
        struct _args_t {
            struct vrdmacm_bind_addr_copy_args copy_args;
            struct vrdmacm_bind_addr_result result;
        } *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), mem_flags);
        if (!_args) { return -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_BIND_ADDR, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST, };

        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));
        memcpy(&_args->copy_args.src_available, &src_available, sizeof(src_available));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr,
                            sizeof(_args->copy_args), pargs, (sizeof(pargs) / sizeof((pargs)[0])),
                            &_args->result.hdr, sizeof(_args->result));
        if (!ret)
            memcpy(&hret, &_args->result.value, sizeof(hret));
        kfree(_args);
    }
    if (ret) {
        debug("could not bind addr on host: ret: %d, hret: %d\n", ret, hret);
        ret = ret ? ret : hret;
    }

    priv_id->device = rdmacm_get_ibdev(*node_guid);

    return ret;
}


int rdma::vrdmacm_query_route(struct rdma_cm_id *id, struct ucma_abi_query_route_resp *resp)
{
    struct vrdmacm_id_priv *priv_id = rdmacm_id_to_priv(id);
    int ret, hret;
    struct ucma_abi_query_route_resp *kresp;

    debug("vRDMA: vrdmacm_query_route\n");

    kresp = (struct ucma_abi_query_route_resp *) kmalloc(sizeof(*kresp), GFP_KERNEL);

    memset(kresp, 0, sizeof(*kresp));

    {
        const struct hcall_parg pargs[] = {
            { kresp, sizeof(*kresp) } ,};
        struct _args_t {
            struct vrdmacm_query_route_copy_args copy_args;
            struct vrdmacm_query_route_result result;
        } *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), mem_flags);
        if (!_args) { return -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_QUERY_ROUTE, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST, };

        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr,
                            sizeof(_args->copy_args), pargs, (sizeof(pargs) / sizeof((pargs)[0])),
                            &_args->result.hdr, sizeof(_args->result));
        if (!ret)
            memcpy(&hret, &_args->result.value, sizeof(hret));
        kfree(_args);
    }
    if (ret) {
        debug("could not query route on host: ret: %d, hret: %d\n", ret, hret);
        ret = ret ? ret : hret;
    }

    memcpy(resp, kresp, sizeof(*resp));

    return ret;
}

int rdma::vrdmacm_listen(struct rdma_cm_id *id, int backlog)
{
    struct vrdmacm_id_priv *priv_id = rdmacm_id_to_priv(id);
    int ret, hret;

    debug("vRDMA: vrdmacm_listen\n");

    {
        const struct hcall_parg pargs[] = { };
        struct _args_t {
            struct vrdmacm_listen_copy_args copy_args;
            struct vrdmacm_listen_result result;
        } *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), mem_flags);
        if (!_args) { return -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_LISTEN, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));
        memcpy(&_args->copy_args.backlog, &backlog, sizeof(backlog));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args), pargs,
                                (sizeof(pargs) / sizeof((pargs)[0])), &_args->result.hdr, sizeof(_args->result));

        if (!ret)
            memcpy(&hret, &_args->result.value, sizeof(hret));

        kfree(_args);
    }
    if (ret || hret) {
        debug("could not start listen on host: ret: %d, hret: %d\n", ret, hret);
        ret = ret ? ret : hret;
    }

    post_event(priv_id);

    return hret;
}

int rdma::vrdmacm_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
                            struct sockaddr *dst_addr, int timeout_ms)
{
    struct vrdmacm_id_priv *priv_id = rdmacm_id_to_priv(id);
    int ret, hret;
    uint32_t addr_size;
    struct sockaddr *addr;

    debug("vRDMA: vrdmacm_resolve_addr\n");

    addr = (sockaddr*) kmalloc(sizeof(*addr) * 2, GFP_KERNEL);
    if (!addr) {
        debug("could not alloc addr\n");
        ret = -ENOMEM;
        goto fail;
    }
    if (src_addr) {
        memcpy(addr, src_addr, sizeof(*src_addr));
    }
    if (dst_addr) {
        memcpy(addr + 1, dst_addr, sizeof(*dst_addr));
    }

    addr_size = sizeof(*addr) * 2;

    {
        uint32_t src_available = src_addr != NULL;
        uint32_t dst_available = dst_addr != NULL;

        const struct hcall_parg pargs[] = { { addr, addr_size } , };
        struct _args_t {
            struct vrdmacm_resolve_addr_copy_args copy_args;
            struct vrdmacm_resolve_addr_result result;
        } *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), mem_flags);
        if (!_args) { return -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_RESOLVE_ADDR, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));
        memcpy(&_args->copy_args.timeout_ms, &timeout_ms, sizeof(timeout_ms));
        memcpy(&_args->copy_args.src_available, &src_available, sizeof(src_available));
        memcpy(&_args->copy_args.dst_available, &dst_available, sizeof(dst_available));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args), pargs,
                                (sizeof(pargs) / sizeof((pargs)[0])), &_args->result.hdr, sizeof(_args->result));
        if (!ret)
            memcpy(&hret, &_args->result.value, sizeof(hret));

        kfree(_args);
    }
    if (ret || hret) {
        debug("could not resolve addr on host\n");
        ret = ret ? ret : hret;
    }
    kfree(addr);

    post_event(priv_id);

fail:
    return ret;
}


int rdma::vrdmacm_init_qp_attr(struct rdma_cm_id *id, struct ibv_qp_attr *qp_attr, int *qp_attr_mask)
{
    struct vrdmacm_id_priv *priv_id = rdmacm_id_to_priv(id);
    struct ib_qp_attr *kqp_attr;
    int ret, hret, *kqp_attr_mask;

    debug("vRDMA: vrdmacm_init_qp_attr\n");

    kqp_attr = (ib_qp_attr *) kmalloc(sizeof(*kqp_attr), GFP_KERNEL);
    if (!kqp_attr) {
        debug("could not allocate qp_attr param\n");
        ret = -ENOMEM;
        goto fail;
    }

    kqp_attr_mask = (int *) kmalloc(sizeof(*kqp_attr_mask), GFP_KERNEL);
    if (!kqp_attr_mask) {
        debug("could not allocate qp_attr_mask param\n");
        ret = -ENOMEM;
        goto fail;
    }

    memcpy(kqp_attr, qp_attr, sizeof(*qp_attr));
    memcpy(kqp_attr_mask, qp_attr_mask, sizeof(*qp_attr_mask));

    {
        const struct hcall_parg pargs[] = { { kqp_attr, sizeof(*kqp_attr) } , { kqp_attr_mask, sizeof(*kqp_attr_mask) } , };
        struct _args_t {
            struct vrdmacm_init_qp_attr_copy_args copy_args;
            struct vrdmacm_init_qp_attr_result result;
        } *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), GFP_KERNEL);
        if (!_args) { return -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_INIT_QP_ATTR, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args), pargs,
                            sizeof(pargs) / sizeof((pargs)[0]), &_args->result.hdr, sizeof(_args->result));

        if (!ret) memcpy(&hret, &_args->result.value, sizeof(hret));
        kfree(_args);
    }
    if (ret || hret) {
        debug("could not init qp attr on host\n");
        ret = ret ? ret : hret;
    }

    memcpy(qp_attr, kqp_attr, sizeof(*kqp_attr));
    memcpy(qp_attr_mask, kqp_attr_mask, sizeof(*kqp_attr_mask));

    kfree(kqp_attr);
    kfree(kqp_attr_mask);

fail:
    return ret;
}


int rdma::vrdmacm_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
    struct vrdmacm_id_priv *priv_id = rdmacm_id_to_priv(id);
    vrdmacm_conn_param *vconn_param;
    int ret, hret;

    debug("vRDMA: vrdmacm_connect\n");

    vconn_param = (struct vrdmacm_conn_param *) kmalloc(sizeof(*vconn_param), GFP_KERNEL);
    if (!vconn_param) {
        debug("could not allocate conn param\n");
        ret = -ENOMEM;
        goto fail;
    }

    if (id->qp) {
        conn_param->qp_num = id->qp->qp_num;
        conn_param->srq = id->qp->srq != NULL;
    }

    copy_rdmacm_conn_param_to_virt(conn_param, vconn_param);

    {
        const struct hcall_parg pargs[] = { { vconn_param, sizeof(*vconn_param) } , };

        struct _args_t {
            struct vrdmacm_connect_copy_args copy_args;
            struct vrdmacm_connect_result result;
        } *_args;

        _args = ( _args_t  *) kmalloc(sizeof(*_args), GFP_KERNEL);
        if (!_args) { return -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_CONNECT, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };

        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args), pargs,
                            sizeof(pargs) / sizeof((pargs)[0]), &_args->result.hdr, sizeof(_args->result));

        if (!ret) memcpy(&hret, &_args->result.value, sizeof(hret));
        kfree(_args);
    }
    if (ret || hret) {
        debug("could not connect on host\n");
        ret = ret ? ret : hret;
    }

    post_event(priv_id);

    kfree(vconn_param);

fail:
    return ret;
}


int rdma::vrdmacm_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
    struct vrdmacm_id_priv *priv_id = rdmacm_id_to_priv(id);
    int ret, hret;
    vrdmacm_conn_param *vconn_param;

    debug("vRDMA: vrdmacm_accept\n");

    vconn_param = (struct vrdmacm_conn_param *) kmalloc(sizeof(*vconn_param), GFP_KERNEL);
    if (!vconn_param) {
        debug("could not allocate conn param\n");
        ret = -ENOMEM;
        goto fail;
    }

    if(conn_param) {
        if (id->qp && conn_param) {
            conn_param->qp_num = id->qp->qp_num;
            conn_param->srq = id->qp->srq != NULL;
        }
        copy_rdmacm_conn_param_to_virt(conn_param, vconn_param);
    }

    {
        __u32 param_available = conn_param != NULL;
        const struct hcall_parg pargs[] = { { vconn_param, sizeof(*vconn_param) } , };
        struct _args_t {
            struct vrdmacm_accept_copy_args copy_args;
            struct vrdmacm_accept_result result; }
        *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), GFP_KERNEL);
        if (!_args) { return -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_ACCEPT, 0,  HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };

        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));
        memcpy(&_args->copy_args.param_available, &param_available, sizeof(param_available));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args), pargs,
                            sizeof(pargs) / sizeof((pargs)[0]), &_args->result.hdr, sizeof(_args->result));

        if (!ret) memcpy(&hret, &_args->result.value, sizeof(hret));
        kfree(_args);
    }

    if (ret || hret) {
        debug("could not accept connection on host\n");
        ret = ret ? ret : hret;
    }

    kfree(vconn_param);
fail:
    return ret;
}


void rdma::vrdmacm_destroy_id(struct rdma_cm_id *id)
{
    struct vrdmacm_id_priv *priv_id = rdmacm_id_to_priv(id);
    int ret, hret;

    debug("vRDMA: vrdmacm_destroy_id\n");

    {
        const struct hcall_parg pargs[] = { };

        struct _args_t {
            struct vrdmacm_destroy_id_copy_args copy_args;
            struct vrdmacm_destroy_id_result result;
        } *_args;

        _args = (_args_t *) kmalloc(sizeof(*_args), GFP_KERNEL);
        if (!_args) { ret = -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_RDMACM_DESTROY_ID, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
        memcpy(&_args->copy_args.ctx_handle, &priv_id->host_handle, sizeof(priv_id->host_handle));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args), pargs,
                            sizeof(pargs) / sizeof((pargs)[0]), &_args->result.hdr, sizeof(_args->result));

        if (!ret) memcpy(&hret, &_args->result.value, sizeof(hret));

        kfree(_args);
    }
    if (ret || hret) {
        debug("could not destroy id on host\n");
    }

    if(priv_id->conn_done){
        debug("free priv_id: %p\n", priv_id);
        kfree(priv_id);
    }
}


void rdma::vrdmacm_post_event_cb()
{
    int hcall_result;
    vrdmacm_id_priv * priv_id;
    struct vrdmacm_event *vevent;

    priv_id = (struct vrdmacm_id_priv *) &_hcall_queue.async->data;
    hcall_result = _hcall_queue.async->hret->value;
    vevent = (vrdmacm_event * ) _hcall_queue.async->pargs[0].ptr;

    priv_id->vevent = *vevent;

    // now process the event
    {
        debug("priv_id = 0x%p, event = { .event = %d, .status = %d }\n",
              priv_id, vevent->event, vevent->status);
        switch(vevent->event) {
        case RDMA_CM_EVENT_CONNECT_REQUEST:
        case RDMA_CM_EVENT_ADDR_RESOLVED:
        {
            struct ib_device *ibdev;

            debug("rdma addr resolved/connect request => set device\n");

            ibdev = rdmacm_get_ibdev(vevent->node_guid);
            if (!ibdev) {
                debug("device does not exists (%llx)\n",
                      vevent->node_guid);
                vevent->event = RDMA_CM_EVENT_ADDR_ERROR;
            } else {
                priv_id->device = ibdev;
            }
            debug("priv_id->id.device: %p\n", priv_id->device);

            break;
        }
        case RDMA_CM_EVENT_REJECTED:
        case RDMA_CM_EVENT_DISCONNECTED:
        case RDMA_CM_EVENT_ESTABLISHED:
            break;
        default:
            debug("Unknown event: %d!\n", vevent->event);
            goto fail;
        }
        /* TODO: handle destroy of cm */
        if (hcall_result) {
            debug("hypercall failed on host (%d)\n", hcall_result);
            goto fail;
        }
    }

fail:
    kfree(vevent);
}


int rdma::vrdmacm_get_cm_event(int fd, struct ucma_abi_event_resp *resp)
{
    vrdmacm_id_priv * priv_id;

    debug("vRDMA: vrdmacm_get_cm_event\n");

    pthread_mutex_lock(&_hcall_queue.lock);
    while(true) {
        pthread_cond_wait(&_hcall_queue.cond, &_hcall_queue.lock);
        // check if there is an event and if it's in our channel
        if (_hcall_queue.hcall_acked && fd == _hcall_queue.channel_fd) {
            break;
        }
    }

    priv_id = (struct vrdmacm_id_priv *) &_hcall_queue.async->data;
    _hcall_queue.hcall_acked = false;
    pthread_mutex_unlock(&_hcall_queue.lock);

    resp->uid = priv_id->vevent.uid;
    resp->event = priv_id->vevent.event;
    resp->status = priv_id->vevent.status;
    // TODO: add support for UD
    copy_virt_conn_param_to_rdmacm(&priv_id->vevent.param.conn, (rdma_conn_param*) &resp->param.conn);

    return 0;
}

}
