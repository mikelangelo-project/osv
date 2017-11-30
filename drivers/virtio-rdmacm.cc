
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

    debug("post_event\n");

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

int rdma::vrdmacm_create_id(struct rdma_event_channel *channel, void *context, enum rdma_port_space ps)
{
    struct vrdmacm_id_priv *priv_id;
    int ret, hret;
    enum ib_qp_type qp_type;

    debug("vrdmacm_create_id\n");

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
    priv_id->conn_done = false;

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
        memcpy(&_args->copy_args.qp_type, &qp_type, sizeof(qp_type));;

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

int rdma::vrdmacm_get_cm_event(int fd, struct rdma_cm_event *event)
{
    int hcall_result;
    vrdmacm_id_priv * priv_id;
    struct vrdmacm_event *vevent;

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
    hcall_result = _hcall_queue.async->hret->value;
    vevent = (vrdmacm_event * ) _hcall_queue.async->pargs[0].ptr;
    _hcall_queue.hcall_acked = false;
    pthread_mutex_unlock(&_hcall_queue.lock);

    event = (rdma_cm_event *) malloc(sizeof(*event));

    // now process the event
    {
        debug("priv_id = 0x%p, event = { .event = %d, .status = %d }\n",
              priv_id, vevent->event, vevent->status);

        // we don't need the the whole rdma_cm id from the host,
        // but we have to retrieve the address infomation of the endpoints
        priv_id->id.route.addr = vevent->route.addr;

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

        // TODO: add support for UD
        copy_virt_event_to_rdmacm(vevent, event);

        /* TODO: handle destroy of cm */
        if (hcall_result) {
            debug("hypercall failed on host (%d)\n", hcall_result);
            goto fail;
        }
    }

    return hcall_result;
fail:
    kfree(vevent);
    return hcall_result;
}

}
