
#include <osv/mempool.hh>
#include <osv/interrupt.hh>
#include <osv/sched.hh>
#include <osv/ilog2.hh>
#include <linux/err.h>

#include "drivers/virtio-rdma.hh"

namespace virtio {

// RDMA CM hypercalls
int rdma::vrdmacm_create_id(void *context, enum rdma_port_space ps)
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

    //post_event(priv_id);

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
        if (!_args) { ret = -ENOMEM; }

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
        if (!_args) { ret = -ENOMEM; }

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

}
