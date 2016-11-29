/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <osv/mempool.hh>
#include <osv/interrupt.hh>
#include <osv/sched.hh>
#include <linux/err.h>
#include "drivers/virtio-rdma.hh"


using namespace std;

namespace virtio {

rdma* rdma::_instance = nullptr;

rdma::rdma(pci::device& pci_dev)
    : virtio_driver(pci_dev)
    , _hcall_queue(get_virt_queue(0), [this] { this->handle_hcall(); })
    , _event_queue(get_virt_queue(1), [this] { this->handle_event(); })
{
    add_dev_status(VIRTIO_CONFIG_S_DRIVER_OK);

    sched::thread* event_poll_task = &_event_queue.event_poll_task;
    sched::thread* hcall_poll_task = &_hcall_queue.hcall_poll_task;

    event_poll_task->set_priority(sched::thread::priority_infinity);
    hcall_poll_task->set_priority(sched::thread::priority_infinity);

    //initialize the event queue
    _vg = (struct virtio_hyv*) malloc(sizeof(*_vg));
    if (!_vg) {
        debug("vRDMA: Could not allocate memory\n");
    }

    _vg->vdev = &pci_dev;
    _vg->cback = 0;

    _vg->vq_hcall = &_hcall_queue;
    _vg->vq_hcall->priv = _hcall_queue.priv;
    _hcall_queue.priv = _vg->vq_hcall;

    _vg->vq_event = &_event_queue;
    _vg->vq_event->vq = _event_queue.vq;

    _vg->evt_queue = (struct hyv_event_queue *) memory::alloc_page();
    if (!_vg->evt_queue) {
        debug("vRDMA: Could not allocate page\n");
    }

    // initialize the event queue list
    atomic_set((atomic_t*) &_vg->evt_queue->front, 0);
    atomic_set((atomic_t*) &_vg->evt_queue->back, 0);

    _vg->vq_event->vq->init_sg();
    _vg->vq_event->vq->add_in_sg(&_vg->evt_queue, memory::page_size);
    if (!_vg->vq_event->vq->add_buf(_vg->evt_queue)) {
        free(_vg->evt_queue);
        debug("vRDMA: Failed to add buffer to event queue.\n");
    }

    event_poll_task->start();
    hcall_poll_task->start();

    if (pci_dev.is_msix()) {
        _msi.easy_register({
                { 0, [&] { _vg->vq_hcall->vq->disable_interrupts(); }, hcall_poll_task },
                { 1, [&] { _vg->vq_event->vq->disable_interrupts(); }, event_poll_task }
        });
    } else {
         // have problem for compilation, but it's ok, as we use msix
         // _irq.reset(new pci_interrupt(pci_dev,
         //                              [=] { return this->ack_irq(); },
         //                              [=] { event_poll_task->wake(); }));
    }

    // the first event kick should have been done in probe phase,
    // we missed one irq before this initialization unfortunately,
    // but let's still register the guest ib device manually.
    _vg->vq_hcall->vq->kick();
    _vg->vq_event->vq->kick();

    register_ib_dev();

    _instance = this;
}

rdma::~rdma()
{
}

int rdma::register_ib_dev()
{
    int ret, result;

    debug("vRDMA: Register hyv device.\n");

    hyv_dev.vg = _vg;
    hyv_dev.host_handle = 0;
    //hyv_dev->dev.release = &hyv_release_dev;

    /* open device */
    ret = vrdma_open_device(&result);
    if (ret || result) {
        debug("vRDMA: Could not get device on host\n");
        ret = ret ? ret : result;
        goto fail_alloc;
    }

    /* query device */
    ib_uverbs_query_device_resp *attr;
    attr = (ib_uverbs_query_device_resp*) kmalloc(sizeof(*attr), GFP_KERNEL);
    if (!attr) {
        debug("vRDMA: Could not allocate device attr.\n");
        return -ENOMEM;
    }

    ret = vrdma_query_device(attr, &result);
    if (ret || result) {
        debug("vRDMA: Could not query device on host\n");
        kfree(attr);
        ret = ret ? ret : result;
        goto fail_get;
    }

    /* ib device initialization */
    hyv_dev.ib_dev.node_guid = attr->node_guid;
    hyv_dev.ib_dev.phys_port_cnt = attr->phys_port_cnt;

    /* use vendor/device id to match driver */
    hyv_dev.id.vendor = attr->vendor_id;
    hyv_dev.id.device = attr->vendor_part_id;

    // where can we get the device index in OSv??
    // dev->index =


    // initialize the struct members of ib_device
//    hyv_dev.ib_dev.ops->alloc_ucontext = vrdma_ibv_alloc_ucontext;

fail_get:
    // it seems we don't need to do so.
    // ret = hyv_put_ib_device(&dev->vg->vq_hcall,
    // 			HYPERCALL_NOTIFY_HOST | HYPERCALL_SIGNAL_GUEST,
    // 			GFP_KERNEL, &hret, dev->host_handle);
    // if (ret || hret) {
    // 	dprint(DBG_ON, "could not put device on host\n");
    // }

fail_alloc:
    return ret;
}

struct rdma::hyv_udata* rdma::udata_create(struct ib_udata *ibudata)
{
    int ret = -1;
    struct rdma::hyv_udata *udata;
    unsigned long inlen;

    debug("vRDMA: udata_create\n");


    if(ibudata->inlen < sizeof(struct ib_uverbs_cmd_hdr)) {
        debug("vRDMA: udata size is not correct. \n");
        goto fail;
    }

    inlen = ibudata->inlen - sizeof(struct ib_uverbs_cmd_hdr);

    debug("vRDMA: sizeof udata: %d, inlen: %d, outlen: %d\n", sizeof(*udata) , inlen , ibudata->outlen);

    udata = (rdma::hyv_udata *) kmalloc(sizeof(*udata) + inlen + ibudata->outlen, GFP_KERNEL);
    if (!udata) {
        debug("vRDMA: could not allocate udata\n");
        ret = -ENOMEM;
        goto fail;
    }
    udata->in = inlen;
    udata->out = ibudata->outlen;

    memcpy(udata->data, ibudata, inlen);

    return udata;
//fail_udata:
    kfree(udata);
fail:
    return (rdma::hyv_udata*) ERR_PTR(ret);
}


int rdma::udata_copy_out(hyv_udata *udata, struct ib_udata *ibudata)
{
    void *out = udata->data + udata->in;

    ibudata = (struct ib_udata *) out;

    return 0;
}

void rdma::ack_irq()
{
    debug("vRDMA: event irq handler.\n");
}

void rdma::handle_irq()
{
    debug("vRDMA: event irq handler.\n");
}

//virtio_hyv_event.c: virtio_hyv_ack_event
void rdma::handle_event()
{
    debug("vRDMA: evnet ack handler.\n");
    auto *vq = _event_queue.vq;
    struct hyv_event event;

    while(1)
    {
        // Wait for event queue (used elements)
        virtio_driver::wait_for_queue(_event_queue.vq, &vring::used_ring_not_empty);

        u32 len;

        while ((_vg->evt_queue = (struct hyv_event_queue *) vq->get_buf_elem(&len))) {
            vq->get_buf_finalize();

            while (pop_event(&event)) {
                if(event.type ==  HYV_EVENT_ADD_DEVICE)

                switch (event.type) {
                case HYV_EVENT_CQ_COMP: {
                    struct hyv_cq *cq = (struct hyv_cq *)event.id;

                    debug("vRDMA: handle_event: CQ_COMP\n");

                    if (cq->ibcq.comp_handler) {
                        cq->ibcq.comp_handler(&cq->ibcq,
                                      cq->ibcq.cq_context);
                    }
                    break;
                }
                case HYV_EVENT_CQ: {
                    struct ib_event ibevent;
                    struct hyv_cq *cq = (struct hyv_cq *)event.id;

                    debug("vRDMA: handle_event: CQ\n");

                    ibevent.device = cq->ibcq.device;
                    ibevent.element.cq = &cq->ibcq;
                    ibevent.event = (ib_event_type) event.ibevent;
                    if (cq->ibcq.event_handler) {
                        cq->ibcq.event_handler(&ibevent,
                                       cq->ibcq.cq_context);
                    }
                    break;
                }
                case HYV_EVENT_QP: {
                    struct ib_event ibevent;
                    struct hyv_qp *qp = (struct hyv_qp *)event.id;

                    debug("vRDMA: handle_event: QP\n");

                    ibevent.device = qp->ibqp.device;
                    ibevent.element.qp = &qp->ibqp;
                    ibevent.event = (ib_event_type) event.ibevent;
                    if (qp->ibqp.event_handler) {
                        qp->ibqp.event_handler(&ibevent,
                                       qp->ibqp.qp_context);
                    }
                    break;
                }
                case HYV_EVENT_SRQ:
                case HYV_EVENT_ASYNC:
                    debug("vRDMA: handle_event: SRQ/ASYNC\n");
                    break;
                case HYV_EVENT_ADD_DEVICE: {
                    debug("vRDMA: handle_event: HYV_EVENT_ADD_DEVICE\n");
                    register_ib_dev();
                    break;
                }
                case HYV_EVENT_REM_DEVICE: {
                    debug("vRDMA: handle_event: rem device\n");
                    // this might not be necessary
                    // unregister_ib_dev();
                    break;
                }
                }

            }
        }
    }
}

bool rdma::pop_event(struct hyv_event *event)
{
    bool result = false;
    u64 front = atomic_read((atomic_t*) &_vg->evt_queue->front);
    if (front == _vg->cback) {
        _vg->cback = atomic_read((atomic_t*) &_vg->evt_queue->back);
    }

    if (!(front == _vg->cback)) {
        *event = _vg->evt_queue->data[front];
        atomic_set((atomic_t*) &_vg->evt_queue->front,
                 (front + 1) % ARRAY_SIZE(_vg->evt_queue->data));
        result = true;
    }

    return result;
}

// hypercall_guest.c : virtio_ack_hypercall
void rdma::handle_hcall()
{
    vring *vq = _hcall_queue.vq;

    debug("vRDMA: hcall ack handler.\n");

    while(1)
    {
        // Wait for hcall queue (used elements)
        virtio_driver::wait_for_queue(vq, &vring::used_ring_not_empty);

        u32 len;
        debug("vRDMA: got hcall ack.\n");

        while (struct hcall * hcall_p = (struct hcall *) vq->get_buf_elem(&len)) {
            vq->get_buf_finalize();
            if (hcall_p->async) {
                debug("vRDMA: async hcall.\n");

                struct hcall_async *async =
                    container_of(hcall_p, struct hcall_async,
                         base);
                if (async->cb) {
                    //async->cbw(_vg->vq_hcall, async);
                }
                // kfree(async);
            } else {
                debug("vRDMA: sync hcall.\n");
                // struct hcall_sync *sync =
                //     container_of(hcall_p, struct hcall_sync,
                //          base);
                // complete(&hcall_sync->completion);
            }
        }
    }
}


int rdma::do_hcall(struct hcall_queue *hvq, const struct hcall *hcall_p,
         const struct hcall_header *hdr, uint32_t copy_size,
         const struct hcall_parg *pargs, uint32_t npargs,
         struct hcall_ret_header *hret, uint32_t result_size)
{
    uint32_t i;
    int ret = 0;
    uint32_t flags = hdr->flags;

    debug("vRDMA: do_hcall\n");

    hvq->vq->init_sg();
    // add header
    hvq->vq->add_out_sg((void *)hdr, copy_size);

    // add parameter list
    for (i = 0; i < npargs; i++) {
        debug("vRDAM: pargds[%d]: size: %d, addr: %p\n", i, pargs[i].size, pargs[i].ptr);
        hvq->vq->add_out_sg(pargs[i].ptr, pargs[i].size);
    }

    hvq->vq->add_in_sg(hret, result_size);

    if(!hvq->vq->add_buf((void *)hcall_p)) {
        ret = -1;
    }

    if (flags & HCALL_NOTIFY_HOST) {
        hvq->vq->kick();
    }

    debug("vRDMA: do_hcall return: %d\n ", ret);

    return ret;
}

int rdma::do_hcall_sync(struct hcall_queue *hvq,
              const struct hcall_header *hdr, uint32_t copy_size,
              const struct hcall_parg *pargs, uint32_t npargs,
              struct hcall_ret_header *hret, uint32_t result_size)
{
    int ret;
    struct hcall_sync hcall_sync;
//  = {
    // 	{ false }, COMPLETION_INITIALIZER(hcall_sync.completion)
    // } ;


    ret = do_hcall(hvq, &hcall_sync.base, hdr, copy_size, pargs, npargs,
               hret, result_size);
    if (ret) {
        return ret;
    }

    // OSv:
    //     wait_for_queue(vring* queue, bool (vring::*)
    //wait_for_completion(&hcall_sync.completion);

    return ret;
}

int rdma::do_hcall_async(struct hcall_queue *hvq,
               struct hcall_async *hcall_async,
               const struct hcall_header *hdr, uint32_t copy_size,
               uint32_t npargs, uint32_t result_size)
{
    hcall_async->base.async = true;

    return do_hcall(hvq, &hcall_async->base, hdr, copy_size,
                hcall_async->pargs, npargs, hcall_async->hret,
                result_size);
}

hw_driver* rdma::probe(hw_device* dev)
{
    return virtio::probe<rdma, VIRTIO_RDMA_DEVICE_ID>(dev);
}


// Implementations of verb calls using hypercall

struct ib_ucontext* rdma::vrdma_alloc_ucontext(struct ib_udata *ibudata)
{
    // TODO: possibly support other providers
    // virtmlx4_alloc_ucontext
    // struct ib_ucontext *ibuctx; // uctx
    // struct hyv_ucontext *guctx;
    // struct virtmlx4_ucontext *vuctx;
    int ret, hret;

    debug("vrdma_ibv_alloc_ucontext\n");

    BUG_ON(!udata);

    struct hyv_udata *udata;

    hyv_uctx = (struct hyv_ucontext*) kmalloc(sizeof(struct hyv_ucontext), GFP_KERNEL);
    if (!hyv_uctx) {
        debug("vRDMA: could not allocate user context\n");
        ret = -ENOMEM;
        goto fail;
    }
    INIT_LIST_HEAD(&hyv_uctx->mmap_list);
    spin_lock_init(&hyv_uctx->mmap_lock);

    udata = udata_create(ibudata);
    if (IS_ERR(udata)) {
        ret = PTR_ERR(udata);
        goto fail_uctx;
    }

    {
        const struct hcall_parg pargs[] = { { udata,  (uint32_t)  (sizeof(*udata) + (uint32_t) ( udata->in + udata->out)) } , };
        struct _args_t {
            struct hyv_ibv_alloc_ucontextX_copy_args copy_args;
            struct vrdma_hypercall_result result;
        } *_args;

        _args = (struct _args_t *) malloc(sizeof(*_args));

        if (!_args)
        { ret = -12; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_IBV_ALLOC_UCTX, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };

        memcpy(&_args->copy_args.dev_handle, &hyv_dev.host_handle, sizeof(hyv_dev.host_handle)); ;
        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr,
                            sizeof(_args->copy_args), pargs,
                            (sizeof (pargs) / sizeof ((pargs)[0])),
                            &_args->result.hdr, sizeof(_args->result));

        if (!ret)
            memcpy(&hret, &_args->result.value, sizeof(hret));
        free(_args);
    }
    if (ret || hret < 0) {
        debug("could not query gid on host\n");
        ret = ret ? ret : hret;
        goto fail_udata;
    }
    hyv_uctx->host_handle = hret;

    ret = udata_copy_out(udata, ibudata);
    kfree(udata);
    if (ret) {
        goto fail_alloc_ucontext;
    }

    /* XXX */
    hyv_uctx->ibuctx.device = &hyv_dev.ib_dev;

    return &hyv_uctx->ibuctx;

fail_udata:
    kfree(udata);
fail_uctx:
    kfree(hyv_uctx);
fail:
    return (ib_ucontext*) ERR_PTR(ret);

fail_alloc_ucontext:
    /* in non-error case ib core would take care of this */
    hyv_uctx->ibuctx.device = &hyv_dev.ib_dev;
    // hyv_ibv_dealloc_ucontext(&hyv_uctx->ibuctx);
    return (ib_ucontext*) ERR_PTR(ret);
}

int rdma::vrdma_open_device(int *result)
{
    int ret = -1;
    const struct hcall_parg pargs[] = { };
    struct _args_t {
        struct hyv_get_ib_device_copy_args copy_args;
        struct vrdma_hypercall_result result;
    } *_args;

    _args = (struct _args_t *) malloc(sizeof(*_args));
    if (!_args) {
        return -12; // what is -12 here? probably ENOMEM??
    }

    _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_GET_IB_DEV, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
    memcpy(&_args->copy_args.dev_handle, &hyv_dev.host_handle, sizeof(hyv_dev.host_handle));

    ret = do_hcall_sync(hyv_dev.vg->vq_hcall,
                        &_args->copy_args.hdr,
                        sizeof(_args->copy_args),
                        pargs, (sizeof (pargs) / sizeof ((pargs)[0])),
                        &_args->result.hdr, sizeof(_args->result));

    if (!ret)
        memcpy(result, &_args->result.value, sizeof(*result));
    free(_args);

    return ret;
}

int rdma::vrdma_query_device(ib_uverbs_query_device_resp *attr, int *result)
{
    int ret = -1;
    uint32_t attr_size = sizeof(*attr);
    const struct hcall_parg pargs[] = { { attr, attr_size } , };
    struct _args_t {
        struct hyv_ibv_query_deviceX_copy_args copy_args;
        struct vrdma_hypercall_result result;
    } *_args;

    _args = (struct _args_t *) malloc(sizeof(*_args));
    if (!_args)
        return ret;

    _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_IBV_QUERY_DEV, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
    memcpy(&_args->copy_args.dev_handle, &hyv_dev.host_handle, sizeof(hyv_dev.host_handle));

    ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args),
                                      pargs, (sizeof (pargs) / sizeof ((pargs)[0])),
                                      &_args->result.hdr, sizeof(_args->result));

    if (!ret)
        memcpy(result, &_args->result.value, sizeof(*result));
    free(_args);

    return ret;
}


int rdma::vrdma_query_port(ib_uverbs_query_port_resp *attr, int port_num, int *result)
{
    int ret = -1;
    uint32_t attr_size = sizeof(*attr);
    const struct rdma::hcall_parg pargs[] = { { attr, attr_size } , };
    struct _args_t {
        struct rdma::hyv_ibv_query_portX_copy_args copy_args;
        struct rdma::vrdma_hypercall_result result;
    } *_args;

    _args = (struct _args_t *) malloc(sizeof(*_args));

    if (!_args)
        return -12;

    _args->copy_args.hdr = (struct rdma::hcall_header) { VIRTIO_HYV_IBV_QUERY_PORT, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
    memcpy(&_args->copy_args.dev_handle, &hyv_dev.host_handle, sizeof(hyv_dev.host_handle));
    memcpy(&_args->copy_args.port_num, &port_num, sizeof(port_num));

    ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args),
                        pargs, (sizeof (pargs) / sizeof ((pargs)[0])),
                        &_args->result.hdr, sizeof(_args->result));

    if (!ret) memcpy(result, &_args->result.value, sizeof(*result));
    free(_args);

    return ret;
}

struct ib_pd* rdma::vrdma_alloc_pd(struct ib_udata *ibudata)
{
    hyv_udata *udata;
    int ret, result;

    hpd = (hyv_pd*) kzalloc(sizeof(*hpd), GFP_KERNEL);
    if (!hpd) {
        debug("vRDMA: could not allocate pd\n");
        ret = -ENOMEM;
        goto fail;
    }

    udata = udata_create(ibudata);
    if (IS_ERR(udata)) {
        ret = PTR_ERR(udata);
        goto fail_pd;
    }

    {
        const struct hcall_parg pargs[] = { { udata, (uint32_t) (sizeof(*udata) + (uint32_t) ( udata->in + udata->out)) } , };
        struct _args_t { struct hyv_ibv_alloc_pdX_copy_args copy_args; struct vrdma_hypercall_result result; } *_args;
        _args = (struct _args_t *) malloc(sizeof(*_args));

        if (!_args) { ret = -12; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_IBV_ALLOC_PD, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
        memcpy(&_args->copy_args.uctx_handle, &hyv_uctx->host_handle, sizeof(hyv_uctx->host_handle));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args),
                            pargs, (sizeof (pargs) / sizeof ((pargs)[0])),
                            &_args->result.hdr, sizeof(_args->result));

        if (!ret)
            memcpy(&result, &_args->result.value, sizeof(result));

        free(_args);
    }
    if (ret || result < 0) {
        debug("vRDMA: could not alloc pd on host\n");
        ret = ret ? ret : result;
        goto fail_udata;
    }

    hpd->host_handle = result;
    hpd->ibpd.device  = &hyv_dev.ib_dev;

    ret = udata_copy_out(udata, ibudata);
    kfree(udata);
    if (ret) {
        goto fail_alloc;
    }

    return &hpd->ibpd;

fail_udata:
    kfree(udata);
fail_pd:
    kfree(hpd);
fail:
    return (ib_pd*) ERR_PTR(ret);

fail_alloc:
    //hyv_ibv_dealloc_pd(&hpd->ibpd);
    return (ib_pd*) ERR_PTR(ret);
}


}
