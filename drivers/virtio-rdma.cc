/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <osv/mempool.hh>
#include <osv/interrupt.hh>
#include <osv/sched.hh>
#include <osv/ilog2.hh>
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
        return;
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
    int ret = -1, udata_size;
    struct rdma::hyv_udata *udata;
    unsigned long inlen;

    debug("vRDMA: udata_create\n");

    if(ibudata->inlen < sizeof(struct ib_uverbs_cmd_hdr)) {
        debug("vRDMA: udata size is not correct. \n");
        goto fail;
    }

    inlen = ibudata->inlen - sizeof(struct ib_uverbs_cmd_hdr);
    udata_size = sizeof(*udata) + inlen + ibudata->outlen;

    udata = (rdma::hyv_udata *) kmalloc(udata_size, GFP_KERNEL);
    if (!udata) {
        debug("vRDMA: could not allocate udata\n");
        ret = -ENOMEM;
        goto fail;
    }
    memset(udata, 0, udata_size);
    udata->in = inlen;
    udata->out = ibudata->outlen;

    // TODO: try to aviod the memcpy
    // udata->data = ibudata->inbuf;

    memcpy(udata->data, ibudata->inbuf, inlen);

    return udata;
//fail_udata:
    kfree(udata);
fail:
    return (rdma::hyv_udata*) ERR_PTR(ret);
}


int rdma::udata_copy_out(hyv_udata *udata, struct ib_udata *ibudata)
{
    void *out = udata->data + udata->in;

    // TODO: try to avoid this memcpy
    //ibudata->outbuf = out;
    memcpy(ibudata->outbuf, out,  udata->out);

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

    debug("vRDMA: do_hcall, npargs: %d\n", npargs);

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

struct rdma::hyv_mmap* rdma::mmap_prepare(void **addr, uint32_t size, uint32_t key)
{
    struct hyv_mmap *gmm;
    int ret;

    debug("mmap_prepare\n");

    gmm = (hyv_mmap*) kmalloc(sizeof(struct hyv_mmap), GFP_KERNEL);
    if (!gmm) {
        debug("could not allocate mmap struct\n");
        ret = -ENOMEM;
        goto fail;
    }

    gmm->addr = *addr = malloc(size);
    gmm->key = key;
    gmm->size = size;
    gmm->mapped = false;
    if (!gmm->addr) {
        debug("could not allocate buffer\n");
        ret = PTR_ERR(gmm->addr);
        goto fail_gmm;
    }
    spin_lock(&hyv_uctx->mmap_lock);
    list_add_tail(&gmm->list, &hyv_uctx->mmap_list);
    spin_unlock(&hyv_uctx->mmap_lock);

    return gmm;
fail_gmm:
    kfree(gmm);
fail:
    return (hyv_mmap*) ERR_PTR(ret);
}

void rdma::mmap_unprepare(struct hyv_mmap *mm)
{
    spin_lock(&hyv_uctx->mmap_lock);
    list_del(&mm->list);
    spin_unlock(&hyv_uctx->mmap_lock);

    vrdma_unmap(mm);
}

int rdma::vrdma_mmap(struct hyv_mmap *gmm)
{
    int ret = 0;
    hyv_mmap_result_t result;
    unsigned long phys_addr;
    //unsigned long prot;
    uint32_t vm_pgoff = gmm->key >> PAGE_SHIFT;
    uint64_t vm_flags = 0xFA;
    hyv_mmap *mm;

    debug("vrdma_mmap\n");

    debug("pgoff: 0x%lx, key: 0x%x, len: %lu, vm_pgoff: %lu\n", vm_pgoff, gmm->key, gmm->size, vm_pgoff);

    // remove the mm from the mmap list
    spin_lock(&hyv_uctx->mmap_lock);
    list_for_each_entry(mm, &hyv_uctx->mmap_list, list)
    {
        if (mm->key == gmm->key) {
            list_del(&mm->list);
        }
    }
    spin_unlock(&hyv_uctx->mmap_lock);

    phys_addr = virt_to_phys(gmm->addr);

    {
        int ret;
        const struct hcall_parg pargs[] = { };
        struct _args_t {
            struct hyv_mmap_copy_args copy_args;
            struct hyv_mmap_result result;
        } *_args;

        _args = (_args_t*) malloc(sizeof(*_args));
        memset(_args, 0, sizeof(*_args));

        if (!_args) { ret = -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_MMAP, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };

        memcpy(&_args->copy_args.uctx_handle, &hyv_uctx->host_handle, sizeof(hyv_uctx->host_handle));
        memcpy(&_args->copy_args.phys_addr, &phys_addr, sizeof(phys_addr));
        memcpy(&_args->copy_args.size, &gmm->size, sizeof(gmm->size));
        memcpy(&_args->copy_args.vm_flags, &vm_flags, sizeof(vm_flags));
        memcpy(&_args->copy_args.vm_pgoff, &vm_pgoff, sizeof(vm_pgoff));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr,
                            sizeof(_args->copy_args), pargs,
                            sizeof(pargs) / sizeof((pargs)[0]),
                            &_args->result.hdr, sizeof(_args->result));

        if (!ret)
            memcpy(&result, &_args->result.value, sizeof(result));
        kfree(_args);
    }
    if (ret || result.mmap_handle < 0 ) {
        debug("could not mmap on host\n");
        ret = ret ? ret : result.mmap_handle;
        goto fail;
    }

    debug("result.pgprot: %llu\n", result.pgprot);

    gmm->host_handle = result.mmap_handle;
    gmm->mapped = true;

fail:
    return ret;
}

int rdma::vrdma_unmap(struct hyv_mmap *mm)
{
    int ret = 0, result;

    debug("vrdma_unmap\n");

    if (mm->mapped) {
        {
            const struct hcall_parg pargs[] = { };
            struct _args_t {
                struct hyv_munmap_copy_args copy_args;
                struct vrdma_hypercall_result result;
            } *_args;

            _args = (_args_t*)kmalloc(sizeof(*_args), mem_flags);

            if (!_args) { ret = -ENOMEM; }

            _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_MUNMAP, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };

            memcpy(&_args->copy_args.mmap_handle, &mm->host_handle, sizeof(mm->host_handle));

            ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr,
                                sizeof(_args->copy_args), pargs,
                                sizeof(pargs) / sizeof((pargs)[0]),
                                &_args->result.hdr, sizeof(_args->result));

            if (!ret) memcpy(&result, &_args->result.value, sizeof(result));
            kfree(_args);
        }

        if (ret || result) {
            debug("could not unmap on host\n");
            ret = ret ? ret : result;
        }
    }

    // free_pages_exact(mm->addr, mm->size);
    kfree(mm);
    return ret;
}
// Implementations of verb calls using hypercall

struct ib_ucontext* rdma::vrdma_alloc_ucontext(struct ib_udata *ibudata, void **uar, void **bf_page)
{
    // TODO: possibly support other providers
    // virtmlx4_alloc_ucontext
    // struct ib_ucontext *ibuctx; // uctx

    struct virtmlx4_ucontext *vuctx;
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
    spinlock_init(&hyv_uctx->mmap_lock);

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
        { ret = -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_IBV_ALLOC_UCTX, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };

        memcpy(&_args->copy_args.dev_handle, &hyv_dev.host_handle, sizeof(hyv_dev.host_handle));

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

    hyv_uctx->priv = NULL;

    vuctx = (virtmlx4_ucontext*) kmalloc(sizeof(*vuctx), GFP_KERNEL);
    if (!vuctx) {
        debug("alloc uctx failed\n");
        ret = -ENOMEM;
        goto fail_alloc_ucontext;
    }
    hyv_uctx->priv = vuctx;

    vuctx->uar_mmap = mmap_prepare(uar, PAGE_SIZE, MLX4_IB_MMAP_UAR_PAGE);
    if (IS_ERR(vuctx->uar_mmap)) {
        debug("could not prepare uar mmap\n");
        ret = PTR_ERR(vuctx->uar_mmap);
        goto fail_vuctx;
    }

    vuctx->bf_mmap = mmap_prepare(bf_page, PAGE_SIZE, MLX4_IB_MMAP_BLUE_FLAME_PAGE << PAGE_SHIFT);
    if (IS_ERR(vuctx->bf_mmap)) {
        debug("could not prepare bf mmap\n");
        ret = PTR_ERR(vuctx->bf_mmap);
        goto fail_uar_mmap;
    }

    // do mmap on the host
    // triggerred by fd event in uverbs
    ret = vrdma_mmap(vuctx->uar_mmap);
    if (ret) {
        debug("could not mmap on host\n");
        goto fail_mmap;
    }

    ret = vrdma_mmap(vuctx->bf_mmap);
    if (ret) {
        debug("could not mmap on host\n");
        goto fail_mmap;
    }

    return &hyv_uctx->ibuctx;
fail_mmap:
    mmap_unprepare(vuctx->bf_mmap);
fail_uar_mmap:
    mmap_unprepare(vuctx->uar_mmap);
fail_vuctx:
    kfree(vuctx);
fail_uctx:
    kfree(hyv_uctx);
fail_udata:
    kfree(udata);
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
        return -ENOMEM;
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
        return -ENOMEM;

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

        if (!_args) { ret = -ENOMEM; }

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

    debug("&hpd->ibpd : %p\n", &hpd->ibpd);

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


struct rdma::hyv_udata_translate* rdma::udata_translate_create(hyv_udata *udata,
                                                  struct hyv_user_mem **umem,
                                                  struct hyv_udata_gvm *udata_gvm,
                                                  uint32_t udata_gvm_num,
                                                  uint32_t *n_chunks_total)
{
    struct uchunks
    {
        struct hyv_user_mem_chunk *data;
        unsigned long n;
    } *chunks;
    uint32_t chunks_total = 0;
    struct hyv_udata_translate *udata_trans_iter;
    struct hyv_udata_translate *udata_translate;
    uint32_t i, j;
    int ret;

    debug("udata_translate_create\n");

    debug("udata_gvm_num: %d\n", udata_gvm_num);

    chunks = (struct uchunks*) kmalloc(sizeof(*chunks) * udata_gvm_num, GFP_KERNEL);
    if (!chunks) {
        debug("could not allocate chunks\n");
        ret = -ENOMEM;
        goto fail;
    }

    for (i = 0; i < udata_gvm_num; i++) {
        __u64 *va = (__u64 *)&udata->data[udata_gvm[i].udata_offset];
        umem[i] =
            pin_user_mem(*va & udata_gvm[i].mask, udata_gvm[i].size,
                     &chunks[i].data, &chunks[i].n, true);
        if (IS_ERR(umem[i])) {
            ret = PTR_ERR(umem[i]);
            debug("could not pin user memory\n");
            goto fail_pin;
        }

        chunks_total += chunks[i].n;
    }
    *n_chunks_total = chunks_total;

    if (udata_gvm_num) {
        udata_translate =
            (hyv_udata_translate*) kmalloc(sizeof(*udata_translate) * udata_gvm_num +
                sizeof(hyv_user_mem_chunk) * chunks_total,
                GFP_KERNEL);
        memset(udata_translate, 0, sizeof(*udata_translate) * udata_gvm_num +
               sizeof(hyv_user_mem_chunk) * chunks_total);
    } else {
        udata_translate = (hyv_udata_translate*) kmalloc(sizeof(*udata_translate), GFP_KERNEL);
        memset(udata_translate, 0, sizeof(*udata_translate));
    }
    if (!udata_translate) {
        debug("could not alloc udata translate\n");
        ret = -ENOMEM;
        goto fail_pin;
    }

    udata_trans_iter = udata_translate;
    for (j = 0; j < udata_gvm_num; j++) {
        uint32_t n_chunks = chunks[j].n;
        udata_trans_iter->udata_offset = udata_gvm[j].udata_offset;
        udata_trans_iter->n_chunks = n_chunks;
        udata_trans_iter->type = udata_gvm[j].type;
        memcpy(udata_trans_iter->chunk, chunks[j].data,
               sizeof(hyv_user_mem_chunk) * n_chunks);
        udata_trans_iter =
            (hyv_udata_translate *)&udata_trans_iter->chunk[n_chunks];
    }

    kfree(chunks);

    return udata_translate;
fail_pin:
    // for (j = 0; j < i; j++) {
    //     hyv_unpin_user_mem(umem[j]);
    // }
    kfree(chunks);
fail:
    return (hyv_udata_translate*) ERR_PTR(ret);
}

#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1) & ~PAGE_MASK)
#define page_to_pfn(addr)       (virt_to_phys(addr)) >> PAGE_SHIFT
struct rdma::hyv_user_mem* rdma::pin_user_mem(unsigned long va, unsigned long size, hyv_user_mem_chunk **chunks, unsigned long *n_chunks, bool write)
{
    struct hyv_user_mem *umem;
    unsigned long i, offset, cur_va;
    unsigned long n_pages, pages_pinned = 0;
    hyv_user_mem_chunk *chunk_tmp = NULL;
    int ret=0;

    offset = va & PAGE_MASK;
    n_pages = PAGE_ALIGN(size) >> PAGE_SHIFT;

    debug("va: 0x%lx, size: %lu\n", va, size);
    debug("n_pages: %lu, offset: 0x%lx\n", n_pages, offset);

    if (n_pages == 0) {
        ret = -EINVAL;
        goto fail;
    }

    if (chunks) {
        *n_chunks = 1;
        bool flag = false;
        unsigned long end_offset;

        chunk_tmp = (hyv_user_mem_chunk*) kmalloc(sizeof(*chunk_tmp) * n_pages, GFP_KERNEL);
        if (!chunk_tmp) {
            debug("could not allocate chunks!\n");
            ret = -ENOMEM;
            goto fail;
        }
        memset(chunk_tmp, 0, sizeof(*chunk_tmp) * n_pages);

        for (cur_va = va; n_pages != pages_pinned; cur_va += PAGE_SIZE) {
            if(!flag) {
                chunk_tmp[*n_chunks-1].addr = virt_to_phys((void*)cur_va);
            }
            pages_pinned++;

            if(virt_to_phys((void*)cur_va) + PAGE_SIZE == virt_to_phys((void*)(cur_va + PAGE_SIZE))) {
                // contigous pages found
                flag = true;
                chunk_tmp[*n_chunks-1].size += PAGE_SIZE;
                continue;
            } else {
                flag = false;
            }

            (*n_chunks)++;
        }

        /* cut last chunk to real size */
        end_offset = ((size - chunk_tmp[0].size) & PAGE_MASK);
        if (end_offset) {
            chunk_tmp[n_pages].size -= PAGE_SIZE - end_offset;
        }

        debug("n_chunks: %lu\n", *n_chunks);
        for (i = 0; i < *n_chunks; i++) {
            debug("-- chunk[%lu] --\n", i);
            debug("virt_addr: 0x%lx\n", va+i*PAGE_SIZE);
            debug("phys_addr: 0x%llx\n", chunk_tmp[i].addr);
            debug("size: %llu\n", chunk_tmp[i].size);
        }

        *chunks = chunk_tmp;
    }

    umem = (hyv_user_mem*) kmalloc(sizeof(*umem), GFP_KERNEL);
    if (!umem) {
        debug("could not allocate user mem struct\n");
        ret = -ENOMEM;
        goto fail_chunk;
    }
    umem->n_pages = n_pages;
    return umem;
fail_chunk:
    kfree(chunk_tmp);
fail:
    return (hyv_user_mem*) ERR_PTR(ret);
}


struct ib_mr* rdma::vrdma_reg_mr(u64 user_va, u64 size, u64 io_va, int access, struct ib_udata *ibudata)
{
    hyv_reg_user_mr_result res;
    hyv_user_mem_chunk *umem_chunks;
    struct hyv_udata_translate *udata_translate;
    struct hyv_user_mem *umem=NULL;
    uint32_t n_chunks_total;
    uint32_t i;
    unsigned long n_chunks;
    hyv_udata *udata;
    bool write;
    int ret=0;
    int udata_gvm_num = 0;
    struct hyv_udata_gvm *udata_gvm = NULL;

    debug("vrdma_reg_user_mr\n");

    BUG_ON(user_va != io_va);

    write = !!(access & ~IB_ACCESS_REMOTE_READ);

    hmr = (hyv_mr*) kmalloc(sizeof(*hmr), GFP_KERNEL);
    if (!hmr) {
        debug("could not allocate mr\n");
        ret = -ENOMEM;
        goto fail;
    }

    umem = pin_user_mem(user_va, size, &umem_chunks, &n_chunks, write);
    if (IS_ERR(umem)) {
        debug("could not pin user memory\n");
        ret = PTR_ERR(umem);
        goto fail_mr;
    }

    udata = udata_create(ibudata);
    if (IS_ERR(udata)) {
        debug( "pre udata failed!\n");
        ret = PTR_ERR(udata);
        goto fail_pin;
    }

    hmr->n_umem = udata_gvm_num;

    hmr->umem = (hyv_user_mem**) kmalloc(sizeof(*hmr->umem) * (udata_gvm_num + 1), GFP_KERNEL);
    if (!hmr->umem) {
        debug("could not allocate umem\n");
        ret = -ENOMEM;
        goto fail_udata;
    }
    hmr->umem[0] = umem;

    udata_translate = udata_translate_create(
        udata, hmr->umem + 1, udata_gvm, udata_gvm_num, &n_chunks_total);
    if (IS_ERR(udata_translate)) {
        debug("could not translate udata\n");
        ret = PTR_ERR(udata_translate);
        goto fail_umem;
    }

    {
        int ret;
        const struct hcall_parg pargs[] = { { umem_chunks, (uint32_t) (n_chunks * sizeof(*umem_chunks)) } ,
                                            { udata, (uint32_t) (sizeof(*udata) + (uint32_t) ( udata->in + udata->out)) } ,
                                            { 	udata_translate,
                                                (uint32_t) (sizeof(*udata_translate) * (udata_gvm_num ? udata_gvm_num : 1)) + \
                                                (uint32_t) (sizeof(hyv_user_mem_chunk) * n_chunks_total) } ,
                                            };
        struct _args_t {
            struct rdma::hyv_ibv_reg_user_mrX_copy_args copy_args;
            struct rdma::vrdma_hypercall_result96 result; // ibv_reg_mr_resp
        } *_args;

        _args = (struct _args_t *) malloc(sizeof(*_args));

        if (!_args) { ret = -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_IBV_REG_USER_MR, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST};

        memcpy(&_args->copy_args.pd_handle, &hpd->host_handle, sizeof(hpd->host_handle));
        memcpy(&_args->copy_args.user_va, &user_va, sizeof(user_va));
        memcpy(&_args->copy_args.size, &size, sizeof(size));
        memcpy(&_args->copy_args.access, &access, sizeof(access));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr,
                            sizeof(_args->copy_args), pargs, (sizeof (pargs) / sizeof ((pargs)[0])),
                            &_args->result.hdr, sizeof(_args->result));
        if (!ret)
            memcpy(&res, &_args->result.value, sizeof(res));

        free(_args);
    }
    if (ret || res.mr_handle < 0) {
        debug("could not reg user mr on host\n");
        ret = ret ? ret : res.mr_handle;
        goto fail_udata_translate;
    }
    hmr->access = access;
    hmr->host_handle = res.mr_handle;
    hmr->ibmr.lkey = res.lkey;
    hmr->ibmr.rkey = res.rkey;

    // udata_translate_destroy(udata_translate);

    kfree(umem_chunks);

    ret = udata_copy_out(udata, ibudata);
    kfree(udata);
    if (ret) {
        debug("could not copy response\n");
//        hyv_ibv_dereg_mr(&hmr->ibmr);
        ret = -EFAULT;
        goto fail;
    }

    return &hmr->ibmr;
fail_udata_translate:
    for (i = 0; i < hmr->n_umem; i++) {
        //hyv_unpin_user_mem(hmr->umem[i]);
    }
    //udata_translate_destroy(udata_translate);
fail_umem:
    kfree(hmr->umem);
fail_udata:
    kfree(udata);
fail_pin:
    kfree(umem_chunks);
    //hyv_unpin_user_mem(umem);
fail_mr:
    kfree(hmr);
fail:
    return (ib_mr*)ERR_PTR(ret);
}

static inline unsigned int roundup_pow_of_two(unsigned int x)
{
    return 1UL << fls(x - 1);
}
#define MLX4_CQ_ENTRY_SIZE 0x20
#define roundup_pow_of_two(a) (1UL << fls((a) - 1))
struct ib_cq* rdma::vrdma_create_cq(int entries, int vector, struct ib_udata *ibudata)
{
    struct hyv_udata_gvm udata_gvm[2];
    int ret;
    hyv_udata_translate *udata_translate;
    hyv_create_cq_result result;
    hyv_udata *udata;
    uint32_t n_chunks_total;
    uint32_t udata_gvm_num;
    int umem_entries;

    debug("vrdma_create_cq\n");

    BUG_ON(!ibuctx);

    // roundup_pow_of_two
    umem_entries = roundup_pow_of_two(entries + 1);

    udata_gvm[0].udata_offset = offsetof(struct mlx4_ib_create_cq, buf_addr);
    udata_gvm[0].mask = ~0UL;
    udata_gvm[0].size = PAGE_ALIGN(MLX4_CQ_ENTRY_SIZE *  umem_entries);
    udata_gvm[0].type = HYV_IB_UMEM;

    udata_gvm[1].udata_offset = offsetof(struct mlx4_ib_create_cq, db_addr);
    udata_gvm[1].mask = ~PAGE_MASK;
    udata_gvm[1].size = PAGE_SIZE;
    udata_gvm[1].type = HYV_IB_UMEM;

    udata_gvm_num = ARRAY_SIZE(udata_gvm);
    hcq = (hyv_cq*) kmalloc(sizeof(*hcq), GFP_KERNEL);
    if (!hcq) {
        debug("could not allocate cq\n");
        ret = -ENOMEM;
        goto fail;
    }

    udata = udata_create(ibudata);
    if (IS_ERR(udata)) {
        ret = PTR_ERR(udata);
        goto fail_cq;
    }

    hcq->n_umem = udata_gvm_num;

    hcq->umem = (hyv_user_mem**) kmalloc(sizeof(*hcq->umem) * udata_gvm_num, GFP_KERNEL);
    if (!hcq->umem) {
        debug("could not allocate umem\n");
        ret = -ENOMEM;
        goto fail_udata;
    }

    udata_translate = udata_translate_create(udata, hcq->umem, udata_gvm, udata_gvm_num, &n_chunks_total);
    if (IS_ERR(udata_translate)) {
        debug("could not translate udata\n");
        ret = PTR_ERR(udata_translate);
        goto fail_umem;
    }

    {
        const struct hcall_parg pargs[] = { { udata, (uint32_t) (sizeof(*udata) + (uint32_t) ( udata->in + udata->out)) } ,
                                            { 	udata_translate,
                                                (uint32_t) (sizeof(*udata_translate) * (udata_gvm_num ? udata_gvm_num : 1)) + \
                                                (uint32_t) (sizeof(hyv_user_mem_chunk) * n_chunks_total) } ,
                                            };
        struct _args_t { struct hyv_ibv_create_cqX_copy_args copy_args; struct vrdma_hypercall_result48 result; } *_args;

        _args = (struct _args_t *) malloc(sizeof(*_args));
        if (!_args) {
            ret = -ENOMEM;
            goto fail_udata_translate;
        }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_IBV_CREATE_CQ, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };
        memcpy(&_args->copy_args.guest_handle, hcq, sizeof(*hcq));
        memcpy(&_args->copy_args.uctx_handle, &hyv_uctx->host_handle, sizeof(hyv_uctx->host_handle));
        memcpy(&_args->copy_args.entries, &entries, sizeof(entries));
        memcpy(&_args->copy_args.vector, &vector, sizeof(vector));

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args), pargs,
                            (sizeof (pargs) / sizeof ((pargs)[0])), &_args->result.hdr, sizeof(_args->result));
        if (!ret)
            memcpy(&result, &_args->result.value, sizeof(result));

        free(_args);
    }
    if (ret || result.cq_handle < 0) {
        debug("could not create cq on host\n");
        ret = ret ? ret : result.cq_handle;
        goto fail_udata_translate;
    }

    hcq->host_handle = result.cq_handle;
    hcq->ibcq.cqe = result.cqe;
    debug("result.cqe: %d\n", result.cqe);

    // udata_translate_destroy(udata_translate);

    ret = udata_copy_out(udata, ibudata);
    // udata_destroy(udata);
    free(udata);
    if (ret) {
        goto fail_create;
    }

    return &hcq->ibcq;
fail_udata_translate:
    // for (i = 0; i < cq->n_umem; i++) {
    //     hyv_unpin_user_mem(cq->umem[i]);
    // }
    // udata_translate_destroy(udata_translate);
fail_umem:
    kfree(hcq->umem);
fail_udata:
    // udata_destroy(udata);
    free(udata);
fail_cq:
    kfree(hcq);
fail_create:
    // hyv_ibv_destroy_cq(&hcq->ibcq);
fail:
    return (ib_cq*) ERR_PTR(ret);
}


struct ib_qp* rdma::vrdma_create_qp(struct ib_qp_init_attr *ibinit_attr, struct ib_udata *ibudata)
{
    struct ib_qp *ibqp;
    struct hyv_udata_gvm udata_gvm[2];
    unsigned int udata_gvm_num = 0;
    struct mlx4_ib_create_qp ucmd;
    unsigned long buf_size;
    unsigned long sq_wqe_cnt, sq_wqe_shift;
    unsigned long rq_wqe_cnt, rq_wqe_shift, rq_max_gs;
    hyv_create_qp_result *resp;
    int ret;
    struct hyv_cq *send_cq, *recv_cq;
    struct hyv_srq *srq = NULL;
    int hret;
    hyv_qp_init_attr init_attr;
    hyv_udata_translate *udata_translate;
    hyv_udata *udata;
    uint32_t n_chunks_total, i;

    debug("vrdma_create_qp\n");
    BUG_ON(!ibudata);

    memcpy(&ucmd, ibudata->inbuf, sizeof(ucmd));

    sq_wqe_shift = ucmd.log_sq_stride;
    sq_wqe_cnt = 1 << ucmd.log_sq_bb_count;
    rq_wqe_cnt = roundup_pow_of_two(max(1U, ibinit_attr->cap.max_recv_wr));
    rq_max_gs = roundup_pow_of_two(max(1U, ibinit_attr->cap.max_recv_sge));
    rq_wqe_shift = ilog2(rq_max_gs * sizeof(struct mlx4_wqe_data_seg));

    buf_size = (sq_wqe_cnt << sq_wqe_shift) + (rq_wqe_cnt << rq_wqe_shift);
    ucmd.buf_addr = ((struct mlx4_ib_create_qp*)ibudata->inbuf)->buf_addr;
    ucmd.db_addr = ((struct mlx4_ib_create_qp*)ibudata->inbuf)->db_addr;
    ucmd.log_sq_bb_count = 8;
    ucmd.log_sq_stride = 6;
    ucmd.sq_no_prefetch = 0;

    udata_gvm[0].udata_offset =
        offsetof(struct mlx4_ib_create_qp, buf_addr);
    udata_gvm[0].mask = ~0UL;
    udata_gvm[0].size = PAGE_ALIGN(buf_size);
    udata_gvm[0].type = HYV_IB_UMEM;
    udata_gvm_num++;

    if (!ibinit_attr->srq) {
        udata_gvm[1].udata_offset =
            offsetof(struct mlx4_ib_create_qp, db_addr);
        udata_gvm[1].mask = ~PAGE_MASK;
        udata_gvm[1].size = PAGE_SIZE;
        udata_gvm[1].type = HYV_IB_UMEM;
        udata_gvm_num++;
    }

    // at moment, we can use one cq for both send and recv opration
    // TODO: add option to use different cq
    send_cq = hcq;
    recv_cq = hcq;

    // if (ibinit_attr->srq) {
    //     srq = container_of(ibinit_attr->srq, struct hyv_srq, ibsrq);
    // }

    hqp = (hyv_qp*) kmalloc(sizeof(*ibqp), GFP_KERNEL);
    if (!hqp) {
        debug("could not allocate qp\n");
        ret = -ENOMEM;
        goto fail;
    }

    resp = (hyv_create_qp_result*) kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        debug("could not allocate result");
        ret = -ENOMEM;
        goto fail_qp;
    }

    udata = udata_create(ibudata);
    if (IS_ERR(udata)) {
        ret = PTR_ERR(udata);
        goto fail_res;
    }

    hqp->n_umem = udata_gvm_num;

    hqp->umem = (hyv_user_mem**) kmalloc(sizeof(*hqp->umem) * udata_gvm_num, GFP_KERNEL);
    if (!hqp->umem) {
        debug("could not allocate umem\n");
        ret = -ENOMEM;
        goto fail_udata;
    }

    udata_translate = udata_translate_create(
        udata, hqp->umem, udata_gvm, udata_gvm_num, &n_chunks_total);
    if (IS_ERR(udata_translate)) {
        debug("could not translate udata\n");
        ret = PTR_ERR(udata_translate);
        goto fail_umem;
    }

    init_attr.send_cq_handle      = send_cq->host_handle;
    init_attr.recv_cq_handle      = recv_cq->host_handle;
    init_attr.srq_handle          = ibinit_attr->srq ? srq->host_handle : -1;
    init_attr.xrcd_handle         = -1;
    init_attr.cap.max_send_wr     = ibinit_attr->cap.max_send_wr;
    init_attr.cap.max_recv_wr     = ibinit_attr->cap.max_recv_wr;
    init_attr.cap.max_send_sge    = ibinit_attr->cap.max_send_sge;
    init_attr.cap.max_recv_sge    = ibinit_attr->cap.max_recv_sge;
    init_attr.cap.max_inline_data = ibinit_attr->cap.max_inline_data;
    init_attr.sq_sig_type         = ibinit_attr->sq_sig_type;
    init_attr.qp_type             = ibinit_attr->qp_type;
    init_attr.create_flags        = ibinit_attr->create_flags;
    init_attr.port_num            = ibinit_attr->port_num;

    {
        const struct hcall_parg pargs[] = {
            { resp, sizeof(*resp) } ,
            { udata, (uint32_t) (sizeof(*udata) + (uint32_t) ( udata->in + udata->out)) } ,
            { 	udata_translate,
                (uint32_t) (sizeof(*udata_translate) * (udata_gvm_num ? udata_gvm_num : 1)) + \
                (uint32_t) (sizeof(hyv_user_mem_chunk) * n_chunks_total)
            } ,
        };

        struct _arg_t { struct hyv_ibv_create_qpX_copy_args copy_args; struct vrdma_hypercall_result result; } *_args;

        _args = (_arg_t*) kmalloc(sizeof(*_args), mem_flags);

        if (!_args) { ret = -ENOMEM; }

        _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_IBV_CREATE_QP, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST };

        memcpy(&_args->copy_args.guest_handle, hqp, sizeof(*hqp));
        memcpy(&_args->copy_args.pd_handle, &hpd->host_handle, sizeof(hpd->host_handle));
        memcpy(&_args->copy_args.init_attr, &init_attr, sizeof(init_attr)); ;

        ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr,
                                sizeof(_args->copy_args), pargs,
                                sizeof(pargs) / sizeof((pargs)[0]),
                                 &_args->result.hdr, sizeof(_args->result));

        if (!ret) memcpy(&hret, &_args->result.value, sizeof(hret));

        kfree(_args);
    }
    if (ret || hret) {
        debug("could not create qp on host\n");
        ret = ret ? ret : hret;
        goto fail_udata_translate;
    }
    // abi_ver = 6
    ibinit_attr->cap.max_send_wr     = resp->cap.max_send_wr;
    ibinit_attr->cap.max_recv_wr     = resp->cap.max_recv_wr;
    ibinit_attr->cap.max_send_sge    = resp->cap.max_send_sge;
    ibinit_attr->cap.max_recv_sge    = resp->cap.max_recv_sge;
    ibinit_attr->cap.max_inline_data = resp->cap.max_inline_data;
    hqp->host_handle = resp->qp_handle;
    hqp->ibqp.qp_num = resp->qpn;

    debug("resp->qpn: %d\n", resp->qpn);

    //udata_translate_destroy(udata_translate);

    ret = udata_copy_out(udata, ibudata);
    // udata_destroy(udata);
    kfree(udata);
    if (ret) {
        goto fail_alloc;
    }

    kfree(resp);

    return &hqp->ibqp;

fail_udata_translate:
    for (i = 0; i < hqp->n_umem; i++) {
        //hyv_unpin_user_mem(qp->umem[i]);
    }
    //udata_translate_destroy(udata_translate);
fail_umem:
    kfree(hqp->umem);
fail_udata:
    //udata_destroy(udata);
    kfree(udata);
fail_res:
    kfree(resp);
fail_qp:
    kfree(hqp);
fail:
    return (ib_qp *)ERR_PTR(ret);

fail_alloc:
    kfree(resp);
    //hyv_ibv_destroy_qp(&qp->ibqp);
    return (ib_qp *)ERR_PTR(ret);
}

void rdma::copy_ib_qp_cap_to_hyv(const struct ib_qp_cap *ibcap,
                     hyv_qp_cap *gcap)
{
    gcap->max_send_wr = ibcap->max_send_wr;
    gcap->max_recv_wr = ibcap->max_recv_wr;
    gcap->max_send_sge = ibcap->max_send_sge;
    gcap->max_recv_sge = ibcap->max_recv_sge;
    gcap->max_inline_data = ibcap->max_inline_data;
}

void rdma::copy_ib_ah_attr_to_hyv(const struct ib_ah_attr *ibahattr,
                      hyv_ah_attr *gahattr)
{
    memcpy(gahattr->grh.raw_gid, ibahattr->grh.dgid.raw,
           sizeof(gahattr->grh.raw_gid));
    gahattr->grh.flow_label = ibahattr->grh.flow_label;
    gahattr->grh.sgid_index = ibahattr->grh.sgid_index;
    gahattr->grh.hop_limit = ibahattr->grh.hop_limit;
    gahattr->grh.traffic_class = ibahattr->grh.traffic_class;

    gahattr->dlid = ibahattr->dlid;
    gahattr->sl = ibahattr->sl;
    gahattr->src_path_bits = ibahattr->src_path_bits;
    gahattr->static_rate = ibahattr->static_rate;
    gahattr->ah_flags = ibahattr->ah_flags;
    gahattr->port_num = ibahattr->port_num;
}

int rdma::vrdma_modify_qp(struct ib_qp_attr *ibattr, int cmd_attr_mask, struct ib_udata *ibudata)
{
    hyv_qp_attr attr;
    int ret = 0, result;
    hyv_udata *udata;
    int attr_mask;

    debug("vrdma_modify_qp\n");

    // set up the new attr mask
    switch (hqp->ibqp.qp_type) {
    case IB_QPT_XRC_INI:
        attr_mask = cmd_attr_mask & ~(IB_QP_MAX_DEST_RD_ATOMIC | IB_QP_MIN_RNR_TIMER);
    case IB_QPT_XRC_TGT:
        attr_mask = cmd_attr_mask & ~(IB_QP_MAX_QP_RD_ATOMIC | IB_QP_RETRY_CNT | IB_QP_RNR_RETRY);
    default:
        attr_mask = cmd_attr_mask;
    }

    debug("attr_mask: %d \n", attr_mask);
    debug("hqp->ibqp.qp_type: %d \n", hqp->ibqp.qp_type);

    copy_ib_qp_cap_to_hyv(&ibattr->cap, &attr.cap);
    copy_ib_ah_attr_to_hyv(&ibattr->ah_attr, &attr.ah_attr);
    copy_ib_ah_attr_to_hyv(&ibattr->alt_ah_attr, &attr.alt_ah_attr);

    attr.qp_state            = ibattr->qp_state;
    attr.cur_qp_state        = ibattr->cur_qp_state;
    attr.path_mtu            = ibattr->path_mtu;
    attr.path_mig_state      = ibattr->path_mig_state;
    attr.qkey                = ibattr->qkey;
    attr.rq_psn              = ibattr->rq_psn;
    attr.sq_psn              = ibattr->sq_psn;
    attr.dest_qp_num         = ibattr->dest_qp_num;
    attr.qp_access_flags     = ibattr->qp_access_flags;
    attr.pkey_index          = ibattr->pkey_index;
    attr.alt_pkey_index      = ibattr->alt_pkey_index;
    attr.en_sqd_async_notify = ibattr->en_sqd_async_notify;
    attr.max_rd_atomic       = ibattr->max_rd_atomic;
    attr.max_dest_rd_atomic  = ibattr->max_dest_rd_atomic;
    attr.min_rnr_timer       = ibattr->min_rnr_timer;
    attr.port_num            = ibattr->port_num;
    attr.timeout             = ibattr->timeout;
    attr.retry_cnt           = ibattr->retry_cnt;
    attr.rnr_retry           = ibattr->rnr_retry;
    attr.alt_port_num        = ibattr->alt_port_num;
    attr.alt_timeout         = ibattr->alt_timeout;

    udata = udata_create(ibudata);
    if (IS_ERR(udata)) {
        ret = PTR_ERR(udata);
        goto fail;
    }

    {
         const struct hcall_parg pargs[] = { { udata, (uint32_t) (sizeof(*udata) + (uint32_t) ( udata->in + udata->out)) } , };
         struct _args_t {
             struct hyv_ibv_modify_qpX_copy_args copy_args;
             struct vrdma_hypercall_result result;
         } *_args;

         _args = (_args_t *) kmalloc(sizeof(*_args), mem_flags);
         if (!_args) { ret = -ENOMEM; }

         _args->copy_args.hdr = (struct hcall_header) { VIRTIO_HYV_IBV_MODIFY_QP, 0, HCALL_NOTIFY_HOST | HCALL_SIGNAL_GUEST, };

         memcpy(&_args->copy_args.qp_handle, &hqp->host_handle, sizeof(hqp->host_handle));
         memcpy(&_args->copy_args.attr, &attr, sizeof(attr));
         memcpy(&_args->copy_args.attr_mask, &attr_mask, sizeof(attr_mask));

         ret = do_hcall_sync(hyv_dev.vg->vq_hcall, &_args->copy_args.hdr, sizeof(_args->copy_args), pargs,
                                 (sizeof(pargs) / sizeof((pargs)[0])), &_args->result.hdr, sizeof(_args->result));

         if (!ret) memcpy(&result, &_args->result.value, sizeof(result));

         kfree(_args);
    }
    if (ret || result) {
        debug("could not modify qp on host\n");
        ret = ret ? ret : result;
        goto fail_udata;
    }

    ret = udata_copy_out(udata, ibudata);

fail_udata:
    //udata_destroy(udata);
    kfree(udata);
fail:
    return ret;

}


}
