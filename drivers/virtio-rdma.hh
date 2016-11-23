/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#ifndef VIRTIO_RDMA_DRIVER_H
#define VIRTIO_RDMA_DRIVER_H

#include <osv/condvar.h>
#include <osv/device.h>
#include <asm/atomic.h>
#include <rdma/ib_verbs.h>
#include "drivers/virtio.hh"
#include "drivers/device.hh"

#define container_of(ptr, type, member)                         \
({                                                              \
        __typeof(((type *)0)->member) *_p = (ptr);              \
        (type *)((char *)_p - offsetof(type, member));          \
})

namespace virtio {

class rdma : public virtio_driver {
public:
    enum {
        VIRTIO_RDMA_DEVICE_ID = 0x100e,
    };

    explicit rdma(pci::device& dev);
    virtual ~rdma();

    virtual std::string get_name() const { return "virtio-rdma"; }

    static hw_driver* probe(hw_device* dev);

    static rdma* instance() {
        if (_instance != nullptr) {
            return _instance;
        }
        return nullptr;
    }

    enum hcall_flags {
        /* host */
        HCALL_SIGNAL_GUEST = (1),
        /* guest */
        HCALL_NOTIFY_HOST = (1 << 1)
    };

    enum hyv_event_type {
        HYV_EVENT_CQ_COMP = 0,
        HYV_EVENT_CQ,
        HYV_EVENT_QP,
        HYV_EVENT_SRQ,
        HYV_EVENT_ASYNC, /* global events like port failure */
        HYV_EVENT_ADD_DEVICE,
        HYV_EVENT_REM_DEVICE
    };

    enum {
        VIRTIO_HYV_GET_IB_DEV = 0,
        VIRTIO_HYV_PUT_IB_DEV,
        VIRTIO_HYV_MMAP,
        VIRTIO_HYV_MUNMAP,
        VIRTIO_HYV_IBV_QUERY_DEV,
        VIRTIO_HYV_IBV_QUERY_PORT,
        VIRTIO_HYV_IBV_QUERY_PKEY,
        VIRTIO_HYV_IBV_QUERY_GID,
        VIRTIO_HYV_IBV_ALLOC_UCTX,
        VIRTIO_HYV_IBV_DEALLOC_UCTX,
        VIRTIO_HYV_IBV_ALLOC_PD,
        VIRTIO_HYV_IBV_DEALLOC_PD,
        VIRTIO_HYV_IBV_CREATE_CQ,
        VIRTIO_HYV_IBV_DESTROY_CQ,
        VIRTIO_HYV_IBV_CREATE_QP,
        VIRTIO_HYV_IBV_MODIFY_QP,
        VIRTIO_HYV_IBV_QUERY_QP,
        VIRTIO_HYV_IBV_DESTROY_QP,
        VIRTIO_HYV_IBV_CREATE_SRQ,
        VIRTIO_HYV_IBV_MODIFY_SRQ,
        VIRTIO_HYV_IBV_DESTROY_SRQ,
        VIRTIO_HYV_IBV_REG_USER_MR,
        VIRTIO_HYV_IBV_DEREG_MR,
        VIRTIO_HYV_IBV_POST_SEND_NULL,
        VIRTIO_HYV_NHCALLS
    };

    // we need to keep the event structure the same as the host
    struct hyv_event
    {
        u16 type; /* event type */
        u8 port;
        u32 ibevent; /* ib event type */
        u64 id;      /* cq/qp/srq or device id*/
    };

    struct event_queue
    {
        event_queue(vring* vqueue, std::function<void ()> poll_func)
            : vq(vqueue), event_poll_task(poll_func, sched::thread::attr().
                                    name("virtio-rdma-eventq")) {};
        vring *vq;
        sched::thread event_poll_task;
        //spinlock_t lock;
    };

    // rewritten from hcall_vq struct
    struct hcall_queue
    {
        hcall_queue(vring* vqueue, std::function<void ()> poll_func)
            : vq(vqueue), hcall_poll_task(poll_func, sched::thread::attr().
                                    name("virtio-rdma-hcallq")) {};
        vring *vq;
        void *priv;
        sched::thread hcall_poll_task;
//        spinlock_t lock;
    };

// including ib_user_verbs.h will introduce a lot of issues
// we just need one definition here.
struct ib_uverbs_query_device_resp {
    uint64_t fw_ver;
    __be64 node_guid;
    __be64 sys_image_guid;
    uint64_t max_mr_size;
    uint64_t page_size_cap;
    uint32_t vendor_id;
    uint32_t vendor_part_id;
    uint32_t hw_ver;
    uint32_t max_qp;
    uint32_t max_qp_wr;
    uint32_t device_cap_flags;
    uint32_t max_sge;
    uint32_t max_sge_rd;
    uint32_t max_cq;
    uint32_t max_cqe;
    uint32_t max_mr;
    uint32_t max_pd;
    uint32_t max_qp_rd_atom;
    uint32_t max_ee_rd_atom;
    uint32_t max_res_rd_atom;
    uint32_t max_qp_init_rd_atom;
    uint32_t max_ee_init_rd_atom;
    uint32_t atomic_cap;
    uint32_t max_ee;
    uint32_t max_rdd;
    uint32_t max_mw;
    uint32_t max_raw_ipv6_qp;
    uint32_t max_raw_ethy_qp;
    uint32_t max_mcast_grp;
    uint32_t max_mcast_qp_attach;
    uint32_t max_total_mcast_qp_attach;
    uint32_t max_ah;
    uint32_t max_fmr;
    uint32_t max_map_per_fmr;
    uint32_t max_srq;
    uint32_t max_srq_wr;
    uint32_t max_srq_sge;
    uint16_t max_pkeys;
    uint8_t  local_ca_ack_delay;
    uint8_t  phys_port_cnt;
    uint8_t  reserved[4];
};

typedef struct ib_uverbs_query_device_resp hyv_query_device_result;

   struct  hyv_event_queue
    {
        atomic_t front __attribute__((aligned(64)));
        atomic_t back __attribute__((aligned(64)));
        struct hyv_event data[128];
   };

    // basic structure that we need to send to host
    struct virtio_hyv
    {
        // struct virtio_device *vdev;
        struct pci::device *vdev;
        struct hcall_queue *vq_hcall;
        struct event_queue *vq_event;

        struct hyv_event_queue *evt_queue;   // event list that will be sent to the host and back
        u64 cback; // number of callbacks ??
//        spinlock_t evt_lock;
    };

    struct hcall_header
    {
        uint32_t id : 22;
        uint32_t async : 1;
        uint32_t flags : 9;
    };

    struct hcall_parg
    {
        void *ptr;
        uint32_t size;
    };

    struct hcall_ret_header
    {
        int32_t value;
    };

    struct hyv_get_ib_device_copy_args {
        struct hcall_header hdr;
        uint32_t dev_handle;
    };

    struct hyv_ibv_query_deviceX_copy_args {
        struct hcall_header hdr;
        int32_t dev_handle;
    };

    struct hyv_ibv_query_portX_copy_args {
        struct hcall_header hdr;
        uint32_t dev_handle;
        uint8_t port_num;
    };

    struct vrdma_hypercall_result {
        struct hcall_ret_header hdr;
        int32_t value;
    };

    struct hcall
    {
        u32 async;
    };

    struct hcall_sync
    {
        struct hcall base;
    };

    struct hcall_async
    {
        struct hcall base;
        void (*cbw)(struct hcall_queue *hvq,
                struct hcall_async *async);
        void *cb;
        void *data;
        struct hcall_ret_header *hret;
        struct hcall_parg *pargs;
    };


    // hyv device
    struct hyv_device_id
    {
        uint32_t device;
        uint32_t vendor;
    };

    struct hyv_device
    {
        struct ib_device ibdev;

        int index;
        struct device dev;
        /* device id to match with hyv driver */
        struct hyv_device_id id;

        struct rdma::virtio_hyv *vg;
        uint32_t host_handle;

        void *priv;
    };

    int do_hcall_async(struct hcall_queue *hvq,
                           struct hcall_async *hcall_async,
                           const struct hcall_header *hdr, uint32_t copy_size,
                           uint32_t npargs, uint32_t result_size);
    int do_hcall_sync(struct hcall_queue *hvq,
                          const struct hcall_header *hdr, uint32_t copy_size,
                          const struct hcall_parg *pargs, uint32_t npargs,
                          struct hcall_ret_header *hret, uint32_t result_size);
    int do_hcall(struct hcall_queue *hvq, const struct hcall *hcall,
                 const struct hcall_header *hdr, uint32_t copy_size,
                 const struct hcall_parg *pargs, uint32_t npargs,
                 struct hcall_ret_header *hret, uint32_t result_size);

    virtio_hyv* get_vg() {
        return _vg;
    }

    struct hyv_cq
    {
        struct ib_cq ibcq;

        uint32_t host_handle;

        /* these are translated udata pointers */
        struct hyv_user_mem **umem;
        unsigned long n_umem;

        void *priv;
    };

    struct hyv_qp
    {
        struct ib_qp ibqp;

        uint32_t host_handle;

        /* these are translated udata pointers */
        struct hyv_user_mem **umem;
        unsigned long n_umem;

        void *priv;
    };

    int ibv_cmd_query_device(struct ibv_context *context,
                             struct ibv_device_attr *device_attr,
                             uint64_t *raw_fw_ver,
                             struct ibv_query_device *cmd, size_t cmd_size);

    struct hyv_device ib_dev;

private:
    void handle_event();
    void handle_hcall();
    void ack_irq();
    void handle_irq();
    int register_ib_dev();
    bool pop_event(struct hyv_event *event);

    // the main virtio_hyv instance.
    struct virtio_hyv *_vg;
    std::unique_ptr<pci_interrupt> _irq;
    static const size_t _pool_size = 64;
    struct hcall_queue _hcall_queue;
    struct event_queue _event_queue;
    static rdma* _instance;
};

}

#endif
