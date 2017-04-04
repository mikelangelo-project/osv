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
#include <osv/spinlock.h>
#include <asm/atomic.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <mlx4/user.h>
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
        pthread_mutex_t lock;
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
        pthread_mutex_t lock;
        pthread_cond_t cond;
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
        pthread_mutex_t evt_lock;
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

    typedef struct
    {
            uint32_t max_send_wr;
            uint32_t max_recv_wr;
            uint32_t max_send_sge;
            uint32_t max_recv_sge;
            uint32_t max_inline_data;
    } hyv_qp_cap;

    typedef struct
    {
            int32_t send_cq_handle;
            int32_t recv_cq_handle;
            int32_t srq_handle;
            int32_t xrcd_handle;
            hyv_qp_cap cap;
            uint32_t sq_sig_type;
            uint32_t qp_type;
            uint32_t create_flags;
            uint8_t port_num;
    } hyv_qp_init_attr;

    typedef struct
    {
        uint8_t raw_gid[16];
        uint32_t flow_label;
        uint8_t sgid_index;
        uint8_t hop_limit;
        uint8_t traffic_class;
    } hyv_global_route;

    typedef struct
    {
        hyv_global_route grh;
        uint16_t dlid;
        uint8_t sl;
        uint8_t src_path_bits;
        uint8_t static_rate;
        uint8_t ah_flags;
        uint8_t port_num;
    } hyv_ah_attr;

    typedef struct
    {
        uint32_t qp_state;
        uint32_t cur_qp_state;
        uint32_t path_mtu;
        uint32_t path_mig_state;
        uint32_t qkey;
        uint32_t rq_psn;
        uint32_t sq_psn;
        uint32_t dest_qp_num;
        uint32_t qp_access_flags;
        hyv_qp_cap cap;
        hyv_ah_attr ah_attr;
        hyv_ah_attr alt_ah_attr;
        uint16_t pkey_index;
        uint16_t alt_pkey_index;
        uint8_t en_sqd_async_notify;
        uint8_t sq_draining;
        uint8_t max_rd_atomic;
        uint8_t max_dest_rd_atomic;
        uint8_t min_rnr_timer;
        uint8_t port_num;
        uint8_t timeout;
        uint8_t retry_cnt;
        uint8_t rnr_retry;
        uint8_t alt_port_num;
        uint8_t alt_timeout;
    } hyv_qp_attr;

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

    struct vrdma_hypercall_result48 {
        struct hcall_ret_header hdr;
        struct {
            int16_t value1;
            int32_t value2;
        } value;
    };

    struct vrdma_hypercall_result64 {
        struct hcall_ret_header hdr;
        int64_t value;
    };

    struct vrdma_hypercall_result96 {
        struct hcall_ret_header hdr;
        struct {
            int32_t value1;
            int32_t value2;
            int32_t value3;
        } value;
    };

    struct hyv_mmap_copy_args {
        struct hcall_header hdr;
        __u32 uctx_handle;
        __u64 phys_addr;
        __u32 size;
        __u64 vm_flags;
        __u64 vm_pgoff;
    };

    typedef struct
    {
     __s32 mmap_handle;
     __u64 pgprot;
    } hyv_mmap_result_t;

    struct hyv_mmap_result {
        struct hcall_ret_header hdr;
        hyv_mmap_result_t value;
    };

    struct hyv_ibv_alloc_ucontextX_copy_args {
        struct hcall_header hdr;
        int32_t dev_handle;
    };

    struct hyv_ibv_alloc_pdX_copy_args {
        struct hcall_header hdr;
        uint32_t uctx_handle;
    };

    struct hyv_ibv_reg_user_mrX_copy_args {
        struct hcall_header hdr;
        uint32_t pd_handle;
        uint64_t user_va;
        uint64_t size;
        int32_t access;
    };

    struct hyv_ibv_create_cqX_copy_args {
        struct hcall_header hdr;
        uint64_t guest_handle;
        uint32_t uctx_handle;
        int32_t entries;
        int32_t vector;
    };

    struct hyv_munmap_copy_args {
        struct hcall_header hdr;
        __u32 mmap_handle;
    };


    struct hyv_ibv_create_qpX_copy_args {
        struct hcall_header hdr;
        __u64 guest_handle;
        __u32 pd_handle;
        hyv_qp_init_attr init_attr;
    };

    struct hyv_ibv_modify_qpX_copy_args {
        struct hcall_header hdr;
        __u32 qp_handle;
        hyv_qp_attr attr;
        __u32 attr_mask;
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
        // we keep both ib_dev and ibv_dev here.
        //struct ibv_device ibv_dev;
        struct ib_device ib_dev;

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

    struct hyv_udata
    {
        uint32_t in;
        uint32_t out;
        uint8_t data[0];
    };

    struct hyv_pd
    {
        struct ib_pd ibpd;

        uint32_t host_handle;

        struct hyv_mr_cache *dma_mr_cache;

        void *priv;
    };

    struct hyv_user_mem
    {
        struct page **pages;
        unsigned long n_pages;
    };

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


    struct hyv_srq
    {
        struct ib_srq ibsrq;

        uint32_t host_handle;

        /* these are translated udata pointers */
        struct hyv_user_mem **umem;
        unsigned long n_umem;

        void *priv;
    };

    struct hyv_ucontext
    {
        struct ib_ucontext ibuctx;

        struct list_head mmap_list;
        spinlock_t mmap_lock;
        uint32_t host_handle;

        void *priv;
    };

    struct hyv_mr
    {
        struct hlist_node node;

        struct ib_mr ibmr;

        /* we need this for kverbs dma mrs */
        u64 iova;
        u64 size;
        int access;

        struct hyv_user_mem **umem;
        unsigned long n_umem;

        uint32_t host_handle;

        void *priv;
    };

    struct hyv_user_mem_chunk
    {
        uint64_t addr;
        uint64_t size;
    };

    typedef struct
    {
        int32_t mr_handle;
        uint32_t lkey;
        uint32_t rkey;
    } hyv_reg_user_mr_result;

    struct hyv_udata_translate
    {
        uint32_t type;
        uint32_t udata_offset;
        uint32_t n_chunks;
        hyv_user_mem_chunk chunk[0];
    };

    enum hyv_udata_gvm_type {
        HYV_IB_UMEM,
        HYV_COPY_FROM_GUEST,
        HYV_COPY_TO_GUEST
    };

    struct hyv_udata_gvm
    {
        enum hyv_udata_gvm_type type;

        /* offset into user cmd */
        unsigned long udata_offset;
        unsigned long mask;
        unsigned long size;
    };

    struct hyv_mmap
    {
        struct list_head list;

        void *addr;
        size_t size;
        uint32_t key;

        bool mapped;
        uint32_t host_handle;
    };

    struct virtmlx4_ucontext
    {
        struct hyv_mmap *uar_mmap;
        struct hyv_mmap *bf_mmap;
    };

    enum mlx4_ib_mmap_cmd {
        MLX4_IB_MMAP_UAR_PAGE = 0,
        MLX4_IB_MMAP_BLUE_FLAME_PAGE = 1,
        MLX4_IB_MMAP_GET_CONTIGUOUS_PAGES = 2,
        MLX4_IB_MMAP_GET_HW_CLOCK = 3,
    };

    typedef struct
    {
        int32_t cq_handle;
        int32_t cqe;
    } hyv_create_cq_result;

    typedef struct
    {
            uint32_t qp_handle;
            uint32_t qpn;
            hyv_qp_cap cap;
    } hyv_create_qp_result;

    struct hyv_udata_translate* udata_translate_create(hyv_udata *udata,
                                                       struct hyv_user_mem **umem,
                                                       struct hyv_udata_gvm *udata_gvm,
                                                       uint32_t udata_gvm_num,
                                                       uint32_t *n_chunks_total);
    struct hyv_udata* udata_create(struct ib_udata *ibudata);
    int udata_copy_out(hyv_udata *udata, struct ib_udata *ibudata);
    struct hyv_mmap* mmap_prepare(void **addr, uint32_t size, uint32_t key);
    void mmap_unprepare(struct hyv_mmap *mm);
    struct hyv_user_mem* pin_user_mem(unsigned long va, unsigned long size,
                                      hyv_user_mem_chunk **chunks, unsigned long *n_chunks, bool write);
    int vrdma_mmap(struct hyv_mmap *mm);
    int vrdma_unmap(struct hyv_mmap *mm);

    // implementations of the verb calls using hypercall
    int vrdma_open_device(int *result);
    int vrdma_query_device(ib_uverbs_query_device_resp *attr, int *result);
    int vrdma_query_port(ib_uverbs_query_port_resp *attr, int port_num, int *result);
    struct ib_ucontext *vrdma_alloc_ucontext(struct ib_udata *ibudata, void **uar, void **bf_page);
    struct ib_pd* vrdma_alloc_pd(struct ib_udata *ibudata);
    struct ib_mr* vrdma_reg_mr(u64 user_va, u64 size, u64 io_va, int access, struct ib_udata *ibudata);
    struct ib_cq* vrdma_create_cq(int entries, int vector, struct ib_udata *udata);
    struct ib_qp* vrdma_create_qp(struct ib_qp_init_attr *attr, struct ib_udata *udata);
    int vrdma_modify_qp(struct ib_qp_attr *ibattr, int cmd_attr_mask, struct ib_udata *ibudata);

    struct hyv_device hyv_dev;
    struct hyv_ucontext *hyv_uctx;

    // TODO: consider to change following into list objects
    // as there may be multiple of hcq in one peer
    struct hyv_pd *hpd;
    struct hyv_mr *hmr;
    struct hyv_cq *hcq;
    struct hyv_qp *hqp;

private:
    void handle_event();
    void handle_hcall();
    void ack_irq();
    void handle_irq();
    int register_ib_dev();
    bool pop_event(struct hyv_event *event);
    void copy_ib_qp_cap_to_hyv(const struct ib_qp_cap *ibcap, hyv_qp_cap *gcap);
    void copy_ib_ah_attr_to_hyv(const struct ib_ah_attr *ibahattr, hyv_ah_attr *gahattr);

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
