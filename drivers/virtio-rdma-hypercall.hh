#ifndef VIRTIO_RDMA_HYPERCALL_H_
#define VIRTIO_RDMA_HYPERCALL_H_

#include <stdint.h>

typedef struct ib_uverbs_query_device_resp hyv_query_device_result;

enum hypercall_flags {
	/* host */
	HYPERCALL_SIGNAL_GUEST = (1),
	/* guest */
	HYPERCALL_NOTIFY_HOST = (1 << 1)
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

struct hypercall_header {
	__u32 id : 22;
	__u32 async : 1;
	__u32 flags : 9;
};

struct hypercall_ret_header {
	__s32 value;
};

#define VOID(...)

#define ARG_VAR(a, b) a b;

#define ARG_DEF(a, b) , a b

#define ARG_COUNT(...) +1

#define ARG_PTR_DEF(a, b, c) , a b, uint32_t c

#define ARG_PTR_VAR(a, b, c)							\
	a __kernel b;								\
	uint32_t c;

#define QUERY_DEV_ARGS(copy_arg, ptr_arg)					\
	copy_arg(uint32_t, dev_handle)						\
	ptr_arg(hyv_query_device_result *, attr, attr_size)

#define HYPERCALL_COPY_ARGS(name, args)						\
	struct name##_copy_args							\
	{									\
		struct hypercall_header hdr;					\
		args(ARG_VAR, VOID)						\
	}

#define HYPERCALL_RESULT(name, ret_type)					\
	struct name##_result							\
	{									\
		struct hypercall_ret_header hdr;				\
		ret_type value;							\
	}

#define HYPERCALL_FUNC(name, ret_type, args)					\
	inline int name(struct hypercall_vq *hvq, enum hypercall_flags flags,	\
			gfp_t mem_flags,					\
			ret_type *result args(ARG_DEF, ARG_PTR_DEF))

#define HYPERCALL_FUNC_ASYNC(name, ret_type, args)				\
	inline int name##_async(struct hypercall_vq *hvq,			\
				enum hypercall_flags flags, gfp_t mem_flags,	\
				name##_callback cb,				\
				void *data args(ARG_DEF, ARG_PTR_DEF))

#define DECL_HYPERCALL(name, ret_type, args)					\
	typedef void (*name##_callback)(					\
	struct hypercall_vq *hvq, void *data, int hcall_result,			\
	ret_type *result args(VOID, ARG_PTR_DEF));				\
	HYPERCALL_COPY_ARGS(name, args);					\
	HYPERCALL_RESULT(name, ret_type);					\
	HYPERCALL_FUNC(name, ret_type, args);					\
	HYPERCALL_FUNC_ASYNC(name, ret_type, args)

struct hypercall_parg {
	void __kernel *ptr;
	uint32_t size;
};

struct hypercall {
	u32 async;
};

struct hypercall_sync {
	struct hypercall base;
	//struct completioc completion;
};

struct hypercall_async {
	struct hypercall base;
	void (*cbw)(struct hypercall_vq *hvq,
		    struct hypercall_async *hcall_async);
	void *cb;
	void *data;
	struct hypercall_ret_header *hret;
	struct hypercall_parg *pargs;
};

int do_hypercall_sync(struct hypercall_vq *hvq,
			const struct hypercall_header *hdr, uint32_t copy_size,
			const struct hypercall_parg *pargs, uint32_t npargs,
			struct hypercall_ret_header *hret, uint32_t result_size);

int do_hypercall_async(struct hypercall_vq *hvq,
			struct hypercall_async *hcall_async,
			const struct hypercall_header *hdr, uint32_t copy_size,
			uint32_t npargs, uint32_t result_size);

#define ARG_ASSIGN(a, b) memcpy(&_args->copy_args.b, &b, sizeof(b));

#define ARG_PTR_ASSIGN(a, b, c)							\
	_async_args->pargs[i++] = (struct hypercall_parg) { b, c };

#define ARG_PTR_ASSIGN2(a, b, c)						\
	_args.b = (a __kernel)hcall_async->pargs[i].ptr;			\
	_args.c = hcall_async->pargs[i++].size;

#define ARG_PTR_INIT(a, b, c)							\
	{									\
		b, c								\
	}									\
	,

#define ARG_PTR_CALL(a, b, c) , _args.b, _args.c

/* id is not in declartion because hypercall declaration might be used
 * by different virtio devices, i.e. different IDs */
#define DEF_HYPERCALL(host_id, name, ret_type, args)				\
	struct name##_args							\
	{									\
		struct name##_copy_args copy_args;				\
		struct name##_result result;					\
        } *_args;								\
	HYPERCALL_FUNC(name, ret_type, args)					\
	{									\
		int ret;							\
		const struct hypercall_parg pargs[] = { args(VOID,		\
			ARG_PTR_INIT) };					\
		_args = (name##_args *) kmalloc(sizeof(*_args), mem_flags);	\
		if (!_args) {							\
			return -ENOMEM;						\
		}								\
		_args->copy_args.hdr =						\
			(struct hypercall_header) { host_id, 0, flags };	\
		args(ARG_ASSIGN, VOID);						\
		ret = do_hypercall_sync(hvq, &_args->copy_args.hdr,		\
					sizeof(_args->copy_args), pargs,	\
					ARRAY_SIZE(pargs), &_args->result.hdr,	\
					sizeof(_args->result));			\
		if (!ret)							\
			memcpy(result, &_args->result.value, sizeof(*result));	\
		kfree(_args);							\
		return ret;							\
	}									\
		inline void name##_callback_wrapper(				\
		struct hypercall_vq *hvq, struct hypercall_async *hcall_async)	\
        {									\
                uint32_t i __attribute__((unused)) = 0;				\
                struct name##_callback_wrapper_args				\
		{								\
			args(VOID, ARG_PTR_VAR);				\
		} __attribute__((unused)) _args;				\
                name##_callback cb = (name##_callback) hcall_async->cb;		\
			struct name##_result *result =				\
				(struct name##_result *)hcall_async->hret;	\
		args(VOID, ARG_PTR_ASSIGN2);					\
		cb(hvq, hcall_async->data, result->hdr.value,			\
			&result->value args(VOID, ARG_PTR_CALL));		\
	}									\
		struct name##_args_async					\
		{								\
			struct hypercall_async hcall_async;			\
			struct name##_copy_args copy_args;			\
			struct name##_result result;				\
			struct hypercall_parg pargs[0 args(VOID, ARG_COUNT)];  	\
		} *_async_args;                                                	\
	HYPERCALL_FUNC_ASYNC(name, ret_type, args)                             	\
	{                                                                      	\
		int ret;                                                       	\
		uint32_t i = 0;                                                	\
		_async_args = (name##_args_async *)kmalloc(sizeof(*_async_args), mem_flags);                    \
		if (!_async_args) {						\
			return -ENOMEM;						\
		}								\
		_async_args->hcall_async.cbw = &name##_callback_wrapper;	\
             	_async_args->hcall_async.cb = (name##_callback *) cb;		\
		_async_args->hcall_async.data = data;				\
		_async_args->hcall_async.hret = &_async_args->result.hdr;	\
		_async_args->hcall_async.pargs = _async_args->pargs;		\
		args(VOID, ARG_PTR_ASSIGN);					\
		_async_args->copy_args.hdr =					\
		    (struct hypercall_header) { host_id, 1, flags };		\
		args(ARG_ASSIGN, VOID);						\
		ret = do_hypercall_async(                                      	\
		    hvq, &_async_args->hcall_async, &_async_args->copy_args.hdr,           \
		    sizeof(_async_args->copy_args), i, sizeof(_async_args->result));       \
		return ret;                                                    \
		}

DECL_HYPERCALL(hyv_ibv_query_deviceX, int32_t, QUERY_DEV_ARGS);


#endif /*VIRTIO_RDMA_HYPERCALL_H_ */
