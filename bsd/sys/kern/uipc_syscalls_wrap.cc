#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <bsd/uipc_syscalls.h>
#include <osv/debug.h>
#include "libc/af_local.h"

#include "libc/internal/libc.h"

#include <osv/elf.hh>
#define sock_d(...)		tprintf_d("socket-api", __VA_ARGS__);

extern "C"
int socketpair(int domain, int type, int protocol, int sv[2])
{
	int error;
	sock_d("socketpair(domain=%d, type=%d, protocol=%d)", domain, type,
		protocol);

	if (domain == AF_LOCAL)
		return socketpair_af_local(type, protocol, sv);
	if(!using_rsocket) {
		error = linux_socketpair(domain, type, protocol, sv);
		if (error) {
		        sock_d("socketpair() failed, errno=%d", error);
			errno = error;
			return -1;
		}
	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, const int, const int, int *)>("rgsocketpair");
	        if(!libbprld_function){
			sock_d("cannot find rgsocketpair() function");
			return -1;
		}

		error=libbprld_function(domain, type, protocol, sv);
		if (error) {
			sock_d("rgsocketpair() function call failed, errno=%d", error);
			errno = error;
	                return -1;
		}
	}
	return 0;
}

extern "C"
int getsockname(int sockfd, struct bsd_sockaddr *addr, socklen_t *addrlen)
{
	int error;
	sock_d("getsockname(sockfd=%d, ...)", sockfd);

	if(!using_rsocket) {
		error = linux_getsockname(sockfd, addr, addrlen);
		if (error) {
			sock_d("getsockname() failed, errno=%d", error);
			errno = error;
			return -1;
		}
	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
	        auto libbprld_function =  _libprld->lookup<int (const int,const struct bsd_sockaddr *, socklen_t* )>("rgetsockname");

		if(!libbprld_function) {
			sock_d("cannot find rgetsockname() function");
			return -1;
		}

		error=libbprld_function(sockfd, addr, addrlen);

		if (error) {
			sock_d("rgetsockname() function call failed, errno=%d", error);
			errno = error;
		        return -1;
		}

	}
	return 0;
}

extern "C"
int getpeername(int sockfd, struct bsd_sockaddr *addr, socklen_t *addrlen)
{
	int error;
	sock_d("getpeername(sockfd=%d, ...)", sockfd);

	if(!using_rsocket) {
		error = linux_getpeername(sockfd, addr, addrlen);
		if (error) {
			sock_d("getpeername() failed, errno=%d", error);
			errno = error;
			return -1;
		}

	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int,const struct bsd_sockaddr *, socklen_t* )>("rgetpeername");
		if(!libbprld_function){
			sock_d("cannot find rgetpeername() function");
			return -1;
		}

		error=libbprld_function(sockfd, addr, addrlen);
		if (error) {
			sock_d("rgetpeername() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}
	}
	return 0;
}

extern "C"
int accept4(int fd, struct bsd_sockaddr *__restrict addr, socklen_t *__restrict len, int flg)
{
	int fd2, error;
	sock_d("accept4(fd=%d, ..., flg=%d)", fd, flg);

	error = linux_accept4(fd, addr, len, &fd2, flg);
	if (error) {
		sock_d("accept4() failed, errno=%d", error);
		errno = error;
		return -1;
	}
	return fd2;
}

extern "C"
int accept(int fd, struct bsd_sockaddr *__restrict addr, socklen_t *__restrict len)
{
	int fd2, error;
	sock_d("accept(fd=%d, ...)", fd);

	if(!using_rsocket) {

		error = linux_accept(fd, addr, len, &fd2);
		if (error) {
			sock_d("accept() failed, errno=%d", error);
			errno = error;
			return -1;
		}

	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int,const struct bsd_sockaddr *, socklen_t* )>("raccept");
		if(!libbprld_function) {
			sock_d("cannot find raccept() function");
			return -1;
		}

		fd2=libbprld_function(fd, addr, len);
		if (error) {
			sock_d("raccept() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}
	}
	return fd2;
}

extern "C"
int bind(int fd, const struct bsd_sockaddr *addr, socklen_t len)
{
	int error;
	sock_d("bind(fd=%d, ...)", fd);

	if(!using_rsocket) {
		error = linux_bind(fd, (void *)addr, len);
			if (error) {
				sock_d("bind() failed, errno=%d", error);
				errno = error;
				return -1;
			}
	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int,const struct bsd_sockaddr *, socklen_t )>("rbind");

		if(!libbprld_function){
			sock_d("cannot find rbind() function");
			return -1;
		}

		error=libbprld_function(fd, addr, len);
		if (error) {
			sock_d("rbind() function call failed, errno=%d", error);
	                errno = error;
			return -1;
		}
	}
	return 0;
}

extern "C"
int connect(int fd, const struct bsd_sockaddr *addr, socklen_t len)
{
	int error;
	sock_d("connect(fd=%d, ...)", fd);

	if(!using_rsocket) {
		error = linux_connect(fd, (void *)addr, len);
		if (error) {
			sock_d("connect() failed, errno=%d", error);
			errno = error;
			return -1;
		}

	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int,const struct bsd_sockaddr *, socklen_t )>("rconnect");
		if(!libbprld_function) {
			sock_d(" cannot find rconnect() function");
			return -1;
		}

		error=libbprld_function(fd, addr, len);
		if (error) {
			sock_d(" rconnect() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}
	}
	return 0;
}

extern "C"
int listen(int fd, int backlog)
{
	int error;
	sock_d("listen(fd=%d, backlog=%d)", fd, backlog);

	if(!using_rsocket) {
		error = linux_listen(fd, backlog);
		if (error) {
			sock_d("listen() failed, errno=%d", error);
			errno = error;
			return -1;
		}
	} else {

	        auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, const int )>("rlisten");
		if(!libbprld_function){
			sock_d(" cannot find rlisten() function");
			return -1;
		}

		error=libbprld_function(fd, backlog);
		if (error) {
			sock_d(" rlisten() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}
	}
	return 0;
}

extern "C"
ssize_t recvfrom(int fd, void *__restrict buf, size_t len, int flags,
		struct bsd_sockaddr *__restrict addr, socklen_t *__restrict alen)
{
	int error;
	ssize_t bytes;
	sock_d("recvfrom(fd=%d, buf=<uninit>, len=%d, flags=0x%x, ...)", fd,
		len, flags);
	if(!using_rsocket) {
		error = linux_recvfrom(fd, (caddr_t)buf, len, flags, addr, alen, &bytes);
		if (error) {
			sock_d("recvfrom() failed, errno=%d", error);
			errno = error;
			return -1;
		}
	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, void *__restrict, size_t,
			const int, struct bsd_sockaddr *__restrict,  socklen_t *__restrict )>("rrecvfrom");
	        if(!libbprld_function) {
			sock_d("cannot find rrecvfrom() function");
			return -1;
		}

		bytes=libbprld_function(fd,  buf, len, flags, addr, alen);
		if (error) {
			sock_d(" rrecvfrom() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}
	}
	return bytes;
}

extern "C"
ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	int error;
	ssize_t bytes;

	sock_d("recv(fd=%d, buf=<uninit>, len=%d, flags=0x%x)", fd, len, flags);

	if(!using_rsocket) {
		error = linux_recv(fd, (caddr_t)buf, len, flags, &bytes);
		if (error) {
			sock_d("recv() failed, errno=%d", error);
			errno = error;
			return -1;
		}
	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, void *, size_t, const int )>("rrecv");
	        if(!libbprld_function) {
			sock_d(" cannot find rrecv() function");
			return -1;
		}
		bytes=libbprld_function(fd,  buf, len, flags);
		if (error) {
			sock_d("rrecv() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}
	}
	return bytes;
}

extern "C"
ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
	ssize_t bytes;
	int error;

	sock_d("recvmsg(fd=%d, msg=..., flags=0x%x)", fd, flags);
	if(!using_rsocket) {
		error = linux_recvmsg(fd, msg, flags, &bytes);
		if (error) {
			sock_d("recvmsg() failed, errno=%d", error);
			errno = error;
			return -1;
		}

	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, struct msghdr *, const int )>("rrecvmsg");
		if(!libbprld_function) {
			sock_d("cannot find rrecvmsg() function");
			return -1;
		}

		bytes=libbprld_function(fd, msg, flags);
		if (error) {
			sock_d("rrecvmsg() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}
	}
	return bytes;
}

extern "C"
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
    const struct bsd_sockaddr *addr, socklen_t alen)
{
	int error;
	ssize_t bytes;

	sock_d("sendto(fd=%d, buf=..., len=%d, flags=0x%x, ...", fd, len, flags);
	if(!using_rsocket) {

		error = linux_sendto(fd, (caddr_t)buf, len, flags, (caddr_t)addr,
				   alen, &bytes);
		if (error) {
			sock_d("sendto() failed, errno=%d", error);
			errno = error;
			return -1;
		}

	} else {
	        auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, const void  *, size_t,
			const int, const struct bsd_sockaddr* )>("rsendto");
		if(!libbprld_function) {
			sock_d(" cannot find rsendto() function");
			return -1;
		}
		bytes=libbprld_function(fd, buf, len, flags, addr);
		if (error) {
			sock_d(" rsendto() function call failed, errno=%d", error);
	                errno = error;
			return -1;
		}
	}
	return bytes;
}

extern "C"
ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	int error;
	ssize_t bytes;

	sock_d("send(fd=%d, buf=..., len=%d, flags=0x%x)", fd, len, flags)

	if(!using_rsocket) {

		error = linux_send(fd, (caddr_t)buf, len, flags, &bytes);
		if (error) {
			sock_d("send() failed, errno=%d", error);
			errno = error;
			return -1;
		}

	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, const void  *, size_t, const int)>("rsend");
	        if(!libbprld_function) {
			sock_d("cannot find rsend() function");
			return -1;
		}

		bytes=libbprld_function(fd, buf, len, flags);
		if (error) {
			sock_d("####### rsend() function call failed, errno=%d", error);
	                errno = error;
			return -1;
		}
	}
	return bytes;
}

extern "C"
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	ssize_t bytes;
	int error;

	sock_d("sendmsg(fd=%d, msg=..., flags=0x%x)", fd, flags);

	if(!using_rsocket) {
		error = linux_sendmsg(fd, (struct msghdr *)msg, flags, &bytes);
		if (error) {
			sock_d("sendmsg() failed, errno=%d", error);
			errno = error;
			return -1;
		}

	} else {
	        auto _libprld =elf::get_program()->get_library("librspreload.so");
	        auto libbprld_function =  _libprld->lookup<int (const int, const msghdr *, const int)>("rsendmsg");
	        if(!libbprld_function) {
			sock_d(" cannot find rsendmsg() function");
			return -1;
		}

		bytes=libbprld_function(fd, msg, flags);
		if (error) {
			sock_d(" rsendmsg() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}
	}
	return bytes;
}

extern "C"
int getsockopt(int fd, int level, int optname, void *__restrict optval,
		socklen_t *__restrict optlen)
{
	int error;
	sock_d("getsockopt(fd=%d, level=%d, optname=%d)", fd, level, optname);
	if(!using_rsocket) {
		error = linux_getsockopt(fd, level, optname, optval, optlen);
		if (error) {
			sock_d("getsockopt() failed, errno=%d", error);
			errno = error;
			return -1;
	        }
        } else {
	        auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, const int, const int,
			const void *__restrict, socklen_t *__restrict )>("rgetsockopt");
		if(!libbprld_function) {
			sock_d("cannot find rgetsockopt() function");
			return -1;
		}

		error=libbprld_function(fd, level, optname, optval, optlen);
		if (error) {
			sock_d(" rgetsockopt() function call failed, errno=%d", error);
	                errno = error;
			return -1;
		}
	}
	return 0;
}


extern "C"
int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	int error;
	sock_d("setsockopt(fd=%d, level=%d, optname=%d, (*(int)optval)=%d, optlen=%d)",
		fd, level, optname, *(int *)optval, optlen);

	if (!using_rsocket) {

		error = linux_setsockopt(fd, level, optname, (caddr_t)optval, optlen);
		if (error) {
			sock_d("setsockopt() failed, errno=%d", error);
			errno = error;
			return -1;
		}
	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, const int, const int,
			const void *, socklen_t  )>("rsetsockopt");
		if(!libbprld_function) {
			sock_d(" cannot find rsetsockopt() function");
			return -1;
		}

		error=libbprld_function(fd, level, optname, optval, optlen);
		if (error) {
			sock_d(" rsetsockopt() function call failed, errno=%d", error);
			errno = error;
			return -1;
		}

	}
	return 0;
}

extern "C"
int shutdown(int fd, int how)
{
	int error;

	sock_d("shutdown(fd=%d, how=%d)", fd, how);

	// Try first if it's a AF_LOCAL socket (af_local.cc), and if not
	// fall back to network sockets. TODO: do this more cleanly.
	error = shutdown_af_local(fd, how);
	if (error != ENOTSOCK) {
		return error;
	}
	if (!using_rsocket) {
		error = linux_shutdown(fd, how);
		if (error) {
			sock_d("shutdown() failed, errno=%d", error);
			errno = error;
			return -1;
		}
	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, const int)>("rshutdown");
		if(!libbprld_function) {
			debug("cannot find rshutdown() function");
			return -1;
		}

		error=libbprld_function(fd, how);
		if (error) {
			sock_d("rshutdown() function call failed, errno=%d", error);
	                errno = error;
			return -1;
		}

	}
	return 0;
}

extern "C"
int socket(int domain, int type, int protocol)
{
	int s, error;
	sock_d("socket(domain=%d, type=%d, protocol=%d)", domain, type, protocol);
        if (!using_rsocket) {
		error = linux_socket(domain, type, protocol, &s);
		if (error) {
			sock_d("socket() failed, errno=%d", error);
			errno = error;
			return -1;
		}
	} else {
		auto _libprld =elf::get_program()->get_library("librspreload.so");
		auto libbprld_function =  _libprld->lookup<int (const int, const int, const int)>("rsocket");
		if(!libbprld_function) {
			debug("cannot find rsocket() function");
			return -1;
		}

		s=libbprld_function(domain, type, protocol);
		if (s) {
			sock_d("rsocket() function call failed, errno=%d", error);
			errno = s;
			return -1;
		}
	}
	return s;
}
