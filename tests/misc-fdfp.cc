/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

/*
http://www.informit.com/articles/article.aspx?p=2065718
*/

//
// Instructions: run this test with 4 vcpus
//
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cstdlib>
#include <ctime>
#include <osv/sched.hh>
#include <arch.hh>
#include <osv/clock.hh>
#include <osv/debug.hh>
#include <osv/file.h>

//
// Create 2 threads on different CPUs which perform lookup
//
class test_fdfp {
public:
    int _num_th = 1;
    int _num_fd = 32*32;
    u64 _elements_to_process = 1000*10;
    u64 *_count;
    int *_myfd;
    struct file* *_myfp;

public:
    test_fdfp(int num_th, int num_fd, u64 num_elements)
    {
        _num_th = num_th;
        _num_fd = num_fd;
        _elements_to_process = num_elements;

        _count = (typeof(_count)) calloc(_num_th, sizeof(_count[0]));
        _myfd = (typeof(_myfd)) calloc(_num_fd, sizeof(_myfd[0]));
        _myfp = (typeof(_myfp)) calloc(_num_fd, sizeof(_myfp[0]));
    }

    void setup()
    {
        int ii, ret;
        int fd;
        struct file * fp;
        char filename[100];
        for (ii=0; ii<_num_fd; ii++) {
            snprintf(filename, sizeof(filename), "/tmp/ff-%06d", ii);
            fd = open(filename, O_RDWR | O_CREAT);
            assert(fd > 0);
            ret = fget(fd, &fp);
            assert(ret == 0);
            fdrop(fp);
            _myfd[ii] = fd;
            _myfp[ii] = fp;
        }
    }

    bool run()
    {
        assert (sched::cpus.size() >= 2);

        sched::thread* *thread = (sched::thread**)malloc(_num_th*sizeof(sched::thread*));
        for (int ii=0; ii<_num_th; ii++) {
            //thread[ii] = sched::thread::make([&    ] {thread_counter(ii); debug("  IN-TH _num_th=%d ii=%d\n", _num_th, ii);}, // BUG !!!
            thread[ii] = sched::thread::make([&, ii] {thread_counter(ii);},
            sched::thread::attr().pin(sched::cpus[ii % sched::cpus.size()]));
        }
        //fd_from_file__cache_build();

        for (int ii=0; ii<_num_th; ii++) {
            thread[ii]->start();
        }
        for (int ii=0; ii<_num_th; ii++) {
            thread[ii]->join();
        }

        for (int ii=0; ii<_num_th; ii++) {
            //delete thread[ii];
            thread[ii] = nullptr;
        }
        free(thread);
        thread = nullptr;

        bool success = true;
        debug("Results:\n");
        debug("    count =");
        for (int ii=0; ii<_num_th; ii++) {
            debug(" %-08d", _count[ii]);
        }
        debug("\n");
        for (int ii=0; ii<_num_th; ii++) {
            if (_count[0] != _count[ii]) {
                success = false;
            }
        }

        return success;
    }

private:

    void thread_counter(int cpu_id)
    {
        std::srand(std::time(0));
        int cfd;
        struct file *cfp;
        for (u64 ctr=0; ctr < _elements_to_process; ctr++)
        {
            for (int ii=0; ii<_num_fd; ii++) {
                cfp = _myfp[ii];

                //cfd = fd_from_file___unordered_map(cfp);
                //cfd = fd_from_file___map(cfp);
                //cfd = fd_from_file___boost_unordered_map(cfp);
                //cfd = fd_from_file___boost_map(cfp);
                //cfd = fd_from_file___boost_flat_map(cfp);
                cfd = fd_from_file(cfp);

                assert(_myfd[ii] == cfd);
                _count[cpu_id]++;
            }
        }
    }

};

s64 nanotime() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>
                (osv::clock::wall::now().time_since_epoch()).count();
}

int main(int argc, char **argv)
{
    // Test
    int ret;
    debug("[~] Testing fd to fp lookup:\n");
    int num_th = 2;
    int num_fd = 16;
    u64 num_elements = 1000;
    switch (argc) {
        case 4:
            num_elements = atoi(argv[3]);
        case 3:
            num_fd = atoi(argv[2]);
        case 2:
            num_th = atoi(argv[1]);
        case 1:
        default:
            break;
    }
    debug("[~] param: num_th=%d num_fd=%d num_elements=%d\n", num_th, num_fd, (int)num_elements);

    test_fdfp *t1 = new test_fdfp(num_th, num_fd, num_elements);
    t1->setup();
    s64 beg = nanotime();
    bool rc = t1->run();
    s64 end = nanotime();
    if (rc) {
        double dT = (double)(end-beg)/1000000000.0;
        debug("[+] fdfp test passed:\n");
        debug("[+] duration: %.6fs\n", dT);
        auto num_ops = t1->_count[0]; // per worker thread
        debug("[+] throughput: %.0f ops/s (sum all cores)\n", (double)(num_ops * t1->_num_th)/dT);
        debug("[+] throughput: %.0f ops/s (sum per core)\n", (double)(num_ops)/dT);
        ret = 0;
    } else {
        debug("[-] fdfp failed\n");
        ret = 1;
    }
    delete t1;
    t1 = nullptr;

    debug("[+] finished.\n");
    return ret;
}
