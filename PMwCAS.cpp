#include "PMwCAS.h"
#include "bzconfig.h"
#include "bzerrno.h"
#include <assert.h>
#include <atomic>
#include <stdint.h>
#include <thread>

#ifdef BZ_DEBUG
#include <iomanip>
#include <fstream>
#include <mutex>
std::mutex flag;
std::fstream mem_fs("memory.txt", std::ios::app);
#endif // BZ_DEBUG

using namespace std;
uint64_t GC_CAN_QUIT = 0;
uint64_t GC_BUSY = 1;
uint64_t GC_QUIT = 2;
uint64_t gc_alive = GC_CAN_QUIT;

/* set desc status to FREE */
void pmwcas_first_use(mdesc_pool_t pool, PMEMobjpool *pop, PMEMoid oid) {
  for (off_t i = 0; i < DESCRIPTOR_POOL_SIZE; ++i) {
    pool->mdescs[i].status = ST_FREE;
    persist(&pool->mdescs[i].status, sizeof(pool->mdescs[i].status));
  }
  for (off_t i = 0; i < WORD_DESCRIPTOR_SIZE; ++i) {
    pool->magic[i] = 0;
    persist(&pool->magic[i], sizeof(uint64_t));
  }
  pool->mem_.init(pop, oid);
  pool->mem_.prev_alloc();
}

void pmwcas_reclaim(gc_entry_t *entry, void *arg);

/* 
* set base address 
* set mdesc_pool ptr
* init gc
*/
int pmwcas_init(mdesc_pool_t pool, PMEMoid oid, PMEMobjpool * pop)
{
	/* base address */
	rel_ptr<uint64_t>::set_base(oid);
	rel_ptr<word_entry>::set_base(oid);
	rel_ptr<pmwcas_entry>::set_base(oid);
	/* mdesc_pool */
	for (off_t i = 0; i < DESCRIPTOR_POOL_SIZE; ++i)
	{
		pool->mdescs[i].mdesc_pool = pool;
	}
	/* init gc */
	if (!(pool->gc = gc_create(offsetof(struct pmwcas_entry, gc_entry), pmwcas_reclaim, (void*)pool)))
		return EGCCREAT;
	/* init mem_pool */
	pool->mem_.init(pop, oid);
        /* 创建GC线程 */
        gc_alive = GC_CAN_QUIT;
        for (int i = 0; i < GC_THREADS_COUNT; ++i) {
          std::thread gc([pool] {
            //	uint64_t gc_rd;
            while (true) {
              do {
                __sync_bool_compare_and_swap(&gc_alive, GC_CAN_QUIT, GC_BUSY);
              } while (gc_alive == GC_BUSY);
              if (gc_alive == GC_QUIT)
                break;
              assert(pool->gc);
              gc_cycle(pool->gc);
              __sync_bool_compare_and_swap(&gc_alive, GC_BUSY, GC_CAN_QUIT);
              std::this_thread::sleep_for(
                  std::chrono::milliseconds(GC_WAIT_MS));
            }
          });
          gc.detach();
        }
        return 0;
}

void pmwcas_finish(mdesc_pool_t pool)
{
  while (!__sync_bool_compare_and_swap(&gc_alive, GC_CAN_QUIT, GC_QUIT))
    ;
  gc_full(pool->gc, 50);
  gc_destroy(pool->gc);
  pool->gc = nullptr;
}

/* allocate a PMwCAS desc; enter crit; return base_address if failed */
mdesc_t pmwcas_alloc(mdesc_pool_t pool, off_t recycle_policy, off_t search_pos) 
{
	if (recycle_policy > 2)
	{
		return mdesc_t::null();
	}
	for (off_t i = 0; i < DESCRIPTOR_POOL_SIZE; ++i)
	{
		off_t pos = (i + search_pos) % DESCRIPTOR_POOL_SIZE;
		if (pool->mdescs[pos].status == ST_FREE)
		{
                  __sync_bool_compare_and_swap(&pool->mdescs[pos].status,
                                               ST_FREE, ST_UNDECIDED);
                  if (pool->mdescs[pos].status == ST_FREE) {
                    pool->mdescs[pos].count = 0;
                    persist((uint64_t *)&pool->mdescs[pos].count,
                            sizeof(uint64_t));
                    pool->mdescs[pos].callback = recycle_policy;
                    persist((uint64_t *)&pool->mdescs[pos].callback,
                            sizeof(uint64_t));
                    return &pool->mdescs[pos];
                  }
                }
	}
	return mdesc_t::null();
}

bool pmwcas_abort(mdesc_t mdesc)
{
  return __sync_bool_compare_and_swap(&mdesc->status, ST_UNDECIDED, ST_FREE);
}

rel_ptr<uint64_t> get_magic(mdesc_pool_t pool, int magic)
{
	return rel_ptr<uint64_t>(&pool->magic[magic]);
}

/* exit crit; add PMwCAS entry to gc list */
void pmwcas_free(mdesc_t mdesc) 
{
	//gc_crit_exit(mdesc->mdesc_pool->gc);
	gc_limbo(mdesc->mdesc_pool->gc, mdesc.abs());
}

/* reset desc status to FREE; reclaim memory accoding to policy */
void pmwcas_reclaim(gc_entry_t *entry, void *arg)
{
	mdesc_pool_t pool = (mdesc_pool_t)arg;
	const off_t off = pool->gc->entry_off;
	mdesc_t mdesc;

	while (entry) {
          mdesc = (mdesc_t)(pmwcas_entry *)((unsigned char *)entry - off);
          entry = entry->next;

          for (off_t j = 0; j < mdesc->count; ++j) {
            wdesc_t wdesc = mdesc->wdescs + j;
            bool done = mdesc->status == ST_SUCCESS;
            uint64_t val = done ? wdesc->new_val : wdesc->expect;

            /* 根据回收规则回收 */
            if (wdesc->recycle_func == NOCAS_RELEASE_ADDR_ON_SUCCESS && done &&
                !wdesc->addr.is_null()) {
              pmwcas_word_recycle(pool, &wdesc->addr);
            } else if (wdesc->recycle_func == NOCAS_EXECUTE_ON_FAILED &&
                       !done) {
              __sync_bool_compare_and_swap(wdesc->addr.abs(), wdesc->expect,
                                           wdesc->new_val);
            } else if (wdesc->recycle_func == NOCAS_RELEASE_NEW_ON_FAILED &&
                       !done && wdesc->new_val) {
              pmwcas_word_recycle(pool, (rel_ptr<uint64_t> *)&wdesc->new_val);
            }
            if ((wdesc->recycle_func == RELEASE_NEW_ON_FAILED ||
                 wdesc->recycle_func == RELEASE_SWAP_PTR) &&
                !done && wdesc->new_val) {
              pmwcas_word_recycle(pool, (rel_ptr<uint64_t> *)&wdesc->new_val);
            }
            if ((wdesc->recycle_func == RELEASE_EXP_ON_SUCCESS ||
                 wdesc->recycle_func == RELEASE_SWAP_PTR) &&
                done && wdesc->expect) {
              /* 成功时回收expect */
              pmwcas_word_recycle(pool, (rel_ptr<uint64_t> *)&wdesc->expect);
            }
		}
		/* we have persist all the target words to the correct state */
		mdesc->status = ST_FREE;
		persist(&mdesc->status, sizeof(mdesc->status));
	}
}

/* 回收内存 */
void pmwcas_word_recycle(mdesc_pool_t pool, rel_ptr<rel_ptr<uint64_t>> ptr_leak)
{
	pool->mem_.release(ptr_leak);
	//pmemobj_free(&ptr_leak.oid());
#ifdef BZ_DEBUG
	flag.lock();
	mem_fs << "RECYCLE " << std::setfill('0') << std::setw(16) << std::hex << ptr_leak.rel() << "\n";
	flag.unlock();
#endif // BZ_DEBUG

}

/*
* add a word entry to PMwCAS desc
* expect and new_val must be common variables whose higher 12 bits are 0
*/
bool pmwcas_add(mdesc_t mdesc, rel_ptr<uint64_t> addr, uint64_t expect, uint64_t new_val, off_t recycle) 
{
	/* check if PMwCAS is full */
	if (mdesc->count == WORD_DESCRIPTOR_SIZE)
	{
		assert(0);
		return false;
	}
	/* 
	* check if the target address exists
	* otherwise, find the insert point 
	*/
	for (off_t i = 0; i < mdesc->count; ++i)
	{
		wdesc_t wdesc = mdesc->wdescs + i;
		if (wdesc->addr == addr)
		{
			assert(0);
			return false;
		}
	}
	wdesc_t wdesc = mdesc->wdescs + mdesc->count;
		
	wdesc->addr = addr;
	wdesc->expect = expect;
	wdesc->new_val = new_val;
	wdesc->mdesc = mdesc;
	wdesc->recycle_func = !recycle ? mdesc->callback : recycle;
	persist(wdesc.abs(), sizeof(*wdesc));

	++mdesc->count;
	persist(&mdesc->count, sizeof(uint64_t));
	return true;
}

inline bool is_RDCSS(uint64_t val)
{
	return (val & RDCSS_BIT) != 0ULL;
}

inline bool is_MwCAS(uint64_t val)
{
	return (val & MwCAS_BIT) != 0ULL;
}

inline bool is_dirty(uint64_t val)
{
	return (val & DIRTY_BIT) != 0ULL;
}

inline void persist_clear(uint64_t *addr, uint64_t val) {
  persist(addr, sizeof(uint64_t));
  __sync_bool_compare_and_swap(addr, val, val & ~DIRTY_BIT);
}

inline void complete_install(wdesc_t wdesc)
{
	uint64_t mdesc_ptr = wdesc->mdesc.rel() | MwCAS_BIT | DIRTY_BIT;
	uint64_t wdesc_ptr = wdesc.rel() | RDCSS_BIT;
	bool test = wdesc->mdesc->status == ST_UNDECIDED;
        __sync_bool_compare_and_swap(wdesc->addr.abs(), wdesc_ptr,
                                     test ? mdesc_ptr : wdesc->expect);
}

inline uint64_t install_mdesc(wdesc_t wdesc)
{
	uint64_t ptr = wdesc.rel() | RDCSS_BIT;
	uint64_t r;
	while (true)
	{
          auto r = __sync_val_compare_and_swap(wdesc->addr.abs(), ptr,
                                               wdesc->expect);
          if (is_RDCSS(r)) {
            complete_install(
                wdesc_t((uintptr_t)wdesc->addr.abs() & (uintptr_t)ADDR_MASK));
            continue;
          }
                if (r == wdesc->expect)
		{
			complete_install(wdesc);
		}
		break;
	}
	return r;
}

void sort_addr(off_t arr[], mdesc_t mdesc) {
	for (off_t i = 0; i < mdesc->count; ++i) {
		arr[i] = i;
	}
	for (int i = 0; i < mdesc->count; ++i) {
		int cur_min_pos = i;
		rel_ptr<uint64_t> cur_min(mdesc->wdescs[arr[i]].addr);
		for (int j = i + 1; j < mdesc->count; ++j)
			if (mdesc->wdescs[arr[j]].addr < cur_min) {
				cur_min = mdesc->wdescs[arr[j]].addr;
				cur_min_pos = j;
			}
		if (cur_min_pos != i) {
			off_t tmp = arr[cur_min_pos];
			arr[cur_min_pos] = arr[i];
			arr[i] = tmp;
		}
	}
}

bool pmwcas_commit(mdesc_t mdesc)
{
	uint64_t status = ST_SUCCESS;
	off_t index[WORD_DESCRIPTOR_SIZE];
	sort_addr(index, mdesc);
	for (off_t i = 0; status == ST_SUCCESS && i < mdesc->count; ++i) {
		wdesc_t wdesc = mdesc->wdescs + index[i];
		if (wdesc->recycle_func == NOCAS_RELEASE_ADDR_ON_SUCCESS
			|| wdesc->recycle_func == NOCAS_EXECUTE_ON_FAILED
			|| wdesc->recycle_func == NOCAS_RELEASE_NEW_ON_FAILED)
			continue;
		uint64_t r;
		while (true) {
			/* try to install a pointer to mdesc for tha target word */
			r = install_mdesc(wdesc);
			uint64_t tmp = wdesc->expect;
			if (r == wdesc->expect || (r & ADDR_MASK) == mdesc.rel()) {
				/* successful CAS install or has been installed by another thread */
				break;
			}
			if (is_MwCAS(r)) {
				/* read a multi word decriptor help it finish */
				if (is_dirty(r)) {
					/* make sure what we read is persistent */
					persist_clear(wdesc->addr.abs(), r);
				}
				pmwcas_commit(mdesc_t(r & ADDR_MASK));
				/* retry install */
				continue;
			}
			/* otherwise, CAS failed, so the whole PMwCAS fails */
			status = ST_FAILED;
			break;
		}
	}
	uint64_t mdesc_ptr = mdesc.rel() | DIRTY_BIT | MwCAS_BIT;
	
	/*
	* make sure that every target word is installed
	*/
	if (status == ST_SUCCESS) {
		for (off_t i = 0; i < mdesc->count; ++i) {
			wdesc_t wdesc = mdesc->wdescs + index[i];
			if (wdesc->recycle_func == NOCAS_RELEASE_ADDR_ON_SUCCESS
				|| wdesc->recycle_func == NOCAS_EXECUTE_ON_FAILED
				|| wdesc->recycle_func == NOCAS_RELEASE_NEW_ON_FAILED)
				continue;
			persist_clear(wdesc->addr.abs(), mdesc_ptr);
		}
	}

	/* finalize MwCAS status */
        __sync_bool_compare_and_swap(&mdesc->status, ST_UNDECIDED,
                                     status | DIRTY_BIT);
        persist_clear(&mdesc->status, mdesc->status);

	/* install the final value for each word */
	for (off_t i = 0; i < mdesc->count; ++i) {
		wdesc_t wdesc = mdesc->wdescs + index[i];
		if (wdesc->recycle_func == NOCAS_RELEASE_ADDR_ON_SUCCESS
			|| wdesc->recycle_func == NOCAS_EXECUTE_ON_FAILED
			|| wdesc->recycle_func == NOCAS_RELEASE_NEW_ON_FAILED)
			continue;
		uint64_t val = 
			(mdesc->status == ST_SUCCESS ? wdesc->new_val : wdesc->expect) | DIRTY_BIT;
                auto r = __sync_val_compare_and_swap(wdesc->addr.abs(),
                                                     mdesc_ptr, val);

                /* if the dirty bit has been unset */
                if (r == (mdesc_ptr & ~DIRTY_BIT)) {
                  __sync_bool_compare_and_swap(wdesc->addr.abs(),
                                               mdesc_ptr & ~DIRTY_BIT, val);
                }
                persist_clear(wdesc->addr.abs(), val);
	}
	return mdesc->status == ST_SUCCESS;
}

uint64_t pmwcas_read(uint64_t * addr)
{
	uint64_t r;
	while (true)
	{
		r = *addr;
		if (is_RDCSS(r))
		{
			complete_install(wdesc_t(r & ADDR_MASK));
			continue;
		}
		if (is_dirty(r))
		{
			persist_clear(addr, r);
			r &= ~DIRTY_BIT;
		}
		if (is_MwCAS(r))
		{
			pmwcas_commit(mdesc_t(r & ADDR_MASK));
			continue;
		}
		break;
	}
	assert(!(r & MwCAS_BIT || r & DIRTY_BIT || r & RDCSS_BIT));
	return r;
}

/*
* recovery process(in a single thread manner):
* 1) roll back failed or in-flight PMwCAS
* 2) finish success PMwCAS
* 3) reclaim PMwCAS descriptor
*/
void pmwcas_recovery(mdesc_pool_t pool)
{
	for (off_t i = 0; i < DESCRIPTOR_POOL_SIZE; ++i)
	{
		mdesc_t mdesc = pool->mdescs + i;
		/*
		* clear dirty bit in persistent memory,
		* this is because crash happens before CPU flushes the newest cache line
		* back to persistent memory
		*/
		if (is_dirty(mdesc->status))
		{
			mdesc->status &= ~DIRTY_BIT;
			persist(&mdesc->status, sizeof(mdesc->status));
		}
		if (mdesc->status == ST_FREE)
		{
			continue;
		}
		bool done = mdesc->status == ST_SUCCESS;
		uint64_t mdesc_ptr = mdesc.rel() | MwCAS_BIT | DIRTY_BIT;

		/*
		* each target word could remain:
		* 1) old value
		* 2) ptr to word descriptor
		* 3) ptr to multi-word descriptor
		* 4) new val
		*/
		for (off_t j = 0; j < mdesc->count; ++j)
		{
			wdesc_t wdesc = mdesc->wdescs + j;
			uint64_t r, val = done ? wdesc->new_val : wdesc->expect;

			/* case (3) when dirty bit set */
                        r = __sync_val_compare_and_swap(wdesc->addr.abs(),
                                                        mdesc_ptr, val);
                        /* case (3) when the dirty bit unset */
                        if (r == (mdesc_ptr & ~DIRTY_BIT)) {
                          __sync_bool_compare_and_swap(
                              wdesc->addr.abs(), mdesc_ptr & ~DIRTY_BIT, val);
                        }
                        /* case (2) */
			if (r & RDCSS_BIT)
			{
                          __sync_val_compare_and_swap(wdesc->addr.abs(),
                                                      wdesc.rel() | RDCSS_BIT,
                                                      wdesc->expect);
                        }
			/*
			* if all CASs above fail,
			* target word remain in case (1) or case (4)
			* no need to modify
			*/
			persist(wdesc->addr.abs(), sizeof(*wdesc->addr));

                        /* 根据回收规则回收 */
                        if (wdesc->recycle_func == NOCAS_RELEASE_ADDR_ON_SUCCESS 
				&& done && !wdesc->addr.is_null()) {
				pmwcas_word_recycle(pool, &wdesc->addr);
			}
			else if (wdesc->recycle_func == NOCAS_EXECUTE_ON_FAILED
				&& !done) {
                          __sync_bool_compare_and_swap(
                              wdesc->addr.abs(), wdesc->expect, wdesc->new_val);
                        }
			else if (wdesc->recycle_func == NOCAS_RELEASE_NEW_ON_FAILED
				&& !done && wdesc->new_val) {
				pmwcas_word_recycle(pool, (rel_ptr<uint64_t>*)&wdesc->new_val);
			}
			else if ((wdesc->recycle_func == RELEASE_NEW_ON_FAILED
				|| wdesc->recycle_func == RELEASE_SWAP_PTR)
				&& !done && wdesc->new_val) {
				pmwcas_word_recycle(pool, (rel_ptr<uint64_t>*)&wdesc->new_val);
			}
			else if ((wdesc->recycle_func == RELEASE_EXP_ON_SUCCESS
				|| wdesc->recycle_func == RELEASE_SWAP_PTR) 
				&& done && wdesc->expect) {
                          /* 成功时回收expect */
                          pmwcas_word_recycle(
                              pool, (rel_ptr<uint64_t> *)&wdesc->expect);
			}
		}
		/* we have persist all the target words to the correct state */
		mdesc->status = ST_FREE;
		persist(&mdesc->status, sizeof(mdesc->status));
	}
}
