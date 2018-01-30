/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef WTF_PartitionAlloc_h
#define WTF_PartitionAlloc_h

// DESCRIPTION
// partitionAlloc() and partitionFree() are approximately analagous
// to malloc() and free().
// The main difference is that a PartitionRoot object must be supplied to
// partitionAlloc(), representing a specific "heap partition" that will
// be used to satisfy the allocation. Different partitions are guaranteed to
// exist in separate address spaces, including being separate from the main
// system heap. If the contained objects are all freed, physical memory is
// returned to the system but the address space remains reserved.
//
// Allocations and frees against a single partition must be single threaded.
// Allocations must not exceed a max size, typically 4088 bytes at this time.
// Allocation sizes must be aligned to the system pointer size.
// The separate APIs partitionAllocGeneric and partitionFreeGeneric are
// provided, and they do not have the above three restrictions. In return, you
// take a small performance hit and are also obliged to keep track of
// allocation sizes, and pass them to partitionFreeGeneric.
//
// This allocator is designed to be extremely fast, thanks to the following
// properties and design:
// - Just a single (reasonably predicatable) branch in the hot / fast path for
// both allocating and (significantly) freeing.
// - A minimal number of operations in the hot / fast path, with the slow paths
// in separate functions, leading to the possibility of inlining.
// - Each partition page (which is usually multiple physical pages) has a header
// structure which allows fast mapping of free() address to an underlying
// bucket.
// - Supports a lock-free API for fast performance in single-threaded cases.
// - The freelist for a given bucket is split across a number of partition
// pages, enabling various simple tricks to try and minimize fragmentation.
// - Fine-grained bucket sizes leading to less waste and better packing.
//
// The following security properties are provided at this time:
// - Linear overflows cannot corrupt into the partition.
// - Linear overflows cannot corrupt out of the partition.
// - Freed pages will only be re-used within the partition.
// - Freed pages will only hold same-sized objects when re-used.
// - Dereference of freelist pointer will fault.
//
// The following security properties could be investigated in the future:
// - No double-free detection (tcmalloc has some but it may be only a detection
// and not a defense).
// - No randomness in freelist pointers.
// - Per-object bucketing (instead of per-size) is mostly available at the API,
// but not used yet.
// - No randomness of freelist entries or bucket position.
// - No specific protection against corruption of page header metadata.

#include "wtf/Assertions.h"
#include "wtf/CPU.h"
#include "wtf/FastMalloc.h"
#include "wtf/SpinLock.h"

#include <stdlib.h>

namespace WTF {

#if CPU(MIPS)
    // Allocation granularity of sizeof(double) bytes.
    typedef double align_t;
    #define WTF_ALIGN(n)  __attribute__((__aligned__(n)))
#else
    // Allocation granularity of sizeof(void*) bytes.
    typedef void * align_t;
    #define WTF_ALIGN(n)
#endif

static const size_t kAllocationGranularity = sizeof(align_t);
static const size_t kAllocationGranularityMask = kAllocationGranularity - 1;
static const size_t kBucketShift = (kAllocationGranularity == 8) ? 3 : 2;
// Supports allocations up to 4088 (one bucket is used for metadata).
static const size_t kMaxAllocationOrder = 12;
static const size_t kMaxAllocation = (1 << kMaxAllocationOrder) - kAllocationGranularity;
static const size_t kNumBuckets = (1 << kMaxAllocationOrder) / (1 << kBucketShift);
// Underlying partition storage pages are a power-of-two size. It is typical
// for a partition page to be based on multiple system pages. We rarely deal
// with system pages. Most references to "page" refer to partition pages. We
// do also have the concept of "super pages" -- these are the underlying
// system allocations we make. Super pages can typically fit multiple
// partition pages inside them. See PageAllocator.h for more details on
// super pages.
static const size_t kPartitionPageSize = 1 << 14; // 16KB
static const size_t kPartitionPageOffsetMask = kPartitionPageSize - 1;
static const size_t kPartitionPageBaseMask = ~kPartitionPageOffsetMask;
// Special bucket id for free page metadata.
static const size_t kFreePageBucket = 0;

struct PartitionRoot;
struct PartitionBucket;

struct PartitionFreelistEntry {
    PartitionFreelistEntry* next;
};

struct PartitionPageHeader {
    int numAllocatedSlots; // Deliberately signed.
    PartitionBucket* bucket;
    PartitionFreelistEntry* freelistHead;
    PartitionPageHeader* next;
    PartitionPageHeader* prev;
} WTF_ALIGN(sizeof(align_t));

struct PartitionFreepagelistEntry {
    PartitionPageHeader* page;
    PartitionFreepagelistEntry* next;
} WTF_ALIGN(sizeof(align_t));

struct PartitionBucket {
    PartitionRoot* root;
    PartitionPageHeader* currPage;
    PartitionFreepagelistEntry* freePages;
    size_t numFullPages;
} WTF_ALIGN(sizeof(align_t));

struct PartitionRoot {
    int lock;
    PartitionPageHeader seedPage;
    PartitionBucket seedBucket;
    PartitionBucket buckets[kNumBuckets];
    char* nextSuperPage;
    char* nextPartitionPage;
    char* nextPartitionPageEnd;
    bool initialized;
};

WTF_EXPORT void partitionAllocInit(PartitionRoot*);
WTF_EXPORT bool partitionAllocShutdown(PartitionRoot*);

WTF_EXPORT NEVER_INLINE void* partitionAllocSlowPath(PartitionBucket*);
WTF_EXPORT NEVER_INLINE void partitionFreeSlowPath(PartitionPageHeader*);
WTF_EXPORT NEVER_INLINE void* partitionReallocGeneric(PartitionRoot*, void*, size_t, size_t);

ALWAYS_INLINE PartitionFreelistEntry* partitionFreelistMask(PartitionFreelistEntry* ptr)
{
    // For now, use a simple / fast mask that guarantees an invalid pointer in
    // case it gets used as a vtable pointer.
    // The one attack we're fully mitigating is where an object is freed and its
    // vtable used where the attacker doesn't get the chance to run allocations
    // between the free and use.
    // We're deliberately not trying to defend against OOB reads or writes.
    uintptr_t masked = ~reinterpret_cast<uintptr_t>(ptr);
    return reinterpret_cast<PartitionFreelistEntry*>(masked);
}

ALWAYS_INLINE size_t partitionBucketSize(const PartitionBucket* bucket)
{
    PartitionRoot* root = bucket->root;
    size_t index = bucket - &root->buckets[0];
    size_t size;
    if (UNLIKELY(index == kFreePageBucket))
        size = sizeof(PartitionFreepagelistEntry);
    else
        size = index << kBucketShift;
    return size;
}

ALWAYS_INLINE void* partitionBucketAlloc(PartitionBucket* bucket)
{
    PartitionPageHeader* page = bucket->currPage;
    PartitionFreelistEntry* ret = page->freelistHead;
    if (LIKELY(ret != 0)) {
        page->freelistHead = partitionFreelistMask(ret->next);
        page->numAllocatedSlots++;
        return ret;
    }
    return partitionAllocSlowPath(bucket);
}

ALWAYS_INLINE size_t partitionAllocRoundup(size_t size)
{
    return (size + kAllocationGranularityMask) & ~kAllocationGranularityMask;
}

ALWAYS_INLINE void* partitionAlloc(PartitionRoot* root, size_t size)
{
#if defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
    return malloc(size);
#else
#if CPU(MIPS)
    size = partitionAllocRoundup(size);
#endif
    size_t index = size >> kBucketShift;
    ASSERT(index < kNumBuckets);
    ASSERT(size == index << kBucketShift);
    PartitionBucket* bucket = &root->buckets[index];
    return partitionBucketAlloc(bucket);
#endif
}

ALWAYS_INLINE PartitionPageHeader* partitionPointerToPage(void* ptr)
{
    uintptr_t pointerAsUint = reinterpret_cast<uintptr_t>(ptr);
    // Checks that the pointer is after the page header. You can't free the
    // page header!
    ASSERT((pointerAsUint & kPartitionPageOffsetMask) >= sizeof(PartitionPageHeader));
    PartitionPageHeader* page = reinterpret_cast<PartitionPageHeader*>(pointerAsUint & kPartitionPageBaseMask);
    // Checks that the pointer is a multiple of bucket size.
    ASSERT(!(((pointerAsUint & kPartitionPageOffsetMask) - sizeof(PartitionPageHeader)) % partitionBucketSize(page->bucket)));
    return page;
}

ALWAYS_INLINE void partitionFreeWithPage(void* ptr, PartitionPageHeader* page)
{
    PartitionFreelistEntry* entry = static_cast<PartitionFreelistEntry*>(ptr);
    entry->next = partitionFreelistMask(page->freelistHead);
    page->freelistHead = entry;
    --page->numAllocatedSlots;
    if (UNLIKELY(page->numAllocatedSlots <= 0))
        partitionFreeSlowPath(page);
}

ALWAYS_INLINE void partitionFree(void* ptr)
{
#if defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
    free(ptr);
#else
    PartitionPageHeader* page = partitionPointerToPage(ptr);
    partitionFreeWithPage(ptr, page);
#endif
}

ALWAYS_INLINE void* partitionAllocGeneric(PartitionRoot* root, size_t size)
{
#if defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
    return malloc(size);
#else
    size = partitionAllocRoundup(size);
    if (LIKELY(size <= kMaxAllocation)) {
        spinLockLock(&root->lock);
        void* ret = partitionAlloc(root, size);
        spinLockUnlock(&root->lock);
        return ret;
    }
    return WTF::fastMalloc(size);
#endif
}

ALWAYS_INLINE void partitionFreeGeneric(void* ptr, size_t size)
{
#if defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
    free(ptr);
#else
    if (LIKELY(size <= kMaxAllocation)) {
        PartitionPageHeader* page = partitionPointerToPage(ptr);
        PartitionRoot* root = page->bucket->root;
        spinLockLock(&root->lock);
        partitionFreeWithPage(ptr, page);
        spinLockUnlock(&root->lock);
        return;
    }
    return WTF::fastFree(ptr);
#endif
}

} // namespace WTF

using WTF::PartitionRoot;
using WTF::partitionAllocInit;
using WTF::partitionAllocShutdown;
using WTF::partitionAlloc;
using WTF::partitionFree;
using WTF::partitionAllocGeneric;
using WTF::partitionFreeGeneric;
using WTF::partitionReallocGeneric;

#endif // WTF_PartitionAlloc_h
