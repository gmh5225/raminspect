// Needed for page table walking
#include <asm/pgtable_types.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <asm/io.h>

// The purpose of 'contiguous_page_data' is to is to handle search results 
// that span page boundaries by storing a contiguous buffer of the end of 
// the last page and the start of the current page, and then searching for 
// results within that combined buffer.
//
// If we skip over a page because it's not present or invalid, then this
// technique will not work anymore and we need to reset the buffer, which
// is what this function is for.

void reset_cpdata(char** contiguous_page_data) {
    kfree(*contiguous_page_data);
    *contiguous_page_data = NULL;
}

void check_for_search_result(volatile char* current_offset, uint64_t virt_offset, SearchOperation* operation) {
    uint64_t search_term_len = operation -> search_term_len;
    char* search_term = operation -> search_term;

    // Note: A 'memcmp' call would be possible here but the last time I benchmarked 
    // it on my machine this was faster than using memcmp, possibly because the 
    // search terms tend to be small and doing a whole memcmp call for ten byte 
    // pieces of data thousands of times per page is kind of overkill / not very 
    // efficient.

    bool found_at_index = true;
    for(int j = 0; j < search_term_len; j++) {
        if(current_offset[j] != search_term[j]) {
            found_at_index = false;
            break;
        }
    }

    if(found_at_index) {
        uint64_t results_found = operation -> results_found;
        if(results_found < operation -> max_search_results) {
            (operation -> results)[results_found] = virt_offset;
            operation -> results_found += 1;
        }
        
        // Notify the user we found a search result
        pr_info("Found search result at process virtual address: 0x%llX\n", virt_offset);
    }
}

// I would like to reduce the amount of parameters here but to ensure thread safety I can't be using any globals to make this cleaner.
void search_page(char** contiguous_page_data, uint64_t page_pfn, uint64_t size_of_page, uint64_t virt_start, SearchOperation* operation) {
    // Convert the physical address of a page to a virtual address so we can access it.
    volatile char* page_start_ptr = phys_to_virt(page_pfn * PAGE_SIZE);
    uint64_t search_term_len = operation -> search_term_len;

    // Search for results contained entirely within this page.
    for(int i = 0; i < size_of_page - search_term_len; i++) {
        check_for_search_result(page_start_ptr + i, virt_start + i, operation);
    }

    // To better understand how the contiguous page data buffer works, consider the 
    // following situation (-- delineates a page boundary):
    //
    // AAAA -- AAAA
    //
    // Say we are searching through every page for the search term AAAA. If we didn't
    // combine the data from the last page with the data at the start of the current page,
    // we would not find the search results here that cross the page boundary.
    //
    // The manner in which we create this combined buffer of data that we search through is
    // important. We don't want it to look like this, combining search_term_len bytes from
    // the end of the last page and the start of the current page, since if it did we would 
    // find duplicate search results:
    // 
    // AAAA -- AAAA 
    // ^^^^    ^^^^
    //
    // We would've already found the search results underlined by searching through the raw
    // page data. A better alternative would look like this, combining search_term_len - 1
    // bytes from the end of the last page and the start of the current page, making the 
    // length of the buffer (search_term_len - 1) * 2:
    //
    // AAA -- AAA
    //
    // With this method we will not miss any search results that cross page boundaries,
    // while simultaneously avoiding the creation of duplicate search results.

    // If the contiguous page data buffer was reset due to a skipped page then we will 
    // reallocate and reinitialize it to prepare it for the next page.
    uint64_t buf_len = (search_term_len - 1) * 2;

    if(*contiguous_page_data == NULL) {
        // Allocate the necessary memory for the buffer
        *contiguous_page_data = kmalloc(buf_len, GFP_KERNEL);

        // Store the end of this page in the first half of the cpdata buffer
        memcpy(*contiguous_page_data, page_start_ptr + size_of_page - search_term_len + 1, search_term_len - 1);
        return;
    }

    // Store the start of this page in the second half of the cpdata buffer
    memcpy((*contiguous_page_data) + search_term_len - 1, page_start_ptr, search_term_len - 1);

    // Search through the combined buffer
    for(int i = 0; i < (buf_len + 1 - search_term_len); i++) {
        check_for_search_result((*contiguous_page_data) + i, virt_start - search_term_len + 1 + i, operation);
    }

    // Store the end of this page in the first half of the cpdata buffer
    memcpy(*contiguous_page_data, page_start_ptr + size_of_page - search_term_len + 1, search_term_len - 1);
}

// The amount of entries in the PGD and other tables. On x86-64 this is 512.
const uint64_t ENTRY_LIST_SIZE = 512;

// Sizes in memory of each page table level
#define pgd_mem_size (ENTRY_LIST_SIZE * ENTRY_LIST_SIZE * ENTRY_LIST_SIZE * PAGE_SIZE)
#define pud_mem_size (ENTRY_LIST_SIZE * ENTRY_LIST_SIZE * PAGE_SIZE)
#define pmd_mem_size (ENTRY_LIST_SIZE * PAGE_SIZE)

// This walks through a processes' PGD entry and searches for the given search term
// in the virtual memory mapped within it.

void walk_pgd_entry(pgd_t* pgd_entry, struct mm_struct* mm, uint64_t addr, char** contiguous_page_data, SearchOperation* operation) {
    // We assume five-level paging is disabled. We also assume that none of
    // the checked pages are swapped off to disk, so this module probably
    // shouldn't be loaded in a resource-constrained environment where 
    // Linux may choose to do this.

    p4d_t* p4d_entry = p4d_offset(pgd_entry, addr);
    if(p4d_none(*p4d_entry) || p4d_bad(*p4d_entry)) {
        reset_cpdata(contiguous_page_data);
        return;
    }

    // Lock mmap so the page tables don't change while we're in the middle of reading them
    mmap_read_lock(mm);

    // Makes sure a page entry is present and not marked as bad before continuing,
    // resetting cpdata and moving on to the next entry if not.

    #define assert_entry_valid(entry_prefix) if((entry_prefix ## _none)(*(entry_prefix ## _entry)) || (entry_prefix ## _bad)(*(entry_prefix ## _entry))) {\
        reset_cpdata(contiguous_page_data);\
        addr += entry_prefix ## _mem_size;\
        continue;\
    }

    // Handles huge pages for a PUD or PMD entry.
    //
    // Note: For now, this doesn't work for some reason. PRs to fix it are welcome, but in 
    // the meantime disable transparent hugepages using the instructions on the GitHub page
    // while using this module.

    #define handle_potential_hugepage(entry_prefix) {\
        entry_prefix##_t* entry = entry_prefix ## _entry;\
        \
        if((entry_prefix ## _trans_huge)(*entry)) {\
            spinlock_t* lock = (entry_prefix ## _lock)(mm, entry);\
            \
            search_page(\
                contiguous_page_data,\
                (entry_prefix ## _pfn)(*entry),\
                entry_prefix ## _mem_size,\
                addr,\
                operation\
            );\
            \
            addr += entry_prefix ## _mem_size;\
            spin_unlock(lock);\
            continue;\
        }\
    }

    for(int pud_ind = 0; pud_ind < ENTRY_LIST_SIZE; pud_ind++) {
        pud_t* pud_entry = pud_offset(p4d_entry, addr);
        assert_entry_valid(pud);
  
        handle_potential_hugepage(pud);
        for(int pmd_ind = 0; pmd_ind < ENTRY_LIST_SIZE; pmd_ind++) {
            pmd_t* pmd_entry = pmd_offset(pud_entry, addr);
            assert_entry_valid(pmd);
            
            handle_potential_hugepage(pmd);
            for(int pte_ind = 0; pte_ind < ENTRY_LIST_SIZE; pte_ind++) {
                pte_t* pte_entry = pte_offset_map(pmd_entry, addr);

                if(pte_none(*pte_entry)) {
                    reset_cpdata(contiguous_page_data);
                } else {
                    search_page(contiguous_page_data, pte_pfn(*pte_entry), PAGE_SIZE, addr, operation);
                }

                pte_unmap(pte_entry);
                addr += PAGE_SIZE;
            }
        }
    }

    // Unlock the process page tables now that we're done
    mmap_read_unlock(mm);
}

int conduct_search(SearchOperation* operation) {
    uint64_t addr = 0;
    char* contiguous_page_data = NULL;
    struct mm_struct* process_mm = get_process_mm(operation -> process_id);

    for(int i = 0; i < ENTRY_LIST_SIZE; i++) {
        // Make sure the address is user-accessible
        const uint64_t USER_MEMORY_END = 0x0000800000000000;

        if(addr >= USER_MEMORY_END) {
            break;
        }

        // Get the PGD entry representing the current address offset
        pgd_t* process_pgd_entry = pgd_offset(process_mm, addr);

        // Skip any non-existent entries
        if(pgd_none(*process_pgd_entry) || pgd_bad(*process_pgd_entry)) {
            reset_cpdata(&contiguous_page_data);
            addr += pgd_mem_size;
            continue;
        }

        // Walk through the current PGD entry now that we've established that it is
        // accessible by the user and therefore possibly used for user-allocated
        // memory that we would want to search for.

        walk_pgd_entry(process_pgd_entry, process_mm, addr, &contiguous_page_data, operation);
        addr += pgd_mem_size;
    }

    if(contiguous_page_data != NULL) {
        kfree(contiguous_page_data);
    }

    pr_info("Done searching! Number of search results: %lld\n", operation -> results_found);
    return 0;
}