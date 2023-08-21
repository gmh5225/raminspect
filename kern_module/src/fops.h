// Needed for the ioctl-based interface
#include <linux/ioctl.h>
#include <asm/ioctl.h>
#include <asm/bug.h>

// Get mm_struct of process
#define get_process_mm(process_id) ({\
    struct task_struct* target_process = pid_task(find_vpid(process_id), PIDTYPE_PID);\
    \
    if(target_process == NULL) {\
        pr_alert("Error: The process you are trying to monitor is not currently running!\n");\
        return -EINVAL;\
    }\
    \
    target_process -> mm;\
})

// Define ioctl data structures

typedef struct {
    uint64_t caller_mem_len;
    uint64_t procmem_ptr;
    char* caller_mem;
    char direction;
} DataReadOrWrite;

typedef struct {
    DataReadOrWrite* reads_and_writes;
    uint64_t reads_and_writes_len;
    int target_process_id;
} InspectorRequest;

typedef struct {
    uint64_t max_search_results;
    uint64_t results_found;
    uint64_t* results;

    char* contiguous_page_data;
    uint64_t search_term_len;
    char* search_term;
    int process_id;
} SearchOperation;

#include "search.h"
// Define ioctl command numbers

#define RS_MAGIC 123
#define CONDUCT_SEARCH _IOWR(RS_MAGIC, 1, SearchOperation)
#define SEND_INSPECTOR_REQUEST _IOW(RS_MAGIC, 0, InspectorRequest)

const char PROC_ACCESS_READ = 0;
const char PROC_ACCESS_WRITE = 1;
// Attempts to read from or write to a process address.
int access_proc_addr(struct mm_struct* target_mm, DataReadOrWrite read_or_write) {
    char* caller_mem = read_or_write.caller_mem;
    uint64_t proc_addr = read_or_write.procmem_ptr;
    uint64_t caller_mem_len = read_or_write.caller_mem_len;

    struct page* page;
    pgd_t* pgd_entry = pgd_offset(target_mm, proc_addr);
    if(pgd_none(*pgd_entry) || pgd_bad(*pgd_entry)) return -EFAULT;

    p4d_t* p4d_entry = p4d_offset(pgd_entry, proc_addr);
    if(p4d_none(*p4d_entry) || p4d_bad(*p4d_entry)) return -EFAULT;

    pud_t* pud_entry = pud_offset(p4d_entry, proc_addr);
    if(pud_none(*pud_entry) || pud_bad(*pud_entry)) return -EFAULT;

    if(pud_trans_huge(*pud_entry)) {
        page = pud_page(*pud_entry);
    } else {
        pmd_t* pmd_entry = pmd_offset(pud_entry, proc_addr);
        if(pmd_none(*pmd_entry) || pmd_bad(*pmd_entry)) return -EFAULT;

        if(pmd_trans_huge(*pmd_entry)) {
            page = pmd_page(*pmd_entry);
        } else {
            pte_t* pte_entry = pte_offset_map(pmd_entry, proc_addr);
            page = pte_page(*pte_entry);
            pte_unmap(pte_entry);
        }
    }

    uint64_t page_phys_start = page_to_pfn(page) * PAGE_SIZE + (proc_addr % PAGE_SIZE);
    char* page_start_ptr = phys_to_virt(page_phys_start);

    switch(read_or_write.direction) {
        case PROC_ACCESS_WRITE:
            memcpy(page_start_ptr, caller_mem, caller_mem_len);
            break;

        case PROC_ACCESS_READ:
            memcpy(caller_mem, page_start_ptr, caller_mem_len);
            break;

        default:
            pr_alert("raminspect entered unreachable code!");
            BUG();

            break;
    }

    return 0;
}

static long raminspect_ioctl(struct file *fptr, unsigned int cmd, unsigned long arg) {
    // Checks the result of a fallible function and logs the line number where the
    // error occurred if it fails and returns the corresponding error code.

    #define handle_errors(call) {\
        int res = call;\
        if(res != 0) {\
            pr_alert("Error occurred on line #%d in file fops.h! This is most likely due to an invalid memory access.", __LINE__);\
            return res;\
        }\
    }

    // Like 'copy_from_user' but it returns -EFAULT on error (eh stands for error handling here)
    #define copy_from_user_eh(...) handle_errors(copy_from_user(__VA_ARGS__))
    #define copy_to_user_eh(...) handle_errors(copy_to_user(__VA_ARGS__))

    // Like 'access_proc_addr' but it returns -EFAULT on error
    #define access_proc_addr_eh(...) handle_errors(access_proc_addr(__VA_ARGS__))

    // Copies argument data into kernel memory
    #define get_argument(data_type) data_type operation_data; copy_from_user_eh(&operation_data, data_ptr, sizeof(operation_data))

    // Get data pointer from argument
    char __user *data_ptr = (char __user *)(arg);

    switch(cmd) {
        case SEND_INSPECTOR_REQUEST: {
            get_argument(InspectorRequest);
            struct mm_struct* target_mm = get_process_mm(operation_data.target_process_id);
            uint64_t reads_and_writes_len = operation_data.reads_and_writes_len * sizeof(DataReadOrWrite);

            if(target_mm == NULL) {
                pr_alert("Error: The target process isn't currently running!\n");
                return -EINVAL;
            }

            // Lock the process memory map for the duration that we're accessing it
            mmap_write_lock(target_mm);

            // Copy data read and writes from user memory
            DataReadOrWrite* reads_and_writes = kmalloc(reads_and_writes_len, GFP_KERNEL);
            copy_from_user_eh(reads_and_writes, (char* __user)(operation_data.reads_and_writes), reads_and_writes_len);

            // Make sure that each read and write has a valid direction
            for(int i = 0; i < operation_data.reads_and_writes_len; i++) {
                if(reads_and_writes[i].direction > 1) {
                    pr_alert("Got invalid read or write request direction at index #%d!\n", i);
                    mmap_write_unlock(target_mm);
                    return -EINVAL;
                }
            }
            
            #ifdef RS_CONFIG_DEBUGGING_ENABLED
                pr_info("Got inspector request with info:\n");
                pr_info("Target Process ID: %d\n", operation_data.target_process_id);
                pr_info("Number of R/W requests: %lld\n", operation_data.reads_and_writes_len);
                pr_info("R/W requests buffer pointer: 0x%llX\n", (uint64_t)(operation_data.reads_and_writes));

                for(int i = 0; i < operation_data.reads_and_writes_len; i++) {
                    pr_info(
                        "Got %s request at index #%d with info:\n", 
                        reads_and_writes[i].direction == READ ? "read" : "write",
                        i + 1
                    );

                    pr_info("Caller memory length: %lld\n", reads_and_writes[i].caller_mem_len);
                    pr_info("Caller memory pointer: 0x%llX\n", (uint64_t)(reads_and_writes[i].caller_mem));
                    pr_info("Process memory pointer: 0x%llX\n", reads_and_writes[i].procmem_ptr);
                }
            #endif

            // Apply each access according to its information
            for(int i = 0; i < operation_data.reads_and_writes_len; i++) {
                DataReadOrWrite read_or_write_info = reads_and_writes[i];
                // Make sure the access isn't bigger than a full page
                uint64_t caller_mem_len = read_or_write_info.caller_mem_len;

                if(caller_mem_len > PAGE_SIZE) {
                    pr_alert("Error: The size of a read or write request can be no larger than the size of a regular page.\n");
                    pr_alert("Note: Max is %ld, got %lld\n", PAGE_SIZE, caller_mem_len);
                    mmap_write_unlock(target_mm);\
                    return -EINVAL;
                }

                uint64_t proc_addr = read_or_write_info.procmem_ptr;
                char* __user caller_mem = read_or_write_info.caller_mem;
                char* byte_buffer = kmalloc(caller_mem_len, GFP_KERNEL);

                if(read_or_write_info.direction == PROC_ACCESS_WRITE) {
                    // Copy the user memory into the allocated buffer
                    copy_from_user_eh(byte_buffer, caller_mem, caller_mem_len);
                }
                
                // Handle data accesses that span across page boundaries
                uint64_t remaining_page_space = (PAGE_SIZE - (proc_addr % PAGE_SIZE));

                DataReadOrWrite current_access = {
                    procmem_ptr: proc_addr,
                    caller_mem: byte_buffer,
                    caller_mem_len: caller_mem_len,
                    direction: read_or_write_info.direction,
                };
                
                if(remaining_page_space < caller_mem_len) {
                    // Split the access into two to handle both sides of the page boundary
                    current_access.caller_mem_len = remaining_page_space;
                    access_proc_addr_eh(target_mm, current_access);

                    current_access.caller_mem += remaining_page_space;
                    current_access.procmem_ptr += remaining_page_space;
                    current_access.caller_mem_len = caller_mem_len - remaining_page_space;
                    access_proc_addr_eh(target_mm, current_access);
                } else {
                    // Perform one access all at once since it fits in one page
                    access_proc_addr_eh(target_mm, current_access);
                }

                if(read_or_write_info.direction == PROC_ACCESS_READ) {
                    // Copy the allocated buffer to user memory
                    copy_to_user_eh(caller_mem, byte_buffer, caller_mem_len);
                }

                kfree(byte_buffer);
            }

            mmap_write_unlock(target_mm);
            kfree(reads_and_writes);
            break;
        }
    
        case CONDUCT_SEARCH:
            get_argument(SearchOperation);
            operation_data.results_found = 0;
            operation_data.contiguous_page_data = NULL;

            #ifdef RS_CONFIG_DEBUGGING_ENABLED
                pr_info("Got search operation with info:\n");
                pr_info("Max search results: %lld\n", operation_data.max_search_results);
                pr_info("Search results pointer: 0x%llX\n", (uint64_t)(operation_data.results));
                pr_info("Search term length: %lld\n", operation_data.search_term_len);
                pr_info("Search term pointer: 0x%llX\n", (uint64_t)(operation_data.search_term));
                pr_info("Target Process ID: %d\n", operation_data.process_id);
            #endif

            if(operation_data.search_term_len == 0 || operation_data.search_term_len >= PAGE_SIZE) {
                pr_alert("Error: The search term length can't be zero and it can't be greater than or equal to the minimum platform page size.\n");
                return -EINVAL;
            }

            // Copy the search term into kernel memory
            char* search_term = kmalloc(operation_data.search_term_len, GFP_KERNEL);
            copy_from_user_eh(search_term, (char* __user)(operation_data.search_term), operation_data.search_term_len);

            // Allocate the necessary resources in kernel memory to store the search results.
            uint64_t search_buffer_size = operation_data.max_search_results * sizeof(uint64_t);
            uint64_t* search_results = kmalloc(search_buffer_size, GFP_KERNEL);

            SearchOperation search_operation = {
                max_search_results: operation_data.max_search_results,
                search_term_len: operation_data.search_term_len,
                process_id: operation_data.process_id,
                search_term: search_term,
                results: search_results,
                results_found: 0,
            };

            // Conduct the search.
            int maybe_error = conduct_search(&search_operation);

            if(maybe_error != 0) {
                return maybe_error;
            }

            // Store the search results in user memory
            copy_to_user_eh((char __user *)(operation_data.results), search_results, search_buffer_size);

            // Store the number of results found in user memory
            operation_data.results_found = search_operation.results_found;
            copy_to_user_eh(data_ptr, &operation_data, sizeof(SearchOperation));
            
            // Free allocated resources
            kfree(search_results);
            kfree(search_term);
            break;

        default:
            return -EINVAL;
    }

    return 0;
}

// There are no restrictions on multiple programs doing multiple searches
// at once, so we don't need to lock / release anything in the open and
// close handlers.

int no_op_open(struct inode* _file_info, struct file* _file) {
    return 0;
}

int no_op_close(struct inode* _file_info, struct file* _file) {
    return 0;
}

ssize_t no_op_read(struct file *fptr, char __user *buffer, size_t blen, loff_t *offs) {
    return 0;
}

ssize_t no_op_write(struct file *fptr, const char __user *buffer, size_t blen, loff_t *offs) {
    return 0;
}

static struct file_operations raminspect_fops = {
    .open = no_op_open,
    .read = no_op_read,
    .write = no_op_write,
    .release = no_op_close,
    .unlocked_ioctl = raminspect_ioctl,
};