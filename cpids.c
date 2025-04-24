#define _POSIX_C_SOURCE 200809L // For strdup, getline if needed later
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>     // For opendir, readdir, closedir
#include <ctype.h>      // For isdigit
#include <sys/types.h>  // For pid_t
#include <errno.h>      // For errno
#include <limits.h>     // For PATH_MAX (optional, can use fixed buffer)

// --- Configuration ---
#define HASH_TABLE_SIZE 4096 // Adjust based on expected number of processes
#define INITIAL_CHILD_CAPACITY 4
#define INITIAL_QUEUE_CAPACITY 16
#define INITIAL_DESCENDANTS_CAPACITY 16
#define MAX_PATH_LEN 256 // Max length for /proc/[pid]/status path
#define MAX_LINE_LEN 256 // Max line length in status file

// --- Data Structures ---

// Linked list node for children of a parent
typedef struct ChildNode {
    pid_t child_pid;
    struct ChildNode *next;
} ChildNode;

// Entry in the parent map hash table (stores PPID and list of children)
typedef struct ParentMapEntry {
    pid_t ppid;                // The key (Parent PID)
    ChildNode *children_head;  // Head of linked list of children PIDs
    struct ParentMapEntry *next; // For separate chaining in hash table
} ParentMapEntry;

// The Parent Map (Hash Table)
ParentMapEntry *parent_map[HASH_TABLE_SIZE];

// --- Hash Function ---
unsigned int hash_pid(pid_t pid) {
    // Simple modulo hash
    return (unsigned int)pid % HASH_TABLE_SIZE;
}

// --- Parent Map Functions ---

// Add a child PID to the list for a given PPID in the map
// Returns 0 on success, -1 on memory allocation error
int add_child_to_map(pid_t ppid, pid_t child_pid) {
    unsigned int index = hash_pid(ppid);
    ParentMapEntry *entry = parent_map[index];
    ParentMapEntry *prev = NULL;

    // Find existing entry for ppid or end of chain
    while (entry != NULL && entry->ppid != ppid) {
        prev = entry;
        entry = entry->next;
    }

    // If entry doesn't exist, create it
    if (entry == NULL) {
        entry = malloc(sizeof(ParentMapEntry));
        if (!entry) {
            perror("Failed to allocate ParentMapEntry");
            return -1;
        }
        entry->ppid = ppid;
        entry->children_head = NULL;
        entry->next = NULL;

        // Link it into the hash table chain
        if (prev == NULL) {
            parent_map[index] = entry;
        } else {
            prev->next = entry;
        }
    }

    // Create the new child node
    ChildNode *new_child = malloc(sizeof(ChildNode));
    if (!new_child) {
        perror("Failed to allocate ChildNode");
        // Note: We don't free the ParentMapEntry here, as it might have other children.
        // A more robust implementation might handle this better.
        return -1;
    }
    new_child->child_pid = child_pid;

    // Add to the beginning of the children list for this ppid
    new_child->next = entry->children_head;
    entry->children_head = new_child;

    return 0;
}

// Find the list of children for a given PPID
ChildNode *get_children(pid_t ppid) {
    unsigned int index = hash_pid(ppid);
    ParentMapEntry *entry = parent_map[index];

    while (entry != NULL) {
        if (entry->ppid == ppid) {
            return entry->children_head;
        }
        entry = entry->next;
    }
    return NULL; // No entry found for this ppid
}

// Free all memory allocated for the parent map
void free_parent_map() {
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        ParentMapEntry *entry = parent_map[i];
        while (entry != NULL) {
            ParentMapEntry *next_entry = entry->next;

            // Free the children list
            ChildNode *child = entry->children_head;
            while (child != NULL) {
                ChildNode *next_child = child->next;
                free(child);
                child = next_child;
            }

            // Free the entry itself
            free(entry);
            entry = next_entry;
        }
        parent_map[i] = NULL; // Clear the bucket pointer
    }
}

// --- /proc Parsing ---

// Build the parent_map by reading /proc
// Returns 0 on success, -1 on major error (e.g., cannot open /proc)
int build_parent_map_from_proc() {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Failed to open /proc");
        return -1;
    }

    struct dirent *entry;
    char path_buffer[MAX_PATH_LEN];
    char line_buffer[MAX_LINE_LEN];

    while ((entry = readdir(proc_dir)) != NULL) {
        // Check if directory name is a number (PID)
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
            pid_t current_pid = (pid_t)strtol(entry->d_name, NULL, 10);
            if (current_pid <= 0) continue; // Skip invalid PIDs like "0" or non-numeric names

            // Construct path to status file
            int required_len = snprintf(path_buffer, sizeof(path_buffer), "/proc/%s/status", entry->d_name);

            // Check for snprintf errors or truncation
            if (required_len < 0) {
                // An encoding error occurred (very rare)
                fprintf(stderr, "Warning: snprintf encoding error for %s\n", entry->d_name);
                continue; // Skip this entry
            }
            if ((size_t)required_len >= sizeof(path_buffer)) {
                // Path would be truncated!
                fprintf(stderr, "Warning: Path for PID %s is too long (required %d, buffer %zu), skipping.\n",
                        entry->d_name, required_len, sizeof(path_buffer));
                continue; // Skip this entry as the path is invalid/truncated
            }

            FILE *status_file = fopen(path_buffer, "r");
            if (!status_file) {
                // Process might have disappeared, permissions issue, etc. - often benign
                // fprintf(stderr, "Warning: Could not open %s: %s\n", path_buffer, strerror(errno));
                continue;
            }

            pid_t pid = -1;
            pid_t ppid = -1;

            // Read status file line by line
            while (fgets(line_buffer, sizeof(line_buffer), status_file)) {
                if (strncmp(line_buffer, "Pid:", 4) == 0) {
                    sscanf(line_buffer + 4, "%d", &pid);
                } else if (strncmp(line_buffer, "PPid:", 5) == 0) {
                    sscanf(line_buffer + 5, "%d", &ppid);
                }
                // Optimization: stop reading if both found
                if (pid != -1 && ppid != -1) {
                    break;
                }
            }
            fclose(status_file);

            // If we found valid PID and PPID, add to map
            if (pid > 0 && ppid >= 0) { // ppid can be 0 for init/systemd
                // Use the PID read from file, not the directory name, as they *should* match
                // but reading from the file is slightly more robust.
                if (add_child_to_map(ppid, pid) != 0) {
                    // Handle allocation error - maybe log and continue, or abort?
                    fprintf(stderr, "Error: Failed to add child %d for parent %d\n", pid, ppid);
                    // Continuing might lead to incomplete results
                }
            } else {
                // fprintf(stderr, "Warning: Could not parse PID/PPID from %s\n", path_buffer);
            }
        }
    }

    closedir(proc_dir);
    return 0;
}

// --- BFS Descendant Finding ---

// Simple Visited Set (using another hash table for demonstration)
typedef struct VisitedNode {
    pid_t pid;
    struct VisitedNode *next;
} VisitedNode;

VisitedNode *visited_set[HASH_TABLE_SIZE];

// Add PID to visited set. Returns 1 if added, 0 if already present, -1 on error.
int add_to_visited(pid_t pid) {
    unsigned int index = hash_pid(pid);
    VisitedNode *node = visited_set[index];
    while (node != NULL) {
        if (node->pid == pid) {
            return 0; // Already visited
        }
        node = node->next;
    }
    // Not found, add it
    VisitedNode *new_node = malloc(sizeof(VisitedNode));
    if (!new_node) {
        perror("Failed to allocate VisitedNode");
        return -1;
    }
    new_node->pid = pid;
    new_node->next = visited_set[index];
    visited_set[index] = new_node;
    return 1; // Added successfully
}

// Clear the visited set (free nodes)
void clear_visited_set() {
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        VisitedNode *node = visited_set[i];
        while (node != NULL) {
            VisitedNode *next_node = node->next;
            free(node);
            node = next_node;
        }
        visited_set[i] = NULL;
    }
}


// Dynamic Array based Queue for BFS
typedef struct PidQueue {
    pid_t *pids;
    size_t capacity;
    size_t count;
    size_t head; // Index of the front element
} PidQueue;

// Initialize Queue
int init_queue(PidQueue *q, size_t initial_capacity) {
    q->pids = malloc(initial_capacity * sizeof(pid_t));
    if (!q->pids) return -1;
    q->capacity = initial_capacity;
    q->count = 0;
    q->head = 0;
    return 0;
}

// Enqueue (add to back)
int enqueue(PidQueue *q, pid_t pid) {
    if ((q->head + q->count) >= q->capacity) { // Need to resize or wrap around
        // Simple resize for this example
        size_t new_capacity = q->capacity == 0 ? INITIAL_QUEUE_CAPACITY : q->capacity * 2;
        // If head is not at 0, we might need to move elements before reallocating
        // to avoid complexity, let's just reallocate a larger buffer
        if (q->head > 0) {
            // Move elements to the beginning if wrapped
            memmove(q->pids, q->pids + q->head, q->count * sizeof(pid_t));
            q->head = 0;
        }
        pid_t *new_pids = realloc(q->pids, new_capacity * sizeof(pid_t));
        if (!new_pids) {
            perror("Failed to reallocate queue");
            return -1;
        }
        q->pids = new_pids;
        q->capacity = new_capacity;
    }
    size_t tail_index = (q->head + q->count) % q->capacity; // Use modulo if implementing circular buffer
    q->pids[tail_index] = pid;
    q->count++;
    return 0;
}

// Dequeue (remove from front)
// Returns PID or -1 if queue is empty
pid_t dequeue(PidQueue *q) {
    if (q->count == 0) {
        return -1; // Empty
    }
    pid_t pid = q->pids[q->head];
    q->head = (q->head + 1) % q->capacity; // Use modulo if implementing circular buffer
    q->count--;
    if (q->count == 0) { // Reset head if empty to avoid large index
        q->head = 0;
    }
    return pid;
}

// Free Queue
void free_queue(PidQueue *q) {
    free(q->pids);
    q->pids = NULL;
    q->capacity = 0;
    q->count = 0;
    q->head = 0;
}

// Comparison function for qsort
int compare_pids(const void *a, const void *b) {
    pid_t pid_a = *(const pid_t *)a;
    pid_t pid_b = *(const pid_t *)b;
    if (pid_a < pid_b) return -1;
    if (pid_a > pid_b) return 1;
    return 0;
}


// Find all descendants using BFS
// Populates the descendants_out array, returns number of descendants found or -1 on error
int find_all_descendants(pid_t start_pid, pid_t **descendants_out, size_t *desc_count_out) {
    PidQueue queue;
    if (init_queue(&queue, INITIAL_QUEUE_CAPACITY) != 0) {
        fprintf(stderr, "Failed to initialize BFS queue\n");
        return -1;
    }

    // Clear visited set for this traversal
    clear_visited_set();

    // --- Dynamic array for results ---
    size_t desc_capacity = INITIAL_DESCENDANTS_CAPACITY;
    size_t desc_count = 0;
    pid_t *descendants = malloc(desc_capacity * sizeof(pid_t));
    if (!descendants) {
        perror("Failed to allocate descendants array");
        free_queue(&queue);
        return -1;
    }
    // ---

    // Start BFS with direct children of the start_pid
    ChildNode *child = get_children(start_pid);
    while (child != NULL) {
        int added = add_to_visited(child->child_pid);
        if (added == 1) { // If successfully added (not visited before)
            // Add to results
            if (desc_count >= desc_capacity) {
                desc_capacity *= 2;
                pid_t *new_desc = realloc(descendants, desc_capacity * sizeof(pid_t));
                if (!new_desc) {
                    perror("Failed to realloc descendants array");
                    free(descendants);
                    free_queue(&queue);
                    clear_visited_set(); // Clean up visited set memory
                    return -1;
                }
                descendants = new_desc;
            }
            descendants[desc_count++] = child->child_pid;

            // Add to queue for further exploration
            if (enqueue(&queue, child->child_pid) != 0) {
                fprintf(stderr, "Failed to enqueue child PID %d\n", child->child_pid);
                free(descendants);
                free_queue(&queue);
                clear_visited_set();
                return -1;
            }
        } else if (added == -1) {
            // Memory allocation error in visited set
            fprintf(stderr, "Failed to add child PID %d to visited set\n", child->child_pid);
            free(descendants);
            free_queue(&queue);
            clear_visited_set();
            return -1;
        }
        child = child->next;
    }

    // Continue BFS
    pid_t current_pid;
    while ((current_pid = dequeue(&queue)) != -1) {
        ChildNode *grand_child = get_children(current_pid);
        while (grand_child != NULL) {
            int added = add_to_visited(grand_child->child_pid);
            if (added == 1) { // If successfully added (not visited before)
                // Add to results
                if (desc_count >= desc_capacity) {
                    desc_capacity *= 2;
                    pid_t *new_desc = realloc(descendants, desc_capacity * sizeof(pid_t));
                    if (!new_desc) {
                        perror("Failed to realloc descendants array");
                        free(descendants);
                        free_queue(&queue);
                        clear_visited_set();
                        return -1;
                    }
                    descendants = new_desc;
                }
                descendants[desc_count++] = grand_child->child_pid;

                // Add to queue
                if (enqueue(&queue, grand_child->child_pid) != 0) {
                    fprintf(stderr, "Failed to enqueue grandchild PID %d\n", grand_child->child_pid);
                    free(descendants);
                    free_queue(&queue);
                    clear_visited_set();
                    return -1;
                }
            } else if (added == -1) {
                // Memory allocation error in visited set
                fprintf(stderr, "Failed to add grandchild PID %d to visited set\n", grand_child->child_pid);
                free(descendants);
                free_queue(&queue);
                clear_visited_set();
                return -1;
            }
            grand_child = grand_child->next;
        }
    }

    free_queue(&queue);
    // Don't clear visited set here, it's needed if called multiple times in main
    // but its memory will be freed later. We clear it *before* each call.

    *descendants_out = descendants;
    *desc_count_out = desc_count;
    return (int)desc_count; // Return count, signal error with -1
}

// --- Main ---
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <PID1> [PID2] ...\n", argv[0]);
        return 1;
    }

    // Initialize map (set buckets to NULL)
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        parent_map[i] = NULL;
        visited_set[i] = NULL; // Also initialize visited set buckets
    }

    // fprintf(stderr, "Building process map...\n");
    if (build_parent_map_from_proc() != 0) {
        fprintf(stderr, "Error: Failed to build process map.\n");
        // No map memory to free yet, as build failed early or handled internally
        return 1;
    }
    // fprintf(stderr, "Process map built.\n");


    for (int i = 1; i < argc; ++i) {
        char *endptr;
        errno = 0; // Reset errno before call
        long val = strtol(argv[i], &endptr, 10);

        // Input validation
        if (endptr == argv[i] || *endptr != '\0' ||
            ((val == LONG_MIN || val == LONG_MAX) && errno == ERANGE) ||
            val <= 0) // PIDs must be positive
        {
            fprintf(stderr, "Warning: Skipping invalid PID '%s'\n", argv[i]);
            continue;
        }
        pid_t pid_to_query = (pid_t)val;

        // fprintf(stderr, "Descendants of PID %d:\n", pid_to_query);

        pid_t *descendant_pids = NULL;
        size_t descendant_count = 0;

        int result = find_all_descendants(pid_to_query, &descendant_pids, &descendant_count);

        if (result < 0) {
            fprintf(stderr, "Error finding descendants for PID %d.\n", pid_to_query);
            // Memory for descendant_pids might or might not have been allocated/freed
            // inside find_all_descendants depending on where the error occurred.
            // If find_all_descendants guarantees freeing on error, we don't free here.
            // Otherwise, we might need to check if descendant_pids is non-NULL and free.
            // For simplicity, assume find_all_descendants cleaned up on error return.
        } else if (descendant_count == 0) {
            // fprintf(stderr, "(None found)\n");
            free(descendant_pids); // Free the empty (but allocated) array
        } else {
            // Sort the results
            qsort(descendant_pids, descendant_count, sizeof(pid_t), compare_pids);

            // Print sorted results
            for (size_t j = 0; j < descendant_count; ++j) {
                printf("%d\n", descendant_pids[j]);
            }
            free(descendant_pids); // Free the results array for this PID
        }
        // Important: Clear the visited set *after* processing each PID,
        // so the next call to find_all_descendants starts fresh.
        clear_visited_set();
    }

    // Clean up global resources
    free_parent_map();
    // Visited set nodes were freed by clear_visited_set after last PID

    return 0;
}
