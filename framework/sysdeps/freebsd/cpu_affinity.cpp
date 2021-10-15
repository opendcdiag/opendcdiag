/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cpu_affinity.h>

#include <pthread_np.h>
#include <sys/cpuset.h>

static_assert(sizeof(cpuset_t) >= sizeof(LogicalProcessorSet));

LogicalProcessorSet ambient_logical_processor_set()
{
    LogicalProcessorSet result;
    if (cpuset_getaffinity(CPU_LEVEL_ROOT, CPU_WHICH_PID, -1, sizeof(result.array),
                           reinterpret_cast<cpu_set_t *>(result.array)) != 0)
        result.clear();
    return result;
}

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    if (thread_name)
        pthread_set_name_np(pthread_self(), thread_name);

    cpuset_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(n, &cpu_set);

    if (cpuset_setaffinity(CPU_LEVEL_ROOT, CPU_WHICH_PID, -1, sizeof(cpu_set), &cpu_set)) {
        perror("cpuset_setaffinity");
        return false;
    }
    return true;
}

