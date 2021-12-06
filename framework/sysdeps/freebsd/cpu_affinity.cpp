/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <topology.h>

#include <pthread_np.h>
#include <sys/cpuset.h>

static_assert(sizeof(cpuset_t) >= sizeof(LogicalProcessorSet));

LogicalProcessorSet ambient_logical_processor_set()
{
    LogicalProcessorSet result;
    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(result.array),
                           reinterpret_cast<cpuset_t *>(result.array)) != 0)
        result.clear();
    return result;
}

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    if (thread_name)
        pthread_set_name_np(pthread_self(), thread_name);

    cpuset_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(int(n), &cpu_set);

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpu_set), &cpu_set)) {
        perror("cpuset_setaffinity");
        return false;
    }
    return true;
}

