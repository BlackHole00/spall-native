#include <stdint.h>

#ifdef __APPLE__
    #ifdef __aarch64__

    uint64_t get_frequency(void) {
        uint64_t freq_val = 0;
        asm volatile("mrs %0, cntfrq_el0" : "=r"(freq_val));
        return freq_val;
    }

    #elif

    uint64_t get_frequency(void) {
        uint64_t freq_val = 0;
        int ret = sysctlbyname("machdep.tsc.frequency", &freq_val, sizeof(freq_val), NULL, 0);
        return freq_val;
    }

    #endif
#elif
    uint64_t get_frequency(void) {
        return 0;
    }
#endif
