#include <stdint.h>
#include <string.h>
#include <python2.7/Python.h>


/* docstrings for method */
static char cpuid_docstring[] =
        "Checks for appropriate vendor string and processor microarchitecture.";

/* available functions for interface */
static PyObject* cpuid_check(PyObject *self, PyObject *noargs);

/* module specification */
static PyMethodDef module_methods[] = {
        {"cpuid_check", cpuid_check, METH_VARARGS, cpuid_docstring},
        {NULL, NULL, 0, NULL}
};

/* initialize the module */
PyMODINIT_FUNC initcpuid(void)
{
        (void) Py_InitModule("cpuid", module_methods);
}

/* represents CPUID microarchs (already unmasked) that are supported */
static const uint32_t valid_pmu_cpu_type[25] = {
        0x106A0, 0x106E0, 0x206E0,          // IntelNehalem
        0x20650, 0x206C0, 0x206F0,          // IntelWestmere
        0x206A0, 0x206D0, 0x306e0,          // IntelSandyBridge
        0x306A0,                            // IntelIvyBridge
        0x306C0, 0x306F0, 0x40650, 0x40660, // IntelHaswell
        0x306D0, 0x40670, 0x406F0, 0x50660, // IntelBroadwell
        0x406e0, 0x50650, 0x506e0,          // IntelSkylake
        0x30670, 0x50670,                   // IntelSilvermont
        0x806e0, 0x906e0                    // IntelKabylake
};

/* inline assembly interface to cpuid */
static inline void cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
        asm volatile("cpuid"
            : "=a" (*eax),
              "=b" (*ebx),
              "=c" (*ecx),
              "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
}

/* returns processor information in eax register */
static uint32_t cpuid_processor_info()
{
        /* temporary registers to hold results */
        uint32_t eax, ebx, ecx, edx;

        /* eax = 1 for processor information */
        eax = 1;

        /* use all registers for output consuming purposes. */
        cpuid(&eax, &ebx, &ecx, &edx);

        /* return signature, must be unmasked */
        return eax;
}

/* stores vendor string in provided char pointer */
static void cpuid_vendor(char * name)
{
        /* set 12th char to 0 */
        name[12] = 0;

        /* eax = 0 for vendor */
        uint32_t eax;
        eax = 0;

        /* call cpuid, storing output in ebx, edx, and ecx */
        cpuid(&eax, (uint32_t *) &name[0], (uint32_t *) &name[8], (uint32_t *) &name[4]);
}

/* main Python interface */
static PyObject* cpuid_check(PyObject *self, PyObject *noargs)
{
        int i;

        /* check vendor: only Intel and AMD processors supported */
        char vendor[13];
        cpuid_vendor(vendor);

        if (strcmp(vendor, "GenuineIntel")) {
                PyErr_SetString(PyExc_RuntimeError, "invalid vendor string");
                return NULL;
        }

        /* check CPU microarchitecture through unmask */
        uint32_t cpuid_data = cpuid_processor_info();
        uint32_t cpu_type = cpuid_data & 0xF0FF0;

        /* check if microarchitecture is appropriate for use */
        for (i=0; i <= sizeof(valid_pmu_cpu_type); i++){
                if (valid_pmu_cpu_type[i] == cpu_type) {
                        /* return a exit code 0 */
                        return Py_BuildValue("i", 0);
                }
        }

        /* returned if microarchitecture is not found */
        PyErr_SetString(PyExc_RuntimeError, "unsupported CPU microarchitecture");
        return NULL;
}
