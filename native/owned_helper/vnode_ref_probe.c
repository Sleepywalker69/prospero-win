#include "vnode_ref_probe.h"
#include <stdint.h>

int lapy_vnode_ref_probe_added_two(
    const struct lapy_vnode_ref_counts *before,
    const struct lapy_vnode_ref_counts *with_donor)
{
    return before && with_donor &&
           before->hold <= UINT32_MAX - 2 &&
           before->use <= UINT32_MAX - 2 &&
           with_donor->hold == before->hold + 2 &&
           with_donor->use == before->use + 2;
}

int lapy_vnode_ref_probe_returned_to_baseline(
    const struct lapy_vnode_ref_counts *before,
    const struct lapy_vnode_ref_counts *after_release)
{
    return before && after_release &&
           after_release->hold == before->hold &&
           after_release->use == before->use;
}
