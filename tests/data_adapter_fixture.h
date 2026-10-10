/* Original mocked adapter control shared by composed test translation units. */
#ifndef DATA_ADAPTER_FIXTURE_H
#define DATA_ADAPTER_FIXTURE_H
#include <stdint.h>
#include "../native/pw_wine_child_data.h"
void data_adapter_fixture_reset(uint64_t *,unsigned);
void data_adapter_fixture_counts(unsigned *,unsigned *,unsigned *);
#endif
