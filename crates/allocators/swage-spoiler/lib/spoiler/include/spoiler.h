#include <stddef.h> // size_t
#include <stdint.h> // uint64_t

/**
 * The SPOILER measurements
 */
struct measurement {
    /** the measurements */
	uint64_t *measurements;
    /** the timing diffs */
	uint64_t *diffs;
};

/**
 * Run the SPOILER attack given read/write buffers, returning the measurement
 */
struct measurement *spoiler_measure(uint8_t *write, size_t write_buf_size, uint8_t *read);

/**
 * Free buffer allocated by spoiler_measure
 */
void spoiler_free(struct measurement *m);

/**
 * Get timing measurements from struct returned by spoiler_measure
 */
const uint64_t *measurements(const struct measurement *m);
/**
 * Get timing diffs from struct returned by spoiler_measure
 */
const uint64_t *diffs(const struct measurement *m);
