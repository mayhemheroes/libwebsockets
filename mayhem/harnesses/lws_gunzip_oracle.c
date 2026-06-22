/*
 * lws_gunzip_oracle.c — self-contained golden oracle for libwebsockets' gzip/DEFLATE inflator,
 * the SAME parser path the OSS-Fuzz harness (mayhem/harnesses/lws_upng_inflate_fuzzer.cpp) drives:
 *   lws_upng_inflator_create() -> lws_upng_inflate_data() -> lws_upng_inflator_destroy().
 *
 * Usage:  lws_gunzip_oracle <gz-input-file> <output-file>
 * Reads the whole gzip file, inflates it through the lws inflator, writes the decompressed bytes to
 * <output-file>, and returns 0 only if inflation completed without a FATAL state. mayhem/test.sh
 * then asserts the output equals the original pre-gzip payload (byte-exact golden round-trip).
 *
 * This is deliberately a tiny, correct driver — it drains the output ringbuffer using the linear
 * outpos/consumed pointers (opl/cl), unlike the example app's file wrapper which mis-frames output.
 */
#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	const uint8_t *outring;
	size_t outringlen, *opl, *cl;
	struct inflator_ctx *gunz;
	lws_stateful_ret_t r;
	uint8_t *in;
	long insize;
	size_t consumed = 0, fed = 0;
	FILE *fi, *fo;
	int rc = 1;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <gz-in> <out>\n", argv[0]);
		return 2;
	}

	fi = fopen(argv[1], "rb");
	if (!fi) { fprintf(stderr, "open in failed\n"); return 2; }
	fseek(fi, 0, SEEK_END); insize = ftell(fi); fseek(fi, 0, SEEK_SET);
	if (insize < 0) { fclose(fi); return 2; }
	in = (uint8_t *)malloc((size_t)insize ? (size_t)insize : 1);
	if (!in) { fclose(fi); return 3; }
	if (insize && fread(in, 1, (size_t)insize, fi) != (size_t)insize) {
		fclose(fi); free(in); return 4;
	}
	fclose(fi);

	fo = fopen(argv[2], "wb");
	if (!fo) { free(in); return 2; }

	gunz = lws_upng_inflator_create(&outring, &outringlen, &opl, &cl);
	if (!gunz) { fclose(fo); free(in); return 5; }

	/* Feed all input once, then keep pumping (buf=NULL) until OK/FATAL, draining output as it
	 * appears. *opl is the linear total produced; *cl is what we've consumed. */
	r = lws_upng_inflate_data(gunz, in, (size_t)insize);
	fed = 1;

	for (;;) {
		/* drain any new output from the ring */
		while (*opl > consumed) {
			size_t off = consumed % outringlen;
			size_t chunk = *opl - consumed;
			if (chunk > outringlen - off)
				chunk = outringlen - off;
			if (fwrite(outring + off, 1, chunk, fo) != chunk)
				goto done;
			consumed += chunk;
			*cl = consumed;
		}

		if (r & LWS_SRET_FATAL) { rc = 1; goto done; }
		if (r == LWS_SRET_OK)   { rc = 0; goto done; }

		/* not done and not fatal: pump more (continue consuming current input) */
		if (!fed) { r = lws_upng_inflate_data(gunz, in, (size_t)insize); fed = 1; }
		else        r = lws_upng_inflate_data(gunz, NULL, 0);

		/* WANT_INPUT with no further input we can give means we're stuck — stop. */
		if ((r & LWS_SRET_WANT_INPUT) && fed && *opl == consumed) {
			/* one more pump may still emit the tail; bail if truly no progress */
			lws_stateful_ret_t r2 = lws_upng_inflate_data(gunz, NULL, 0);
			if (r2 == r && *opl == consumed) { rc = (r2 & LWS_SRET_FATAL) ? 1 : 0; goto done; }
			r = r2;
		}
	}

done:
	/* final drain */
	while (*opl > consumed) {
		size_t off = consumed % outringlen;
		size_t chunk = *opl - consumed;
		if (chunk > outringlen - off)
			chunk = outringlen - off;
		if (fwrite(outring + off, 1, chunk, fo) != chunk)
			break;
		consumed += chunk;
		*cl = consumed;
	}

	lws_upng_inflator_destroy(&gunz);
	fclose(fo);
	free(in);
	return rc;
}
