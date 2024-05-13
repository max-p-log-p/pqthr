#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// #include "flint/src/fq.h"
// #include "flint/src/fq_poly.h"
#include <NTL/GF2E.h>
#include <NTL/GF2EX.h>
#include <NTL/GF2X.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/vec_GF2E.h>
#include <NTL/vector.h>
extern "C" {
#include "Picnic/hash.h"
#include "Picnic/picnic.h"
#include "Picnic/picnic_impl.h"
#include "Picnic/picnic_types.h"
int get_param_set(picnic_params_t, paramset_t *);

int commit(picnic_publickey_t *, const uint8_t *, size_t, commitments_t *,
		g_commitments_t *, signature_t *, paramset_t *);
int trapdoor_commit(uint32_t *, picnic_publickey_t *, view_t **, seeds_t *,
		commitments_t *, g_commitments_t *, uint8_t *, paramset_t *);
int trapdoor_open(const uint8_t *, size_t, view_t **, seeds_t *,
		commitments_t *, g_commitments_t *, signature_t *, paramset_t *);
int verify2(signature_t *, const uint32_t *, const uint32_t *,
           const uint8_t *, size_t, paramset_t *);
}

using namespace NTL;

typedef struct pqtr_params {
	uint32_t numProofs;
	uint32_t numOpenings;
	uint32_t ringSize;
	uint32_t threshold;
	uint32_t keySize; // size of key in bytes
	uint32_t fieldDegree; // degree of field extension
} pqtr_params_t;

typedef struct trap_commit {
	view_t **views;
	seeds_t *seeds;
	commitments_t *as;
	g_commitments_t *gs;
} trap_commit_t;

typedef struct share {
	GF2E point;
	trap_commit_t *commit;
	signature_t *sig;
	uint8_t *key;
	uint8_t *enc;
} share_t;

// static fq_ctx_t fctx;
// static fmpz_t prime = { 2 };
// static const char *var = "v";

enum Algs { KEY_GEN, SIGN, VERIFY, NONE };

