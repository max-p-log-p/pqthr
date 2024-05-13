#include "pqtr.h"

void
memcpyS(uint8_t *dst, const uint8_t **src, size_t len)
{
	memcpy(dst, *src, len);
	*src += len;
}

void
memcpyD(uint8_t **dst, const uint8_t *src, size_t len)
{
	memcpy(*dst, src, len);
	*dst += len;
}

static inline ssize_t
getPkSize(paramset_t *commit_params)
{
	return 1 + 2 * commit_params->stateSizeBytes;
}

static inline ssize_t
getSkSize(paramset_t *commit_params)
{
	return 1 + 3 * commit_params->stateSizeBytes;
}

static inline size_t
getCommitSize(paramset_t *params)
{
	return params->digestSizeBytes;
}

static inline size_t
getGcommitSize(paramset_t *params)
{
	return params->UnruhGWithInputBytes;
}

static inline size_t
getGcommitSize2(uint8_t challenge, paramset_t *params)
{
	return (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
}

static inline size_t
getCommitsSize(paramset_t *params)
{
	return params->numMPCRounds * params->numMPCParties * (params->digestSizeBytes + params->UnruhGWithInputBytes);
}

static inline size_t
getOpenSize(paramset_t *params)
{
	return 2 * params->seedSizeBytes + params->stateSizeBytes + params->andSizeBytes;
}

static inline size_t
getFieldSize(pqtr_params_t *params)
{
	return numBytes(params->fieldDegree);
}

static inline size_t
getEncSize(pqtr_params_t *params, paramset_t *commit_params)
{
	return getFieldSize(params) + commit_params->numMPCRounds * params->keySize + getOpenSize(commit_params);
}

static inline size_t
getSigSize(paramset_t *params)
{
	return params->numMPCRounds * (getCommitSize(params) + getGcommitSize(params) + getOpenSize(params));
}

static inline size_t
getProofSize(pqtr_params_t *params, paramset_t *commit_params)
{
	return params->ringSize * (getFieldSize(params) + getCommitsSize(commit_params) + getSigSize(commit_params) + params->keySize + params->numOpenings * getEncSize(params, commit_params));
}

static inline size_t
getThrSize(pqtr_params_t *params, paramset_t *commit_params)
{
	return /* params->ringSize * params->getPkSize(commit_params) + */ params->numProofs * getProofSize(params, commit_params);
}

void
point2Bytes(GF2E elem, uint8_t **bytes, struct pqtr_params *params)
{
	*bytes = malloc(getFieldSize(params));
	BytesFromGF2X(*bytes, rep(elem), getFieldSize(params));
}

void
bytes2point(uint8_t *bytes, GF2E elem, struct pqtr_params *params)
{
	GF2X tmp;

	GF2XFromBytes(tmp, bytes, params->fieldDegree);
	elem = conv<GF2E>(tmp);

	free(bytes);
}

void H(const char *message, size_t messageLen, trap_commit_t *commits, uint8_t *output, pqtr_params_t *pqtr_params, paramset_t *params, uint32_t counter)
{
    HashInstance ctx;

    /* Hash the inputs with prefix, store digest in output */
    HashInit(&ctx, params, HASH_PREFIX_6);
	HashUpdate(&ctx, (uint8_t *)message, messageLen);
	HashUpdate(&ctx, (uint8_t *)&counter, sizeof(counter));

	for (uint32_t i = 0; i < pqtr_params->ringSize; ++i) {
		for (uint32_t r = 0; r < params->numMPCRounds; ++r) {
			for (uint32_t p = 0; p < params->numMPCParties; ++p) {
				HashUpdate(&ctx, commits[i].as[r].hashes[p], getCommitSize(params));
				HashUpdate(&ctx, commits[i].gs[r].G[p], getGcommitSize(params));
			}
		}
	}

    HashFinal(&ctx);
    HashSqueeze(&ctx, output, getFieldSize(pqtr_params));
}

void H1(const char *message, size_t messageLen, trap_commit_t *commits, uint8_t **enc, uint8_t *output, paramset_t *commit_params, pqtr_params_t *params)
{
	size_t encSize;
    HashInstance ctx;

	encSize = getEncSize(params, commit_params);

    /* Hash the inputs with prefix, store digest in output */
    HashInit(&ctx, commit_params, HASH_PREFIX_9);
	HashUpdate(&ctx, (uint8_t *)message, messageLen);

	for (uint32_t i = 0; i < params->ringSize; ++i) {
		for (uint32_t r = 0; r < commit_params->numMPCRounds; ++r) {
			for (uint32_t p = 0; p < commit_params->numMPCParties; ++p) {
				HashUpdate(&ctx, commits[i].as[r].hashes[p], getCommitSize(commit_params));
				HashUpdate(&ctx, commits[i].gs[r].G[p], getGcommitSize(commit_params));
			}
		}
	}

	for (uint32_t o = 0; o < params->numOpenings; ++o)
		for (uint32_t i = 0; i < params->ringSize; ++i)
			HashUpdate(&ctx, &enc[o][i * encSize], encSize);

    HashFinal(&ctx);
    HashSqueeze(&ctx, output, sizeof(*output));
}

void permute(GF2E point, signature_t *sig, uint8_t *key, uint8_t *enc, paramset_t *params, pqtr_params_t *pqtr_params)
{
    HashInstance ctx;

    /* Hash the key with prefix, store digest in output */
    HashInit(&ctx, params, HASH_PREFIX_8);
	uint8_t *bytes;
   	point2Bytes(point, &bytes, pqtr_params);
	HashUpdate(&ctx, bytes, getFieldSize(pqtr_params));

	for (uint32_t r = 0; r < params->numMPCRounds; ++r) {
		HashUpdate(&ctx, sig->proofs[r].seed1, params->seedSizeBytes);
		HashUpdate(&ctx, sig->proofs[r].seed2, params->seedSizeBytes);
		if (getChallenge(sig->challengeBits, r))
			HashUpdate(&ctx, (uint8_t *)sig->proofs[r].inputShare, params->stateSizeBytes);
		HashUpdate(&ctx, sig->proofs[r].communicatedBits, params->andSizeBytes);
	}

    HashUpdate(&ctx, key, pqtr_params->keySize);
    HashFinal(&ctx);
    HashSqueeze(&ctx, enc, getEncSize(pqtr_params, params));
}

void
interpolate(GF2EX poly, GF2E output0, GF2E *outputs, size_t len)
{
	GF2EX basis, monic, term;
	GF2E f1, input;

	// fq_poly_init2(basis, len, fctx);
	// fq_poly_init2(monic, 2, fctx);
	// fq_poly_init2(term, len, fctx);

	// fq_init2(eval, fctx);
	// fq_init2(f1, fctx);
	// fq_init2(input, fctx);

	poly = output0;
	// fq_poly_set_fq(poly, output0, fctx);
	basis = 1;
	// fq_poly_one(basis, fctx);

	// std::cout << "degree: " << GF2E::degree() << std::endl;
	// std::cout << "modulus: " << GF2E::modulus() << std::endl;

	for (long n = 1; n <= len; ++n) {
		// fq_set_si(input, n, fctx);
		input = n;

		// (v - i_{n - 1})
		// fq_poly_gen(monic, fctx);
		// fq_set_si(f1, -(n - 1), fctx);
		// fq_poly_set_coeff(monic, 0, f1, fctx);

		// b_i = prod_{c = 1}^{n - 1} (v - i_c)
		SetCoeff(monic, 0, GF2E(-(n - 1)));
		SetCoeff(monic, 1, GF2E(1));
		basis *= monic;
		// fq_poly_mul(basis, basis, monic, fctx);

		// c = f(i_n) - p(i_n) / b_i(i_n)
		// fq_poly_evaluate_fq(eval, poly, input, fctx);
		// fq_sub(f1, outputs[n - 1], eval, fctx);
		// fq_poly_evaluate_fq(eval, basis, input, fctx);
		// fq_div(f1, f1, eval, fctx);
		// std::cout << "monic: " << monic << std::endl;
		// std::cout << "basis: " << basis << std::endl;
		// std::cout << "basis(input): " << eval(basis, input) << std::endl;
		f1 = (outputs[n - 1] - eval(poly, input)) / eval(basis, input);

		// t_i = c b_i
		// fq_poly_scalar_mul_fq(term, basis, f1, fctx);
		term = f1 * basis;

		// p_i = p_{i - 1} + t_i
		// fq_poly_add(poly, poly, term, fctx);
		poly += term;
	}

	// fq_poly_clear(basis, fctx);
	// fq_poly_clear(monic, fctx);
	// fq_poly_clear(term, fctx);

	// fq_clear(eval, fctx);
	// fq_clear(f1, fctx);
	// fq_clear(input, fctx);
}

void
trap_open(GF2E test, GF2E *trap_outputs, GF2E *outputs, trap_commit_t *commits, signature_t *trap_sigs, paramset_t *commit_params, pqtr_params_t *params)
{
	uint32_t n;
	GF2E input;
	GF2EX poly;

	// fq_poly_init2(poly, params->ringSize - params->threshold + 1, fctx);
	// fq_init2(input, fctx);

	vec_GF2E inputs;
	vec_GF2E out;

	inputs.SetLength(params->ringSize - params->threshold + 1);
	out.SetLength(params->ringSize - params->threshold + 1);

	n = 0;
	inputs[0] = conv<GF2E>(GF2XFromBytes((uint8_t *)&n, sizeof(n)));
	out[0] = test;

	for (uint32_t i = 1; i <= params->ringSize - params->threshold; ++i) {
		n = i + params->threshold;
		inputs[i] = conv<GF2E>(GF2XFromBytes((uint8_t *)&n, sizeof(n)));
		out[i] = outputs[i - 1];
		// std::cout << "inputs: " << inputs[i] << std::endl;
		// std::cout << "out: " << out[i] << std::endl;
	}

	interpolate(poly, inputs, out);

	for (uint32_t i = 0; i < params->threshold; ++i) {
		// fq_set_ui(input, i + 1, fctx);
		// fq_poly_evaluate_fq(trap_outputs[i], poly, input, fctx);
		n = i + 1;
		input = conv<GF2E>(GF2XFromBytes((uint8_t *)&n, sizeof(n)));
		trap_outputs[i] = eval(poly, input);
		// std::cout << "trap_outputs[i]: " << trap_outputs[i] << std::endl;
		uint8_t *bytes = malloc(getFieldSize(params));
		BytesFromGF2X(bytes, rep(trap_outputs[i]), getFieldSize(params));
		trapdoor_open(bytes, getFieldSize(params), commits[i].views, commits[i].seeds, commits[i].as, commits[i].gs, &trap_sigs[i], commit_params);
	}

	// fq_poly_clear(poly, fctx);
	// fq_clear(input, fctx);
}

void
addProof(uint8_t **sig, GF2E *trap_points, GF2E *points, trap_commit_t *commits, signature_t *trap_sigs, signature_t *sigs, uint8_t *keys, uint8_t **enc, pqtr_params_t *params, paramset_t *commit_params)
{
	for (uint32_t i = 0; i < params->threshold; ++i) {
		// fmpz_poly_struct trap_point = trap_points[i][0];
		// std::cout << rep(trap_points[i]) << std::endl;
		uint8_t *bytes = malloc(getFieldSize(params));
		BytesFromGF2X(bytes, rep(trap_points[i]), getFieldSize(params));
		// printHex("bytes: ", bytes, getFieldSize(params));
		memcpyD(sig, bytes, getFieldSize(params));
	}

	for (uint32_t i = 0; i < params->ringSize - params->threshold; ++i) {
		// fmpz_poly_struct point = points[i][0];
		// std::cout << rep(points[i]) << std::endl;
		uint8_t *bytes = malloc(getFieldSize(params));
		BytesFromGF2X(bytes, rep(points[i]), getFieldSize(params));
		// printHex("bytes: ", bytes, getFieldSize(params));
		memcpyD(sig, bytes, getFieldSize(params));
	}

	for (uint32_t i = 0; i < params->ringSize; ++i) {
		for (uint32_t r = 0; r < commit_params->numMPCRounds; ++r) {
			for (uint32_t p = 0; p < commit_params->numMPCParties; ++p) {
				memcpyD(sig, commits[i].as[r].hashes[p], getCommitSize(commit_params));
				memcpyD(sig, commits[i].gs[r].G[p], getGcommitSize(commit_params));
			}
		}
	}

	for (uint32_t i = 0; i < params->threshold; ++i) {
		serializeSignature(&trap_sigs[i], *sig, getSigSize(commit_params), commit_params);
		*sig += getSigSize(commit_params);
	}

	for (uint32_t i = 0; i < params->ringSize - params->threshold; ++i) {
		serializeSignature(&sigs[i], *sig, getSigSize(commit_params), commit_params);
		*sig += getSigSize(commit_params);
	}

	memcpyD(sig, keys, params->ringSize * params->keySize);

	for (uint32_t o = 0; o < params->numOpenings; ++o)
		memcpyD(sig, enc[o], params->ringSize * getEncSize(params, commit_params));
}

void
pqtr_sign(picnic_privatekey_t *sks, picnic_publickey_t *pks, pqtr_params_t *params,
		paramset_t *commit_params, const char *message, size_t message_len,
		uint8_t **signature, ssize_t *signature_len)
{
	signature_t *sigs, **trap_sigs;
	// flint_rand_t state;
	GF2E *points, **trap_points;
	GF2E *hashes;
	trap_commit_t *commits;
	uint8_t **enc, **keys, **salts, *sig;
	uint8_t open;
	size_t encSize;

	GF2X P = BuildIrred_GF2X(params->fieldDegree);
	GF2E::init(P);
	// fq_ctx_init(fctx, prime, params->fieldDegree, var);
	// flint_randinit(state);

	encSize = getEncSize(params, commit_params);

	commits = calloc(params->ringSize, sizeof(*commits));
	points = calloc(params->ringSize - params->threshold, sizeof(*points));
	sigs = calloc(params->ringSize - params->threshold, sizeof(*sigs));
	salts = calloc(params->threshold, sizeof(*salts));
	enc = calloc(params->numOpenings, encSize);
	keys = calloc(params->numOpenings, sizeof(*keys));
	hashes = calloc(params->numOpenings, sizeof(*hashes));
	trap_points = calloc(params->numOpenings, sizeof(*trap_points));
	trap_sigs = calloc(params->numOpenings, sizeof(*trap_sigs));

	for (uint32_t i = 0; i < params->threshold; ++i)
		salts[i] = calloc(commit_params->saltSizeBytes, sizeof(**salts));

	for (uint32_t i = 0; i < params->ringSize; ++i) {
		commits[i].views = allocateViews(commit_params);
		commits[i].seeds = allocateSeeds(commit_params);
		commits[i].as = allocateCommitments(commit_params, 0);
		commits[i].gs = allocateGCommitments(commit_params);
	}

	for (uint32_t i = 0; i < params->ringSize - params->threshold; ++i) {
		// fq_init2(points[i], fctx);
		allocateSignature(&sigs[i], commit_params);
	}

	for (uint32_t o = 0; o < params->numOpenings; ++o) {
		// fq_init2(hashes[o], fctx);
		enc[o] = calloc(params->ringSize, encSize);
		keys[o] = calloc(params->ringSize, params->keySize);
		trap_points[o] = calloc(params->threshold, sizeof(**trap_points));
		trap_sigs[o] = calloc(params->threshold, sizeof(**trap_sigs));

		for (uint32_t i = 0; i < params->threshold; ++i) {
			// fq_init2(trap_points[o][i], fctx);
			allocateSignature(&trap_sigs[o][i], commit_params);
		}
	}

	*signature_len = getThrSize(params, commit_params);
	sig = *signature = malloc(*signature_len);

	/*
	for (uint32_t i = 0; i < params->ringSize; ++i) {
		picnic_write_public_key(&pks[i], *sig, getPkSize(commit_params));
		*sig += getPkSize(commit_params);
	}
	*/

	for (uint32_t p = 0; p < params->numProofs; ++p) {
		for (uint32_t i = 0; i < params->ringSize - params->threshold; ++i) {
			// fq_rand(points[i], state, fctx);
			random(points[i]);
		}

		for (uint32_t i = 0; i < params->threshold; ++i)
			trapdoor_commit((uint32_t *)&sks[i], &pks[i], commits[i].views, commits[i].seeds, commits[i].as, commits[i].gs, salts[i], commit_params);

		for (uint32_t i = 0; i < params->ringSize - params->threshold; ++i) {
			uint8_t *bytes = malloc(getFieldSize(params));
			BytesFromGF2X(bytes, rep(points[i]), getFieldSize(params));
			commit(&pks[i + params->threshold], bytes, getFieldSize(params), commits[i + params->threshold].as, commits[i + params->threshold].gs, &sigs[i], commit_params);
		}

		for (uint32_t o = 0; o < params->numOpenings; ++o) {
			uint8_t *bytes = malloc(getFieldSize(params));
			getrandom(keys[o], params->ringSize * params->keySize, 0);

			H(message, message_len, commits, bytes, params, commit_params, o);

			GF2X tmp;
			GF2XFromBytes(tmp, bytes, getFieldSize(params));
			hashes[o] = conv<GF2E>(tmp);

			trap_open(hashes[o], trap_points[o], points, commits, trap_sigs[o], commit_params, params);

			for (uint32_t i = 0; i < params->threshold; ++i)
				permute(trap_points[o][i], &trap_sigs[o][i], &keys[o][i * params->keySize], &enc[o][i * encSize], commit_params, params);

			for (uint32_t i = 0; i < params->ringSize - params->threshold; ++i)
				permute(points[i], &sigs[i], &keys[o][(i + params->threshold) * params->keySize], &enc[o][(i + params->threshold) * encSize], commit_params, params);
		}

		H1(message, message_len, commits, enc, &open, commit_params, params);

		open %= params->numOpenings;

		for (uint32_t i = 0; i < params->threshold; ++i)
			memcpy(trap_sigs[open][i].salt, salts[i], commit_params->saltSizeBytes);

		// printf("test: %lu\n", tests[open]);
		// printf("open: %d\n", open);
		// printHex("keys", keys[open], params->ringSize * params->keySize);
		// printHex("enc: ", enc[open], params->ringSize * encSize);

        addProof(&sig, trap_points[open], points, commits, trap_sigs[open], sigs, keys[open], enc, params, commit_params);
	}

	for (uint32_t i = 0; i < params->threshold; ++i)
		free(salts[i]);

	for (uint32_t i = 0; i < params->ringSize; ++i) {
		freeViews(commits[i].views, commit_params);
		freeSeeds(commits[i].seeds);
		freeCommitments(commits[i].as);
		freeGCommitments(commits[i].gs);
	}

	for (uint32_t i = 0; i < params->ringSize - params->threshold; ++i)
		freeSignature(&sigs[i], commit_params);

	for (uint32_t o = 0; o < params->numOpenings; ++o) {
		for (uint32_t i = 0; i < params->threshold; ++i)
			freeSignature(&trap_sigs[o][i], commit_params);

		free(enc[o]);
		free(keys[o]);
		free(trap_points[o]);
		free(trap_sigs[o]);
	}

	free(commits);
	free(enc);
	free(keys);
	free(salts);
	free(sigs);
	free(hashes);
	free(trap_sigs);
}

int
pqtr_verify(picnic_publickey_t *pks, const char *message, size_t message_len,
			  const uint8_t *signature, size_t signature_len, pqtr_params_t *params, paramset_t *commit_params)
{
	GF2EX poly;
	GF2E *points, hash;
	signature_t *sigs;
	uint8_t *keys, **enc, *enc2, open;
	size_t encSize;
	trap_commit_t *commits;

	GF2X P = BuildIrred_GF2X(params->fieldDegree);
	GF2E::init(P);

	// fq_ctx_init(fctx, prime, params->fieldDegree, var);
	// fq_poly_init2(poly, params->ringSize - params->threshold, fctx);
	// fq_init2(hash, fctx);

	encSize = getEncSize(params, commit_params);

	enc = calloc(params->numOpenings, sizeof(*enc));
	enc2 = calloc(params->ringSize, encSize);

	commits = calloc(params->ringSize, sizeof(*commits));
	keys = calloc(params->ringSize, params->keySize);
	points = calloc(params->ringSize, sizeof(*points));
	sigs = calloc(params->ringSize, sizeof(*sigs));

	for (uint32_t i = 0; i < params->ringSize; ++i) {
		// fq_init2(points[i], fctx);
		// fmpz_poly_struct point = points[i][0];
		uint8_t *bytes = malloc(getFieldSize(params));
		memcpyS(bytes, &signature, getFieldSize(params));
		// printHex("bytes: ", bytes, getFieldSize(params));
		GF2X tmp;
		GF2XFromBytes(tmp, bytes, getFieldSize(params));
		points[i] = conv<GF2E>(tmp);
		// std::cout << points[i] << std::endl;
	}

	for (uint32_t i = 0; i < params->ringSize; ++i) {
		commits[i].as = allocateCommitments(commit_params, 0);
		commits[i].gs = allocateGCommitments(commit_params);

		for (uint32_t r = 0; r < commit_params->numMPCRounds; ++r) {
			for (uint32_t p = 0; p < commit_params->numMPCParties; ++p) {
				memcpyS(commits[i].as[r].hashes[p], &signature, getCommitSize(commit_params));
				memcpyS(commits[i].gs[r].G[p], &signature, getGcommitSize(commit_params));
			}
		}
	}

	for (uint32_t i = 0; i < params->ringSize; ++i) {
		allocateSignature(&sigs[i], commit_params);

		if (deserializeSignature(&sigs[i], signature, signature_len, commit_params) != EXIT_SUCCESS) {
			fprintf(stderr, "can't deserialize signature for point %d\n", i);
			return EXIT_FAILURE;
		}

		signature += getSigSize(commit_params);

		// fmpz_poly_struct point = points[i][0];
		// uint8_t *bytes;
		// point2Bytes(points[i], &bytes, params);
		uint8_t *bytes = malloc(getFieldSize(params));

		if (bytes == NULL)
			return EXIT_FAILURE;

		BytesFromGF2X(bytes, rep(points[i]), getFieldSize(params));
		// printHex("bytes: ", bytes, getFieldSize(params));

		if (verify2(&sigs[i], (uint32_t *)pks[i].ciphertext, (uint32_t *)pks[i].plaintext, bytes, getFieldSize(params), commit_params) != EXIT_SUCCESS) {
			fprintf(stderr, "can't verify signature for point %d\n", i);
			return EXIT_FAILURE;
		}

		free(bytes);
	}

	memcpyS(keys, &signature, params->ringSize * params->keySize);

	for (uint32_t o = 0; o < params->numOpenings; ++o) {
		enc[o] = calloc(params->ringSize, encSize);
		memcpyS(enc[o], &signature, params->ringSize * encSize);
	}

	H1(message, message_len, commits, enc, &open, commit_params, params);

	open %= params->numOpenings;

	uint8_t *bytes = malloc(getFieldSize(params));
	H(message, message_len, commits, bytes, params, commit_params, open);
	bytes2point(bytes, hash, params);

	for (uint32_t i = 0; i < params->ringSize; ++i)
		permute(points[i], &sigs[i], &keys[i * params->keySize], &enc2[i * encSize], commit_params, params);

	// printf("test: %lu\n", test);
	// printf("open: %d\n", open);
	// printHex("keys", keys, params->ringSize * params->keySize);
	// printHex("enc: ", enc[open], params->ringSize * encSize);
	// printHex("enc2: ", enc2, params->ringSize * encSize);

	if (memcmp(enc[open], enc2, params->ringSize * encSize)) {
		fprintf(stderr, "bad enc value\n");
		return EXIT_FAILURE;
	}

	// std::cout << poly << std::endl;

	vec_GF2E inputs;
	vec_GF2E out;

	inputs.SetLength(params->ringSize);
	out.SetLength(params->ringSize);

	for (uint32_t i = 0; i < inputs.length(); ++i) {
		uint32_t n = i + 1;
		inputs[i] = conv<GF2E>(GF2XFromBytes((uint8_t *)&n, sizeof(n)));
		// std::cout << "inputs: " << inputs[i] << std::endl;
	}

	for (uint32_t i = 0; i < params->ringSize; ++i) {
		out[i] = points[i];
		// std::cout << "out: " << out[i] << std::endl;
	}

	interpolate(poly, inputs, out);

	// std::cout << poly << std::endl;
	// printf("deg: %ld\n", deg(poly));

	if (deg(poly) > params->ringSize - params->threshold) {
		fprintf(stderr, "not enough signers\n");
		return EXIT_FAILURE;
	}

	for (uint32_t i = 0; i < params->threshold; ++i) {
		freeCommitments(commits[i].as);
		freeGCommitments(commits[i].gs);
	}

	for (uint32_t i = 0; i < params->ringSize; ++i)
		freeSignature(&sigs[i], commit_params);

	for (uint32_t o = 0; o < params->numOpenings; ++o)
		free(enc[o]);

	free(enc);
	free(enc2);
	free(keys);
	free(sigs);

	return EXIT_SUCCESS;
}

ssize_t
read_file(char *fmt, char *prefix, uint32_t index, uint8_t *buf, size_t buflen)
{
	int fd;
	ssize_t bytesRead;
	char *pathname;

	asprintf(&pathname, fmt, prefix, index);

	fd = open(pathname, O_RDONLY);

	bytesRead = read(fd, buf, buflen);

	close(fd);
	free(pathname);

	return bytesRead;
}

void
write_file(char *fmt, char *prefix, uint32_t index, uint8_t *buf, size_t buflen)
{
	FILE *f;
	char *pathname;

	asprintf(&pathname, fmt, prefix, index);

	f = fopen(pathname, "wb");

	fwrite(buf, sizeof(*buf), buflen, f);

	fclose(f);
	free(pathname);
}

int
main(int argc, char *argv[])
{
	uint8_t *buf, *sigBytes;
	char *prefix, *msg;
	int alg, bytesRequired, opt, ret;
	size_t buflen;
	ssize_t sigBytesLen;
	pqtr_params_t params;

	ret = EXIT_FAILURE;
	params.ringSize = params.threshold = 1;
	params.fieldDegree = 256;
	params.numProofs = 1;
	params.numOpenings = 4; // power of 2 which is >= 3
	params.keySize = 32;
    paramset_t paramset;
	picnic_params_t parameters = Picnic_L5_UR;
	picnic_publickey_t *pks;
	picnic_privatekey_t *sks;
	msg = prefix = NULL;
	alg = NONE;

	while ((opt = getopt(argc, argv, "km:n:p:st:v")) != -1) {
		switch (opt) {
		case 'k':
			alg = KEY_GEN;
			break;
		case 'n':
			params.ringSize = strtol(optarg, NULL, 10);
			break;
		case 'm':
			msg = optarg;
			break;
		case 'p':
			prefix = optarg;
			break;
		case 's':
			alg = SIGN;
			break;
		case 't':
			params.threshold = strtol(optarg, NULL, 10);
			break;
		case 'v':
			alg = VERIFY;
			break;
		default:
			fprintf(stderr, "usage: %s\n", argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (prefix == NULL) {
		fprintf(stderr, "no prefix\n");
		return EXIT_FAILURE;
	}

	get_param_set(parameters, &paramset);
	buflen = getSkSize(&paramset);
	buf = malloc(buflen);

	pks = calloc(params.ringSize, sizeof(*pks));

	switch (alg) {
	case KEY_GEN:
			sks = calloc(params.ringSize, sizeof(*sks));

			for (uint32_t i = 0; i < params.ringSize; ++i) {
				picnic_keygen(parameters, &pks[i], &sks[i]);

				bytesRequired = picnic_write_public_key(&pks[i], buf, buflen);
				write_file("%s_pk_%d", prefix, i, buf, bytesRequired);

				bytesRequired = picnic_write_private_key(&sks[i], buf, buflen);
				write_file("%s_sk_%d", prefix, i, buf, bytesRequired);
			}

			free(sks);
			break;
	case SIGN:
			if (msg == NULL) {
				fprintf(stderr, "no message to sign\n");
				ret = EXIT_FAILURE;
				break;
			}

			sks = calloc(params.threshold, sizeof(*sks));

			for (uint32_t i = 0; i < params.threshold; ++i) {
				if (read_file("%s_sk_%d", prefix, i, buf, buflen) != getSkSize(&paramset)) {
					fprintf(stderr, "bad private key\n");
					return EXIT_FAILURE;
				}
				if (picnic_read_private_key(&sks[i], buf, buflen)) {
					fprintf(stderr, "no private key\n");
					return EXIT_FAILURE;
				}
			}

			for (uint32_t i = 0; i < params.ringSize; ++i) {
				if (read_file("%s_pk_%d", prefix, i, buf, buflen) != getPkSize(&paramset)) {
					fprintf(stderr, "bad public key\n");
					return EXIT_FAILURE;
				}
				if (picnic_read_public_key(&pks[i], buf, buflen)) {
					fprintf(stderr, "no public key\n");
					return EXIT_FAILURE;
				}
			}

			pqtr_sign(sks, pks, &params, &paramset, msg, strlen(msg), &sigBytes, &sigBytesLen);
			printf("Signature Size: %lu\n", sigBytesLen);

			if (sigBytes && sigBytesLen) {
				write_file("%s_%d", "sign", 0, sigBytes, sigBytesLen);
				free(sigBytes);
			}

			free(sks);
			break;
	case VERIFY:
			for (uint32_t i = 0; i < params.ringSize; ++i) {
				if (read_file("%s_pk_%d", prefix, i, buf, buflen) != getPkSize(&paramset)) {
					fprintf(stderr, "bad public key\n");
					return EXIT_FAILURE;
				}
				if (picnic_read_public_key(&pks[i], buf, buflen)) {
					fprintf(stderr, "no public key\n");
					return EXIT_FAILURE;
				}
			}

			sigBytesLen = getThrSize(&params, &paramset);
			sigBytes = malloc(sigBytesLen);
			printf("Signature Len: %lu\n", sigBytesLen);

			if (read_file("%s_%d", "sign", 0, sigBytes, sigBytesLen) == sigBytesLen)
				ret = pqtr_verify(pks, msg, strlen(msg), sigBytes, sigBytesLen, &params, &paramset);
			else {
				fprintf(stderr, "bad signature size\n");
				ret = EXIT_FAILURE;
			}

			free(sigBytes);
			break;
	default:
			fprintf(stderr, "bad alg\n");
			ret = EXIT_FAILURE;
			break;
	}

	free(buf);
	free(pks);
	return ret;
}
