#include "erl_nif.h"
#include "keccak-tiny.h"

static int load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info) {
    return 0;
}

static ERL_NIF_TERM keccak_256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  ErlNifBinary input;
  ERL_NIF_TERM output;

  if (argc != 1 || !enif_inspect_binary(env, argv[0], &input)) {
    return enif_make_badarg(env);
  }

  unsigned char *buf = enif_make_new_binary(env, 32, &output);

  keccak256(buf, 32, input.data, input.size);

  return output;

}

static ErlNifFunc nif_funcs[] = {
  {"keccak_256", 1, keccak_256}
};

ERL_NIF_INIT(keccak, nif_funcs, &load, NULL, NULL, NULL);
