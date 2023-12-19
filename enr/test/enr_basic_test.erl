-module(enr_basic_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("src/enr.hrl").


-define(TEST_VECTOR_PRIV_KEY, binary:decode_hex(<<"b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291">>)).
-define(TEST_VECTOR_ENCODED_ENR, <<"enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8">>).
-define(TEST_VECTOR_IP, binary:decode_hex(<<"7f000001">>)).
-define(TEST_VECTOR_UDP, binary:decode_hex(<<"765f">>)).
-define(TEST_VECTOR_SEQ, 1).
-define(TEST_VECTOR_SECP256K1, binary:decode_hex(<<"03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138">>)).

encode_test() ->
  {ok, ENR} = enr:encode(1, [
                             {<<"ip">>, ?TEST_VECTOR_IP},
                             {<<"udp">>, ?TEST_VECTOR_UDP}
                            ], ?TEST_VECTOR_PRIV_KEY),
  ?assertEqual(ENR, ?TEST_VECTOR_ENCODED_ENR).

decode_test() ->
  {ok, ENR} = enr:decode(?TEST_VECTOR_ENCODED_ENR),

  KV = ENR#enr_v4.kv,

  ?assertEqual(proplists:get_value(<<"ip">>, KV), ?TEST_VECTOR_IP),
  ?assertEqual(proplists:get_value(<<"udp">>, KV), ?TEST_VECTOR_UDP),
  ?assertEqual(proplists:get_value(<<"secp256k1">>, KV), ?TEST_VECTOR_SECP256K1),
  ?assertEqual(ENR#enr_v4.seq, ?TEST_VECTOR_SEQ).
