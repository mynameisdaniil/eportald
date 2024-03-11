-module(enr_basic_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("src/enr.hrl").


-define(TEST_VECTOR_PRIV_KEY, binary:decode_hex(<<"b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291">>)).
-define(TEST_VECTOR_ENCODED_ENR, <<"enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8">>).
-define(TEST_VECTOR_IP, binary:decode_hex(<<"7f000001">>)).
-define(TEST_VECTOR_UDP, binary:decode_hex(<<"765f">>)).
-define(TEST_VECTOR_SEQ, 1).
-define(TEST_VECTOR_SECP256K1, binary:decode_hex(<<"03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138">>)).
-define(TEST_VECTOR_NODE_ID, binary:decode_hex(<<"a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7">>)).

-define(REAL_TRIN_ENR, <<"enr:-Jy4QIs2pCyiKna9YWnAF0zgf7bT0GzlAGoF8MEKFJOExmtofBIqzm71zDvmzRiiLkxaEJcs_Amr7XIhLI74k1rtlXICY5Z0IDAuMS4xLWFscGhhLjEtMTEwZjUwgmlkgnY0gmlwhKEjVaWJc2VjcDI1NmsxoQLSC_nhF1iRwsCw0n3J4jRjqoaRxtKgsEe5a-Dz7y0JloN1ZHCCIyg">>).
-define(REAL_TRIN_IP, binary:decode_hex(<<"A12355A5">>)).
-define(REAL_TRIN_UDP, binary:decode_hex(<<"2328">>)).
-define(REAL_TRIN_SECP256K1, binary:decode_hex(<<"02D20BF9E1175891C2C0B0D27DC9E23463AA8691C6D2A0B047B96BE0F3EF2D0996">>)).
-define(REAL_TRIN_SEQ, 2).
-define(REAL_TRIN_CLIENT, <<"t 0.1.1-alpha.1-110f50">>).

encode_test() ->
  {ok, ENR} = enr:encode(1, #{
                              <<"ip">> => ?TEST_VECTOR_IP,
                              <<"udp">> => ?TEST_VECTOR_UDP
                             }, ?TEST_VECTOR_PRIV_KEY),
  ?assertEqual(ENR, ?TEST_VECTOR_ENCODED_ENR).

decode_test() ->
  {ok, ENR} = enr:decode(?TEST_VECTOR_ENCODED_ENR),

  KV = ENR#enr_v4.kv,

  ?assertEqual(enr:compressed_pub_key_to_node_id(maps:get(<<"secp256k1">>, KV)), ?TEST_VECTOR_NODE_ID),
  ?assertEqual(maps:get(<<"ip">>, KV), ?TEST_VECTOR_IP),
  ?assertEqual(maps:get(<<"udp">>, KV), ?TEST_VECTOR_UDP),
  ?assertEqual(maps:get(<<"secp256k1">>, KV), ?TEST_VECTOR_SECP256K1),
  ?assertEqual(ENR#enr_v4.seq, ?TEST_VECTOR_SEQ).

decode_real_enr_test() ->
  {ok, ENR} = enr:decode(?REAL_TRIN_ENR),
  KV = ENR#enr_v4.kv,
  ?assertEqual(maps:get(<<"ip">>, KV), ?REAL_TRIN_IP),
  ?assertEqual(maps:get(<<"udp">>, KV), ?REAL_TRIN_UDP),
  ?assertEqual(maps:get(<<"secp256k1">>, KV), ?REAL_TRIN_SECP256K1),
  ?assertEqual(maps:get(<<"c">>, KV), ?REAL_TRIN_CLIENT),
  ?assertEqual(ENR#enr_v4.seq, ?REAL_TRIN_SEQ).
