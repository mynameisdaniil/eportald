-module(enr).

-export([
         encode/3,
         decode/1,
         decode_rlp/1,
         test_vector_struct/0,
         test_vector_privkey/0,
         test_vector_base64/0,
         test_vector_decode_base64/0,
         test_compressed/0
        ]).

-include_lib("enr.hrl").

-opaque enr_v4() :: #enr_v4{}.
-export_type([enr_v4/0]).

-type priv_key() :: binary().
-type kv() :: proplists:proplist().
-type seq() :: non_neg_integer().

-spec encode(seq(), kv(), priv_key()) -> {ok, binary()} | {error, binary()}.
encode(Seq, KV, PrivKey) ->
  {ok, PubKey} = libsecp256k1:ec_pubkey_create(PrivKey, compressed),
  SortedKV = lists:sort(fun ({A, _}, {B, _}) -> A > B end,
               lists:uniq([
                  {<<"id">>, <<"v4">>},
                  {<<"secp256k1">>, PubKey} | KV])),
  FlatKV = lists:foldl(fun ({Key, Value}, Acc) -> [Key, Value | Acc] end, [], SortedKV),
  Content = [<<Seq>> | FlatKV],
  {ok, EncodedKV} = rlp:encode(Content),
  Digest = keccak:keccak_256(EncodedKV),
  Signature = sign(Digest, PrivKey),
  FullContent = [Signature | Content],
  {ok, Raw} = rlp:encode(FullContent),
  Encoded = base64:encode(Raw, #{mode => urlsafe, padding => false}),
  Ret = <<<<"enr:">>/binary, Encoded/binary>>,
  {ok, Ret}.

-spec decode(binary()) -> {ok, enr_v4()} | {error, binary()}.
% TODO not applicable for RLP-encoded ENR
% Max length of ENR is 300 bytes according to spec
% https://github.com/ethereum/devp2p/blob/master/enr.md#rlp-encoding
decode(ENR) when byte_size(ENR) > 300 ->
  {error, <<"ENR is too long">>};

% TODO not applicable for RLP-encoded ENR
% Minimal ENR is 64 + 8 + 2 + 33 bytes
% 64 bytes is sginature
% 8 bytes is 64 bit seq
% 4 bytes is {"id","v4"} in key-value pairs, rquired by the spec
% 33 bytes is {"secp256k1", <<>>} in key-value pairs - although spec says it's not required,
% in fact it is, otherwise it is impossible to verify singature
decode(ENR) when byte_size(ENR) < 118 ->
  {error, <<"ENR is too short">>};

decode(<<"enr:", Encoded/binary>>) ->
  Raw = base64:decode(Encoded, #{mode => urlsafe, padding => false}),
  {ok, List} = rlp:decode(Raw),
  decode(signature, List, #enr_v4{}).

decode_rlp(RlpEncoded) ->
  case rlp:decode(RlpEncoded) of
    {ok, List} ->
      decode(signature, List, #enr_v4{});
    {error, Reason} ->
      {error, Reason}
  end.

decode(signature, [Signature | Rest], Struct) ->
  {ok, EncodedRest} = rlp:encode(Rest),
  ContentHash = keccak:keccak_256(EncodedRest),
  decode(seq, Rest, Struct#enr_v4{signature = Signature, content_hash = ContentHash});

% TODO seq is 64 bit integer according to spec
% but in fact it is not, it is variable in size from 1 to 4 bytes
decode(seq, [Seq | Rest], Struct) ->
  decode(id, Rest, Struct#enr_v4{seq = Seq});

decode(id, [<<"id">>, ID | Rest], Struct) when ID == <<"v4">> ->
  decode(pair, Rest, Struct#enr_v4{kv = [<<"id">>, ID]});

decode(pair,
       [<<"secp256k1">> = Key, Value | Rest],
       #enr_v4{kv = KV, signature = Signature, content_hash = ContentHash} = Struct) ->
  case verify(ContentHash, Signature, Value) of
    true ->
      decode(pair, Rest, Struct#enr_v4{kv = [{Key, Value}| KV]});
    false ->
      {error, <<"Signature verification failed">>}
  end;

decode(pair, [Key, Value | Rest], #enr_v4{kv = KV} = Struct) ->
  decode(pair, Rest, Struct#enr_v4{kv = [{Key, Value}| KV]});

decode(pair, [], Struct) ->
  {ok, Struct};

decode(_Stage, _List, _State) ->
  {error, <<"Cannot decode ENR">>}.

verify(Digest, Signature, PubKey) ->
  case libsecp256k1:ecdsa_verify_compact(Digest, Signature, PubKey) of
    ok -> true;
    error -> false;
    {error, _} -> false
  end.

sign(Digest, PrivKey) ->
  {ok, Signature, _RecoveryId} = libsecp256k1:ecdsa_sign_compact(Digest, PrivKey, default, <<>>),
  Signature.

test_compressed() ->
  Msg = <<"Test">>,
  A = crypto:strong_rand_bytes(32),
  {ok, Pubkey} = libsecp256k1:ec_pubkey_create(A, compressed),
  {ok, Signature, _} = libsecp256k1:ecdsa_sign_compact(Msg, A, default, <<>>),
  libsecp256k1:ecdsa_verify_compact(Msg, Signature, Pubkey).

test_vector_struct() ->
  #enr_v4{
     seq = 1,
     kv = [
       {<<"ip">>, binary:decode_hex(<<"7f000001">>)},
       {<<"udp">>, binary:decode_hex(<<"765f">>)}
     ]
  }.

test_vector_privkey() ->
  binary:decode_hex(<<"b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291">>).

test_vector_base64() ->
  <<"enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8">>.

test_vector_decode_base64() ->
  [Encoded] = binary:split(test_vector_base64(), <<"enr:">>, [trim_all]),
  base64:decode(Encoded, #{mode => urlsafe, padding => false}).


to_hex({ok, Bin}) ->
  to_hex(Bin);
to_hex(Bin) when is_binary(Bin) ->
  io_lib:format("~s\n", [[io_lib:format("~2.16.0B ",[X]) || <<X:8>> <= Bin ]]).
