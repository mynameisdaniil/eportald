-module(enr_codec).

-export([
         encode/3,
         decode/1,
         decode_rlp/1,
         compressed_pub_key_to_node_id/1
        ]).

-include_lib("enr.hrl").

-opaque enr_v4() :: #enr_v4{}.
-export_type([enr_v4/0]).

-type priv_key() :: binary().
-type kv() :: proplists:proplist().
-type seq() :: non_neg_integer().

compressed_pub_key_to_node_id(PubKey) ->
  {ok, <<_:1/binary, X:32/binary, Y:32/binary>>} = libsecp256k1:ec_pubkey_decompress(PubKey),
  keccak:keccak_256(<<X/binary, Y/binary>>).

-spec encode(seq(), kv(), priv_key()) -> {ok, binary()} | {error, binary()}.
% TODO do a PubKey version of this method
encode(Seq, KV, PrivKey) ->
  {ok, PubKey} = libsecp256k1:ec_pubkey_create(PrivKey, compressed),
  Combined = maps:merge(KV, #{<<"id">> => <<"v4">>, <<"secp256k1">> => PubKey}),
  SortedKV = lists:sort(fun ({A, _}, {B, _}) -> A > B end, maps:to_list(Combined)),
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
  % decode(pair, Rest, Struct#enr_v4{kv = [{<<"id">>, ID} | []]});
  decode(pair, Rest, Struct#enr_v4{kv = #{<<"id">> => ID}});

decode(pair,
       [<<"secp256k1">> = Key, Value | Rest],
       #enr_v4{kv = KV, signature = Signature, content_hash = ContentHash} = Struct) ->
  case verify(ContentHash, Signature, Value) of
    true ->
      KV1 = maps:put(Key, Value, KV),
      decode(pair, Rest, Struct#enr_v4{kv = KV1});
    false ->
      {error, <<"Signature verification failed">>}
  end;

decode(pair, [Key, Value | Rest], #enr_v4{kv = KV} = Struct) ->
  KV1 = maps:put(Key, Value, KV),
  decode(pair, Rest, Struct#enr_v4{kv = KV1});

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
