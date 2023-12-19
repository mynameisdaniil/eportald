-module(rlp).

-include_lib("rlp.hrl").

%% API exports
-export([encode/1, decode/1, to_hex/1]).

encode(Value) ->
  do_encode(Value).

decode(Binary) ->
  case do_decode(Binary, []) of
    {ok, [Ret]} -> {ok, Ret};
    {error, _} = E -> E
  end.

% byte -> itself
do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value < ?RLP_ZERO ->
  do_decode(Rest, [Value | Acc]);

% 0-55 bytes string
do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value >= ?RLP_ZERO andalso Value =< ?RLP_SHORT_PAYLOAD_BORDER ->
  Length = Value - ?RLP_ZERO,
  case extract_bytes(Length, Rest) of
    {ok, Bytes, Rest2} ->
      do_decode(Rest2, [Bytes | Acc]);
    {error, _} = E -> E
  end;

% string longer than 55 bytes
do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value > ?RLP_SHORT_PAYLOAD_BORDER andalso Value < ?RLP_SHORT_LIST_BORDER ->
  LengthOfLength = Value - ?RLP_SHORT_PAYLOAD_BORDER,
  case extract_bytes(LengthOfLength, Rest) of
    {ok, <<Length:LengthOfLength/big-unsigned-integer-unit:8>>, Rest2} ->
      case extract_bytes(Length, Rest2) of
        {ok, Bytes2, Rest3} ->
          do_decode(Rest3, [Bytes2 | Acc]);
        {error, _} = E -> E
      end;
    {error, _} = E -> E
  end;

% 0-55 bytes list
do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value >= ?RLP_SHORT_LIST_BORDER andalso Value < ?RLP_LONG_LIST_BORDER ->
  Length = Value - ?RLP_SHORT_LIST_BORDER,
  case extract_bytes(Length, Rest) of
    {ok, Bytes, Rest2} ->
      %TODO I don't really like this recursion
      % as it potentially can blow up the stack
      case do_decode(Bytes, []) of
        {ok, Decoded} ->
          do_decode(Rest2, [lists:reverse(Decoded) | Acc]);
        {error, _} = E -> E
      end;
    {error, _} = E -> E
  end;

do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value >= ?RLP_LONG_LIST_BORDER ->
  LengthOfLength = Value - ?RLP_LONG_LIST_BORDER,
  case extract_bytes(LengthOfLength, Rest) of
    {ok, <<Length:LengthOfLength/big-unsigned-integer-unit:8>>, Rest2} ->
      case extract_bytes(Length, Rest2) of
        {ok, Bytes2, Rest3} ->
          % TODO same as above
          case do_decode(Bytes2, []) of
            {ok, Decoded} ->
              do_decode(Rest3, [lists:reverse(Decoded) | Acc]);
            {error, _} = E -> E
          end;
        {error, _} = E -> E
      end;
    {error, _} = E -> E
  end;

do_decode(<<>>, Acc) ->
  {ok, Acc};

do_decode(Binary, Acc) ->
  io:format("Unexpected binary: ~p\n>>>~p\n", [Binary, Acc]),
  {error, <<"Invalid RLP">>}.

extract_bytes(Len, Binary) ->
  case Binary of
    <<Bytes:Len/binary, Rest/binary>> ->
      {ok, Bytes, Rest};
    _ ->
      {error, <<"Invalid RLP">>}
  end.

%% Encode functions

do_encode(<<Byte:1/big-unsigned-integer-unit:8>> = Bin) when Byte < ?RLP_ZERO ->
  {ok, Bin};

do_encode(Integer) when is_integer(Integer) andalso Integer >= 0 andalso Integer < ?RLP_ZERO ->
  {ok, <<Integer:8/big-unsigned-integer>>};

do_encode(String)
  when is_binary(String) ->
  case byte_size(String) of
    Size when Size =< ?RLP_SHORT_LENGTH ->
      EncodedHeader = <<(?RLP_ZERO + Size):8/big-unsigned-integer>>,
      {ok, <<EncodedHeader/binary, String/binary>>};
    Size ->
      LengthOfLength = binary:encode_unsigned(Size, big),
      EncodedHeader =  <<(?RLP_SHORT_PAYLOAD_BORDER + byte_size(LengthOfLength)):8/big-unsigned-integer>>,
      {ok, <<EncodedHeader/binary, LengthOfLength/binary, String/binary >>}
  end;

do_encode(List)
  when is_list(List) ->
  Encoded = lists:map(fun (Item) ->
    {ok, EncodedItem} = do_encode(Item),
    EncodedItem
  end, List),
  Binary = iolist_to_binary(Encoded),
  case byte_size(Binary) of
    Size when Size =< ?RLP_SHORT_LENGTH ->
      EncodedHeader = <<(?RLP_SHORT_LIST_BORDER + Size):8/big-unsigned-integer>>,
      {ok, <<EncodedHeader/binary, Binary/binary>>};
    Size ->
      LengthOfLength = binary:encode_unsigned(Size, big),
      EncodedHeader = <<(?RLP_LONG_LIST_BORDER + byte_size(LengthOfLength)):8/big-unsigned-integer>>,
      {ok, <<EncodedHeader/binary, LengthOfLength/binary, Binary/binary >>}
  end;

do_encode(WTF) ->
  io:format("RLP WTF: ~p~n", [WTF]),
  {error, <<"Can't encode this data">>}.

%% Utils
to_hex({ok, Bin}) ->
  to_hex(Bin);
to_hex(Bin) when is_binary(Bin) ->
  io:format("~s\n", [[io_lib:format("~2.16.0B ",[X]) || <<X:8>> <= Bin ]]).
