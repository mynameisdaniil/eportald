-module(rlp_basic_test).

-include_lib("eunit/include/eunit.hrl").

-include_lib("src/rlp.hrl").

-define(DOG_STR, <<16#83, "dog">>).
-define(CAT_DOG_LIST, <<16#c8, 16#83, "cat", 16#83, "dog">>).
-define(EMPTY_STRING, <<16#80>>).
-define(EMPTY_LIST, <<16#c0>>).
-define(ENCODED_INTEGER_0, <<16#00>>).
-define(ENCODED_INTEGER_15, <<16#0f>>).
-define(ENCODED_INTEGER_1024, <<16#82, 16#04, 16#00>>).
-define(SET_THEORETICAL_OF_THREE, <<16#c7, 16#c0, 16#c1, 16#c0, 16#c3, 16#c0, 16#c1, 16#c0>>).
-define(STRING_LOREM_IPSUM, <<16#b8, 16#38, "Lorem ipsum dolor sit amet, consectetur adipisicing elit">>).


decode_test() ->
  {ok, <<"dog">>} = rlp:decode(?DOG_STR),
  {ok, [<<"cat">>, <<"dog">>]} = rlp:decode(?CAT_DOG_LIST),
  {ok, <<"">>} = rlp:decode(?EMPTY_STRING),
  {ok, []} = rlp:decode(?EMPTY_LIST),
  {ok, 0} = rlp:decode(?ENCODED_INTEGER_0),
  {ok, 15} = rlp:decode(?ENCODED_INTEGER_15),
  {ok, <<16#04, 16#00>>} = rlp:decode(?ENCODED_INTEGER_1024),
  {ok, [ [], [[]], [ [], [[]] ] ]} = rlp:decode(?SET_THEORETICAL_OF_THREE),
  {ok, <<"Lorem ipsum dolor sit amet, consectetur adipisicing elit">>} = rlp:decode(?STRING_LOREM_IPSUM).

encode_test() ->
  {ok, <<16#83, "dog">>} = rlp:encode(<<"dog">>),
  {ok, <<16#c8, 16#83, "cat", 16#83, "dog">>} = rlp:encode([<<"cat">>, <<"dog">>]),
  {ok, <<16#80>>} = rlp:encode(<<"">>),
  {ok, <<16#c0>>} = rlp:encode([]),
  {ok, <<16#00>>} = rlp:encode(binary:encode_unsigned(0, big)),
  {ok, <<16#0f>>} = rlp:encode(binary:encode_unsigned(15, big)),
  {ok, <<16#82, 16#04, 16#00>>} = rlp:encode(binary:encode_unsigned(1024, big)),
  {ok, <<16#c7, 16#c0, 16#c1, 16#c0, 16#c3, 16#c0, 16#c1, 16#c0>>} = rlp:encode([ [], [[]], [ [], [[]] ] ]),
  {ok, <<16#b8, 16#38, "Lorem ipsum dolor sit amet, consectetur adipisicing elit">>} = rlp:encode(<<"Lorem ipsum dolor sit amet, consectetur adipisicing elit">>).
