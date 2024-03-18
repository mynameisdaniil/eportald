-module(discv5_node).

-include_lib("kernel/include/logger.hrl").
-include_lib("../enr/src/enr.hrl").
-include_lib("discv5.hrl").

-define(WHOAREYOU_TIMEOUT, 1000).
-define(COOLDOWN_TIMEOUT, rand:uniform(1000) + 1000). % 1 to 2 seconds

-behaviour(gen_statem).

-record(data, {
          node_id                  :: node_id(),
          enr                      :: enr:enr_v4(),
          loaded_from_disk = false :: boolean(),
          nonce                    :: nonce(),
          whoareyou_msg            :: #whoareyou_message{}
         }).

-type data() :: #data{}.

%% API
-export([
         start_link/1
        ]).

%% gen_statem callbacks
-export([
         callback_mode/0,
         init/1,
         terminate/3
        ]).

%% states
-export([
         initial_state/3,
         begin_handshake/3,
         await_whoareyou/3,
         cooldown_before_retry/3,
         process_challenge/3,
         session_established/3
        ]).

%%%===================================================================
%%% API
%%%===================================================================

start_link(ENR) ->
  {ok, #enr_v4{kv = KV}} = enr:decode(ENR),
  PubKey = maps:get(<<"secp256k1">>, KV),
  NodeId = enr:compressed_pub_key_to_node_id(PubKey),
  gen_statem:start_link({via, gproc, {n, l, NodeId}}, ?MODULE, {NodeId, ENR}, []).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================
-spec callback_mode() -> gen_statem:callback_mode().
callback_mode() ->
  state_functiuons.

init({NodeId, EnrStr}) ->
  ?LOG_INFO("Starting discv5 node with NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  case enr:decode(EnrStr) of
    {ok, Enr} ->
      {ok, initial_state, #data{node_id = NodeId, enr = Enr, loaded_from_disk = false}};
    {error, Reason} ->
      {stop, Reason}
  end.

terminate(_Reason, _State, _Data) ->
  ok.

initial_state(enter, _OldState, #data{loaded_from_disk = false} = Data) ->
  {next_state, begin_handshake, Data}.

begin_handshake(enter, _OldState, #data{node_id = NodeId} = Data) ->
  ?LOG_INFO("1. Starting handshake with NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  Nonce = discv5_codec:nonce(),
  %TODO send FINDNODE
  gproc:reg({n, l, {nonce, Nonce}}, self()),
  {next_state, await_whoareyou, Data#data{nonce = Nonce},
   [{state_timeout, ?WHOAREYOU_TIMEOUT, initial_state}]}.

await_whoareyou(state_timeout, initial_state, #data{nonce = Nonce, node_id = NodeId} = Data) ->
  ?LOG_ERROR("Timeout waiting for WHOAREYOU from NodeId: 0x~p",
             [binary:encode_hex(NodeId, lowercase)]),
  gproc:unreg({n, l, {nonce, Nonce}}),
  {next_state, cooldown_before_retry, Data#data{nonce = undefined},
   [state_timeout, ?COOLDOWN_TIMEOUT, cooldown]};

await_whoareyou(info, #whoareyou_message{} = Msg, #data{node_id = NodeId} = Data) ->
  ?LOG_INFO("2. Received WHOAREYOU from NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  {next_state, process_challenge, Data#data{nonce = undefined, whoareyou_msg = Msg}}.

cooldown_before_retry(state_timeout, cooldown, #data{node_id = NodeId} = Data) ->
  ?LOG_INFO("Retrying handshake with NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  {next_state, begin_handshake, Data}.

process_challenge(enter, _OldState, #data{node_id = NodeId, whoareyou_msg = WhoareyouMsg} = Data) ->
  ?LOG_INFO("3. Processing challenge from NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  %TODO process challenge
  {next_state, session_established, Data}.

session_established(enter, _OldState, #data{node_id = NodeId}) ->
  ?LOG_INFO("Session established with NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  keep_state_and_data;

session_established(info, #ordinary_message{} = Msg, #data{node_id = NodeId} = Data) ->
  ?LOG_INFO("4. Processing reply from NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  keep_state_and_data.

