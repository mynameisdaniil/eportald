-module(discv5_node).

-include_lib("kernel/include/logger.hrl").
-include_lib("../enr/src/enr.hrl").
-include_lib("discv5.hrl").

-behaviour(gen_server).

-define(MAX_32_BIT_INTEGER, 16#FFFFFFFF).

-define(GC_INTERVAL, 60_000). % 1 minute in ms

-define(MAX_IDLE_TIME, 300_000). % 5 minutes in ms

-type session_id() :: {node_id(), gen_udp:ip(), gen_udp:port()}.
-type session_key() :: binary().

-record(state, {
          node_id          :: node_id(),
          enr              :: enr(),
          session_id       :: session_id(),
          session_key      :: session_key(),
          msg_counter = 0  :: non_neg_integer(),
          last_interaction :: non_neg_integer()
         }).

-type state() :: #state{}.

%% API
-export([
         start_link/1
        ]).

%% gen_server callbacks
-export([init/1,
         handle_continue/2,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%%%===================================================================
%%% API
%%%===================================================================

start_link(ENR) ->
  {ok, #enr_v4{kv = KV}} = enr:decode(ENR),
  PubKey = maps:get(<<"secp256k1">>, KV),
  NodeId = enr:compressed_pub_key_to_node_id(PubKey),
  gen_server:start_link({via, gproc, {n, l, NodeId}}, ?MODULE, {NodeId, ENR}, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
-spec init([]) -> state().
init({NodeId, ENR}) ->
  ?LOG_INFO("Starting node: 0x~s", [binary:encode_hex(NodeId, lowercase)]),
  {ok, #state{enr = ENR, node_id = NodeId}, {continue, init_session}}.

handle_continue(init_session, State) ->
  {noreply, State};

handle_continue(Continue, State) ->
  ?LOG_ERROR("Unexpected handle_continue: ~p", [Continue]),
  {noreply, State}.

handle_call(get_node_id, _From, #state{node_id = NodeId} = State) ->
  Reply = {ok, NodeId},
  LastInteraction = erlang:system_time(millisecond),
  {reply, Reply, State#state{last_interaction = LastInteraction}};

handle_call(get_enr, _From, #state{node_id = ENR} = State) ->
  Reply = {ok, ENR},
  LastInteraction = erlang:system_time(millisecond),
  {reply, Reply, State#state{last_interaction = LastInteraction}};

handle_call(get_session, _From, #state{session_key = SessionKey} = State) ->
  Reply = {ok, SessionKey},
  LastInteraction = erlang:system_time(millisecond),
  {reply, Reply, State#state{last_interaction = LastInteraction}};

handle_call(inc_msg_counter, _From, #state{msg_counter = Counter} = State) ->
  case Counter + 1 of
    NewCounter when NewCounter < ?MAX_32_BIT_INTEGER ->
      Reply = {ok, NewCounter},
      LastInteraction = erlang:system_time(millisecond),
      {reply, Reply, State#state{msg_counter = NewCounter, last_interaction = LastInteraction}};
    _ ->
      Reply = {error, msg_counter_overflow},
      LastInteraction = erlang:system_time(millisecond),
      {stop, normal, Reply, State#state{last_interaction = LastInteraction}}
  end;

handle_call(_Request, _From, State) ->
  Reply = {error, unexpected},
  {reply, Reply, State}.

handle_cast(Msg, State) ->
  ?LOG_ERROR("Unexpected handle_cast: ~p", [Msg]),
  {noreply, State}.

handle_info(check_session, State) ->
  #state{
     last_interaction = LastInteraction,
     session_id       = SessionId
    } = State,
  Now = erlang:system_time(millisecond),
  case Now - LastInteraction of
    Diff when Diff =< ?MAX_IDLE_TIME ->
      check_session(),
      {noreply, State};
    _ ->
      % It's been too long, let's end this session
      gproc:unregister({n, l, SessionId}),
      {noreply, State#state{msg_counter = 0, session_id = undefined, session_key = undefined}}
  end;

handle_info(Info, State) ->
  ?LOG_ERROR("Unexpected handle_info: ~p", [Info]),
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

generate_nonce(MsgCounter) ->
  Random = crypto:strong_rand_bytes(8), % 64 bits
  <<MsgCounter:32/big-unsigned-integer-unit:1, Random/binary>>. % 96 bits total

check_session() ->
  Interval = ?GC_INTERVAL + (rand:uniform(?GC_INTERVAL/2) - ?GC_INTERVAL/4),
  erlang:send_after(Interval, check_session).
