-module(discv5_session).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-define(SUPERVISOR, discv5_session_sup).

-define(MAX_32_BIT_INTEGER, 16#FFFFFFFF).

-type node_id() :: binary().
-type session_id() :: {node_id(), gen_udp:ip(), gen_udp:port()}.
-type session_key() :: binary().

-record(state, {
          session_id :: session_id(),
          session_key :: session_key(),
          msg_counter :: non_neg_integer()
         }).

-type state() :: #state{}.

%% API
-export([
         start_link/2,
         add_session/2,
         get_session/1,
         inc_msg_counter/1,
         generate_nonce/1
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%%%===================================================================
%%% API
%%%===================================================================

start_link({_NodeId, _IP, _Port} = SessionId, SessionKey) ->
  gen_server:start_link({via, gproc, {n, l, SessionId}}, ?MODULE, {SessionId, SessionKey}, []).

add_session({_NodeId, _IP, _Port} = SessionId, SessionKey) ->
  supervisor:start_child(?SUPERVISOR, [SessionId, SessionKey]).

get_session({_NodeId, _IP, _Port} = SessionId) ->
  case gproc:whereis_name({n, l, SessionId}) of
    undefined -> {error, not_found};
    Pid -> gen_server:call(Pid, get_session)
  end.

inc_msg_counter({_NodeId, _IP, _Port} = SessionId) ->
  case gproc:whereis_name({n, l, SessionId}) of
    undefined -> {error, not_found};
    Pid -> gen_server:call(Pid, inc_msg_counter)
  end.

generate_nonce({_NodeId, _IP, _Port} = SessionId) ->
  case gproc:whereis_name({n, l, nonce}) of
    undefined -> {error, not_found};
    Pid -> gen_server:call(Pid, generate_nonce)
  end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
-spec init({session_id(), session_key()}) -> state().
init({{NodeId, IP, Port} = SessionId, SessionKey}) ->
  ?LOG_INFO("Starting session handler for ~p/~p/~p", [NodeId, IP, Port]),
  {ok, #state{session_key = SessionKey, session_id = SessionId}}.

handle_call(get_session, _From, #state{session_key = SessionKey} = State) ->
  Reply = {ok, SessionKey},
  {reply, Reply, State};

handle_call(inc_msg_counter, _From, #state{msg_counter = Counter} = State) ->
  case Counter + 1 of
    NewCounter when NewCounter < ?MAX_32_BIT_INTEGER ->
      Reply = {ok, NewCounter},
      {reply, Reply, State#state{msg_counter = NewCounter}};
    _ ->
      Reply = {error, msg_counter_overflow},
      {stop, normal, Reply, State}
  end;

handle_call(generate_nonce, _From, #state{msg_counter = MsgCounter} = State) ->
  Random = crypto:strong_rand_bytes(8), % 64 bits
  Nonce = <<MsgCounter:32/big-unsigned-integer-unit:1, Random/binary>>, % 96 bits total
  Reply = {ok, Nonce},
  {reply, Reply, State};

handle_call(_Request, _From, State) ->
  Reply = {error, unexpected},
  {reply, Reply, State}.

handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info(Info, State) ->
  ?LOG_ERROR("Unexpected handle_info: ~p~n", [Info]),
  {noreply, State}.

terminate(_Reason, #state{session_id = SessionId}) ->
  syn:unregister_name(SessionId),
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
