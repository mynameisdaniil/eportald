-module(discv5_session).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-define(SUPERVISOR, discv5_session_sup).

-type node_id() :: binary().
-type session_id() :: {node_id(), gen_udp:ip(), gen_udp:port()}.
-type session() :: any(). % TODO define the type of this

-record(state, {
          session_id :: session_id(),
          session :: session()
         }).

-type state() :: #state{}.

%% API
-export([
         start_link/2,
         add_session/2,
         get_session/1
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

start_link({_NodeId, _IP, _Port} = SessionId, Session) ->
  gen_server:start_link({via, gproc, {n, l, SessionId}}, ?MODULE, {SessionId, Session}, []).

add_session({_NodeId, _IP, _Port} = SessionId, Session) ->
  supervisor:start_child(?SUPERVISOR, [SessionId, Session]).

get_session({_NodeId, _IP, _Port} = SessionId) ->
  case gproc:whereis_name({n, l, SessionId}) of
    undefined -> {error, not_found};
    Pid -> gen_server:call(Pid, get_session)
  end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
-spec init({session_id(), session()}) -> state().
init({{NodeId, IP, Port} = SessionId, Session}) ->
  ?LOG_INFO("Starting session holder for ~p/~p/~p", [NodeId, IP, Port]),
  {ok, #state{session = Session, session_id = SessionId}}.

handle_call(get_session, _From, State) ->
  {reply, {ok, State#state.session}, State};

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
