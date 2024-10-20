-module(discv5_session_keys).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-record(state, {
          table :: ets:table()
         }).

-type state() :: #state{}.

%% API
-export([
         start_link/0,
         get_session_keys_for/1
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

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

 get_session_keys_for(NodeId) ->
   gen_server:call(?MODULE, {get_session_keys_for, NodeId}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init([string()]) -> state().
init([]) ->
  ?LOG_INFO("Starting session keys maintainer"),
  Table = ets:new(?MODULE, [named_table, public, set]),
  {ok, #state{table = Table}}.

handle_call({get_session_keys_for, NodeId}, _From, #state{table = Table} = State) ->
  case ets:lookup(Table, NodeId) of
    [] ->
      {reply, {error, not_found}, State};
    [{_NodeId, SessionKey}] ->
      {reply, {ok, SessionKey}, State}
  end;

handle_call(_Request, _From, State) ->
  Reply = {error, unexpected},
  {reply, Reply, State}.

handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info(Info, State) ->
  ?LOG_ERROR("Unexpected handle_info: ~p", [Info]),
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.
