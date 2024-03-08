-module(discv5_routing).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-record(state, {
          table :: ets:table()
         }).

-type state() :: #state{}.

%% API
-export([
         start_link/0
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

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
-spec init([]) -> state().
init([]) ->
  ?LOG_INFO("Starting routing table"),
  Table = ets:new(routing_table, [
                                  named_table,
                                  ordered_set,
                                  protected,
                                  {keypos, 2},
                                  % TODO: collect statistics on read/write
                                  % frequency and update if needed
                                  {read_concurrency, false},
                                  {write_concurrency, false}
                                 ]),
  {ok, #state{table = Table}}.

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

%%%===================================================================
%%% Internal functions
%%%===================================================================

