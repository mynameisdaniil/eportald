-module(discv5_bootstrap).

-include_lib("kernel/include/logger.hrl").
-include_lib("discv5.hrl").

-define(SERVER, ?MODULE).

-record(state, {}).

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
  ?LOG_INFO("Starting bootstrap..."),
  self() ! do_add_bootstrap_nodes,
  {ok, #state{}}.

handle_call(_Request, _From, State) ->
  Reply = {error, unexpected},
  {reply, Reply, State}.

handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info(do_add_bootstrap_nodes, State) ->
  ?LOG_INFO("Starting bootstrap nodes..."),
  BoostrapNodes = application:get_env(?APP, bootstrap_nodes, []),
  [supervisor:start_child(?NODE_SUP, [ENR]) || ENR <- BoostrapNodes],
  self() ! do_exit,
  {stop, normal, State};

handle_info(do_exit, State) ->
  ?LOG_INFO("Finishing bootstrap"),
  {stop, normal, State};

handle_info(Info, State) ->
  ?LOG_ERROR("Unexpected handle_info: ~p", [Info]),
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.
