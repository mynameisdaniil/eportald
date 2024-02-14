-module(discv5_record_maintainer).

-include_lib("kernel/include/logger.hrl").
-include_lib("../enr/src/enr.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-define(PRIVKEY_SIZE_BYTES, 32).
-define(ENR_FILENAME, "enr").

-record(state, {
          privkey :: binary(),
          pubkey :: binary(),
          seq :: non_neg_integer()
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
  PrivKey = crypto:strong_rand_bytes(?PRIVKEY_SIZE_BYTES),
  {ok, PubKey} = libsecp256k1:ec_pubkey_create(PrivKey, uncompressed),
  Seq = 0,
  {ok, #state{seq = Seq, privkey = PrivKey, pubkey = PubKey}}.

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


