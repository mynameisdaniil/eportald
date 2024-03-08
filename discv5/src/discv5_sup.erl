%%%-------------------------------------------------------------------
%% @doc discv5 top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(discv5_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

-define(TIMEOUT, 5000).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
init([]) ->
    SupFlags = #{strategy => one_for_all,
                 intensity => 0,
                 period => 1},
    ChildSpecs = [
                  #{id       => discv5_routing
                  , start    => {discv5_routing, start_link, []}
                  , restart  => transient
                  , shutdown => ?TIMEOUT
                  , type     => worker
                  , modules  => [discv5_routing]
                   },
                  #{id       => discv5_session_sup
                  , start    => {discv5_session_sup, start_link, []}
                  , restart  => transient
                  , shutdown => infinity
                  , type     => supervisor
                  , modules  => [discv5_session_sup]
                   },
                  #{id       => discv5_udp_listener
                  , start    => {discv5_udp_listener, start_link, [5050, {127, 0, 0, 1}]}
                  , restart  => transient
                  , shutdown => ?TIMEOUT
                  , type     => worker
                  , modules  => [discv5_udp_listener]
                   }
                 ],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
