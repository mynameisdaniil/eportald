%%%-------------------------------------------------------------------
%% @doc discv5 top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(discv5_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

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
                  #{id       => discv5_udp_listener
                  , start    => {discv5_udp_listener, start_link, [5050, {127, 0, 0, 1}]}
                  , restart  => transient
                  , shutdown => infinity
                  , type     => worker
                  , modules  => [discv5_udp_listener]
                   },
                  #{id       => discv5_routing_table
                  , start    => {discv5_routing_table, start_link, []}
                  , restart  => transient
                  , shutdown => infinity
                  , type     => worker
                  , modules  => [discv5_routing_table]
                   },
                  #{id       => discv5_record_maintainer
                  , start    => {discv5_record_maintainer, start_link, []}
                  , restart  => transient
                  , shutdown => infinity
                  , type     => worker
                  , modules  => [discv5_record_maintainer]
                   }
                 ],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
