-ifndef(ENR).

-type enr_seq() :: non_neg_integer().

-record(enr_v4, {
  signature    = <<>> :: nonempty_binary(),
  content_hash = <<>> :: nonempty_binary(),
  seq          = 0    :: enr_seq(),
  kv           = []   :: list(tuple())
}).

-type enr() :: binary().

-define(ENR, 1).
-endif.
