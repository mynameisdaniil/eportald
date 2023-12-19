-ifndef(ENR).

-record(enr_v4, {
  signature    = <<>> :: nonempty_binary(),
  content_hash = <<>> :: nonempty_binary(),
  seq          = 0 :: non_neg_integer(),
  kv           = [] :: list(tuple())
}).

-define(ENR, 1).
-endif.
