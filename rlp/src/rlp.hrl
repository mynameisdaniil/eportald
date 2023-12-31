-ifndef(RLP_CONSTANTS).

-define(RLP_ZERO, 16#80).
-define(RLP_SHORT_PAYLOAD_BORDER, 16#B7).
-define(RLP_SHORT_LIST_BORDER, 16#C0).
-define(RLP_LONG_LIST_BORDER, 16#F7).

-define(RLP_SHORT_LENGTH, 55).

-define(RLP_CONSTANTS, 1).

-type rlp() :: binary().

-endif.
