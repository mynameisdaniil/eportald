-module(discv5_crypto_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("src/discv5.hrl").



-define(ENCRYPTION_KEY, binary:decode_hex(<<"9f2d77db7004bf8a1a85107ac686990b">>)).
-define(ENCRYPTION_NONCE, binary:decode_hex(<<"27b5af763c446acd2749fe8e">>)).
-define(ENCRYPTION_PAYLOAD, binary:decode_hex(<<"01c20101">>)).
-define(ENCRYPTION_MESSAGE_AD, binary:decode_hex(<<"93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903">>)).
-define(ENCRYPTION_RESULT, binary:decode_hex(<<"a5d12a2d94b8ccb3ba55558229867dc13bfa3648">>)).
encryption_test() ->
  {Encrypted, Tag} = crypto:crypto_one_time_aead(
                       aes_128_gcm,
                       ?ENCRYPTION_KEY,
                       ?ENCRYPTION_NONCE,
                       ?ENCRYPTION_PAYLOAD,
                       ?ENCRYPTION_MESSAGE_AD,
                       ?TAG_LEN,
                       true),
  Result = <<Encrypted/binary, Tag/binary>>,
  ?assertEqual(?ENCRYPTION_RESULT, Result).


-define(PUBLIC_KEY, binary:decode_hex(<<"039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231">>)).
-define(SECRET_KEY, binary:decode_hex(<<"fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736">>)).
-define(SHARED_SECRET, binary:decode_hex(<<"033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e">>)).
ecdh_derivation_test() ->
  {ok, Secret} = libsecp256k1:ec_pubkey_tweak_mul(?PUBLIC_KEY, ?SECRET_KEY),
  ?assertEqual(?SHARED_SECRET, Secret).


-define(EPHEMERAL_KEY, binary:decode_hex(<<"fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736">>)).
-define(DEST_PUBKEY, binary:decode_hex(<<"0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91">>)).
-define(NODE_ID_A, binary:decode_hex(<<"aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb">>)).
-define(NODE_ID_B, binary:decode_hex(<<"bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9">>)).
-define(CHALLENGE_DATA, binary:decode_hex(<<"000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000">>)).
-define(INITIATOR_KEY, binary:decode_hex(<<"dccc82d81bd610f4f76d3ebe97a40571">>)).
-define(RECIPIENT_KEY, binary:decode_hex(<<"ac74bb8773749920b0d3a8881c173ec5">>)).
key_derivation_test() ->
  {ok, Secret} = libsecp256k1:ec_pubkey_tweak_mul(?DEST_PUBKEY, ?EPHEMERAL_KEY),
  NodeIdA = ?NODE_ID_A,
  NodeIdB = ?NODE_ID_B,
  KDFInfo = <<?KDF_INFO_TEXT/binary, NodeIdA/binary, NodeIdB/binary>>,
  % KeyData = hkdf:derive_secrets(sha256, Secret, KDFInfo, ?CHALLENGE_DATA, 32),
  PRK = hkdf:extract(sha256, ?CHALLENGE_DATA, Secret),
  KeyData = hkdf:expand(sha256, PRK, KDFInfo, 32),
  <<InitiatorKey:16/binary, RecipientKey:16/binary>> = KeyData,
  io:format("InitiatorKey: ~p\nRecipientKey: ~p\n", [binary:encode_hex(InitiatorKey), binary:encode_hex(RecipientKey)]),
  ?assertEqual(?INITIATOR_KEY, InitiatorKey),
  ?assertEqual(?RECIPIENT_KEY, RecipientKey).

-define(SIGNING_STATIC_KEY, binary:decode_hex(<<"fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736">>)).
-define(SIGNING_CHALLENGE_DATA, binary:decode_hex(<<"000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000">>)).
-define(SIGNING_EPHEMERAL_PUBKEY, binary:decode_hex(<<"039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231">>)).
-define(SIGNING_NODE_ID_B, binary:decode_hex(<<"bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9">>)).
-define(ID_SIGNATURE, binary:decode_hex(<<"94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6">>)).
id_nonce_signing_test() ->
  ChallengeData = ?SIGNING_CHALLENGE_DATA,
  EphemeralPubkey = ?SIGNING_EPHEMERAL_PUBKEY,
  NodeIdB = ?SIGNING_NODE_ID_B,
  IdSignatureInput = <<?ID_SIGNATURE_TEXT/binary, ChallengeData/binary, EphemeralPubkey/binary, NodeIdB/binary>>,
  Sha256 = crypto:hash(sha256, IdSignatureInput),
  {ok, Signature, _RecoveryId} = libsecp256k1:ecdsa_sign_compact(Sha256, ?SIGNING_STATIC_KEY, default, <<>>), % TODO this should be possible with crypto:sign/4
  ?assertEqual(?ID_SIGNATURE, Signature).
