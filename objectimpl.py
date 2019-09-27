
from collections import OrderedDict

from basic_types import (
    IPEndpoint, Uint32, Int64, PublicKey, Uint8, RIPEMD160, Uint16, Uint64, Data, String, VoteID, FakePublicKey)
from generic_types import Vector, Extension, Map, StaticVariant, Optional
from objectids import AssetID, AccountID
from objects import Object


# separate file to avoid circular imports


class EmptyExtension(Object):

    definition = {}

class Address(Object):

    definition = OrderedDict([
        ("remote_endpoint", IPEndpoint),
        ("last_seen_time", Uint32),
        ("latency", Int64),
        ("node_id", FakePublicKey),
        ("direction", Uint8),
        ("firewalled", Uint8)
    ])

    def __repr__(self):
        return "%s%s" % (repr(self["remote_endpoint"]), ", open" if self["firewalled"].data == 2 else "")

class Asset(Object):

    definition = OrderedDict([
        ("amount", Int64),
        ("asset_id", AssetID)
    ])

class Memo(Object):

    definition = OrderedDict([
        ("from", PublicKey),
        ("to", PublicKey),
        ("nonce", Uint64),
        ("message", Data)
    ])

class Price(Object):

    definition = OrderedDict([
        ("base", Asset),
        ("quote", Asset)
    ])

class PriceFeed(Object):

    definition = OrderedDict([
        ("settlement_price", Price),
        ("maintenance_collateral_ratio", Uint16),
        ("maximum_short_squeeze_ratio", Uint16),
        ("core_exchange_rate", Price),
    ])

class Authority(Object):

    definition = OrderedDict([
        ("weight_threshold", Uint32),
        ("account_auths", Map[AccountID, Uint16]),
        ("key_auths", Map[PublicKey, Uint16]),
        ("address_auths", Map[RIPEMD160, Uint16]),
    ])

class AccountOptions(Object):

    definition = OrderedDict([
        ("memo_key", PublicKey),
        ("voting_account", AccountID),
        ("num_witness", Uint16),
        ("num_committee", Uint16),
        ("votes", Vector[VoteID]),
        ("extensions", Extension[EmptyExtension]),
    ])

class CallOrderOptions(Object):

    definition = {
        "target_collateral_ratio": Uint16
    }

class LinearVesting(Object):

    definition = OrderedDict([
        ("begin_timestamp", Uint32),
        ("vesting_cliff_seconds", Uint32),
        ("vesting_duration_seconds", Uint32),
    ])

class CDDVesting(Object):

    definition = OrderedDict([
        ("start_claim", Uint32),
        ("vesting_seconds", Uint32),
    ])

class InstantVesting(Object):

    definition = {}

class AdditionalAssetOptions(Object):

    definition = OrderedDict([
        ("reward_percent", Uint16),
        ("whitelist_market_fee_sharing", Vector[AccountID]),
    ])

class AssetOptions(Object):

    definition = OrderedDict([
        ("max_supply", Int64),
        ("market_fee_percent", Uint16),
        ("max_market_fee", Int64),
        ("issuer_permissions", Uint16),
        ("flags", Uint16),
        ("core_exchange_rate", Price),
        ("whitelist_authorities", Vector[AccountID]),
        ("blacklist_authorities", Vector[AccountID]),
        ("whitelist_markets", Vector[AssetID]),
        ("blacklist_markets", Vector[AssetID]),
        ("description", String),
        ("extensions", Extension[AdditionalAssetOptions]),
    ])

class BitAssetOptions(Object):

    definition = OrderedDict([
        ("feed_lifetime_sec", Uint16),
        ("minimum_feeds", Uint8),
        ("force_settlement_delay_sec", Uint32),
        ("force_settlement_offset_percent", Uint16),
        ("maximum_force_settlement_volume", Uint16),
        ("short_backing_asset", AssetID),
        ("extensions", Extension[EmptyExtension]),
    ])

class RefundWorkerInitializer(Object):

    definition = {}

class VestingBalanceWorkerInitializer(Object):

    definition = {
        "pay_vesting_period_days": Uint16
    }

class BurnWorkerInitializer(Object):

    definition = {}

WorkerInitializer = StaticVariant[
    RefundWorkerInitializer,
    VestingBalanceWorkerInitializer,
    BurnWorkerInitializer
]

class AccountNameEqLitPredicate(Object):

    definition = OrderedDict([
        ("account_id", AccountID),
        ("name", String)
    ])

class AssetSymbolEqLitPredicate(Object):

    definition = OrderedDict([
        ("asset_id", AssetID),
        ("symbol", String)
    ])

class BlockIDPredicate(Object):

    definition = {
        "id", RIPEMD160
    }

Predicate = StaticVariant[
    AccountNameEqLitPredicate,
    AssetSymbolEqLitPredicate,
    BlockIDPredicate
]

# names may be very wrong here

class BlindInput(Object):

    definition = OrderedDict([
        ("commitment", PublicKey),
        ("owner", Authority)
    ])

class StealthConfirmation(Object):

    definition = OrderedDict([
        ("one_time_key", PublicKey),
        ("to", Optional[PublicKey]),
        ("encrypted_memo", Data)
    ])

class BlindOutput(Object):

    definition = OrderedDict([
        ("commitment", PublicKey),
        ("range_proof", Data),
        ("owner", Authority),
        ("stealth_memo", Optional[StealthConfirmation])
    ])