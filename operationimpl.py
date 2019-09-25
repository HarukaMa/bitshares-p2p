
from collections import OrderedDict

from basic_types import Uint16, Uint32, Signature, Null, RIPEMD160, VariantObject, Bool, String, Uint8, Int64, \
    PublicKey, Data, SHA256
from generic_types import Optional, Extension, StaticVariant, Vector
from objectids import AccountID, FullObjectID, WitnessID, LimitOrderID, AssetID, ProposalID, VestingBalanceID, \
    WithdrawPermissionID, CommitteeMemberID
from objectimpl import Asset, Memo, EmptyExtension, CallOrderOptions, Authority, AccountOptions, AssetOptions, \
    BitAssetOptions, PriceFeed, LinearVesting, CDDVesting, InstantVesting, Price, WorkerInitializer, \
    Predicate, BlindInput, BlindOutput
from objects import Object
from operations import Operation

class TransferOperation(Operation):

    opid = 0
    definition = OrderedDict([
        ("fee", Asset),
        ("from", AccountID),
        ("to", AccountID),
        ("amount", Asset),
        ("memo", Optional[Memo]),
        ("extensions", Extension[EmptyExtension])
    ])

class LimitOrderCreateOperation(Operation):

    opid = 1
    definition = OrderedDict([
        ("fee", Asset),
        ("seller", AccountID),
        ("amount_to_sell", Asset),
        ("min_to_receive", Asset),
        ("expiration", Uint32),
        ("fill_or_kill", Bool),
        ("extensions", Extension[EmptyExtension])
    ])

class LimitOrderCancelOperation(Operation):
    
    opid = 2
    definition = OrderedDict([
        ("fee", Asset),
        ("order", LimitOrderID),
        ("fee_paying_account", AccountID),
        ("extensions", Extension[EmptyExtension])
    ])
    
class CallOrderUpdateOperation(Operation):
    
    opid = 3
    definition = OrderedDict([
        ("fee", Asset),
        ("funding_account", AccountID),
        ("delta_collateral", Asset),
        ("delta_debt", Asset),
        ("extensions", Extension[CallOrderOptions])
    ])
    
class AccountCreateOperation(Operation):
    
    opid = 5
    definition = OrderedDict([
        ("fee", Asset),
        ("registrar", AccountID),
        ("referrer", AccountID),
        ("referrer_percent", Uint16),
        ("name", String),
        ("owner", Authority),
        ("active", Authority),
        ("options", AccountOptions),
        ("extensions", Extension[EmptyExtension])
    ])
    
class AccountUpdateOperation(Operation):
    
    opid = 6
    definition = OrderedDict([
        ("fee", Asset),
        ("account", LimitOrderID),
        ("owner", Optional[Authority]),
        ("active", Optional[Authority]),
        ("new_options", Optional[AccountOptions]),
        ("extensions", Extension[EmptyExtension])
    ])

class AccountWhitelistOperation(Operation):

    opid = 7
    definition = OrderedDict([
        ("fee", Asset),
        ("authorizing_account", AccountID),
        ("account_to_list", AccountID),
        ("new_listing", Uint8),
        ("extensions", Extension[EmptyExtension]),
    ])

class AccountUpgradeOperation(Operation):

    opid = 8
    definition = OrderedDict([
        ("fee", Asset),
        ("account_to_update", AccountID),
        ("upgrade_to_lifetime_member", Bool),
        ("extensions", Extension[EmptyExtension])
    ])

class AccountTransferOperation(Operation):

    opid = 9
    definition = OrderedDict([
        ("fee", Asset),
        ("account_id", AccountID),
        ("new_owner", AccountID),
        ("extensions", Extension[EmptyExtension])
    ])

class AssetCreateOperation(Operation):
    
    opid = 10
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("symbol", String),
        ("precision", Uint8),
        ("common_options", AssetOptions),
        ("bitasset_opts", Optional[BitAssetOptions]),
        ("is_prediction_market", Bool),
        ("extensions", Extension[EmptyExtension])
    ])
    
class AssetUpdateOperation(Operation):
    
    opid = 11
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("asset_to_update", AssetID),
        ("new_issuer", Optional[AccountID]),
        ("new_options", AssetOptions),
        ("extensions", Extension[EmptyExtension])
    ])

class AssetUpdateBitassetOperation(Operation):

    opid = 12
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("asset_to_update", AssetID),
        ("new_options", BitAssetOptions),
        ("extensions", Extension[EmptyExtension])
    ])

class AssetUpdateFeedProducersOperation(Operation):

    opid = 13
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("asset_to_update", AssetID),
        ("new_feed_producers", Vector[AccountID]),
        ("extensions", Extension[EmptyExtension])
    ])

class AssetIssueOperation(Operation):
    
    opid = 14
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("asset_to_issue", Asset),
        ("issue_to_account", AccountID),
        ("memo", Optional[Memo]),
        ("extensions", Extension[EmptyExtension])
    ])
    
class AssetReserveOperation(Operation):
    
    opid = 15
    definition = OrderedDict([
        ("fee", Asset),
        ("payer", AccountID),
        ("amount_to_reserve", Asset),
        ("extensions", Extension[EmptyExtension])
    ])
    
class AssetFundFeePoolOperation(Operation):
    
    opid = 16
    definition = OrderedDict([
        ("fee", Asset),
        ("from_account", AccountID),
        ("asset_id", AssetID),
        ("amount", Int64),
        ("extensions", Extension[EmptyExtension])
    ])
    
class AssetSettleOperation(Operation):
    
    opid = 17
    definition = OrderedDict([
        ("fee", Asset),
        ("account", AccountID),
        ("amount", Asset),
        ("extensions", Extension[EmptyExtension])
    ])

class AssetGlobalSettleOperation(Operation):

    opid = 18
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("asset_to_settle", AssetID),
        ("settle_price", Price),
        ("extensions", Extension[EmptyExtension]),
    ])

class AssetPublishFeedOperation(Operation):
    
    opid = 19
    definition = OrderedDict([
        ("fee", Asset),
        ("publisher", AccountID),
        ("asset_id", AssetID),
        ("feed", PriceFeed),
        ("extensions", Extension[EmptyExtension])
    ])
    
class WitnessCreateOperation(Operation):
    
    opid = 20
    definition = OrderedDict([
        ("fee", Asset),
        ("witness_account", AccountID),
        ("url", String),
        ("block_signing_key", PublicKey)
    ])
    
class WitnessUpdateOperation(Operation):
    
    opid = 21
    definition = OrderedDict([
        ("fee", Asset),
        ("witness", WitnessID),
        ("witness_account", AccountID),
        ("new_url", Optional[String]),
        ("new_signing_key", Optional[PublicKey])
    ])

class ProposalCreateOperation(Operation):

    opid = 22
    definition = {}
    # Late declaration of definition
    
class ProposalUpdateOperation(Operation):
    
    opid = 23
    definition = OrderedDict([
        ("fee", Asset),
        ("fee_paying_account", AccountID),
        ("proposal", ProposalID),
        ("active_approvals_to_add", Vector[AccountID]),
        ("active_approvals_to_remove", Vector[AccountID]),
        ("owner_approvals_to_add", Vector[AccountID]),
        ("owner_approvals_to_remove", Vector[AccountID]),
        ("key_approvals_to_add", Vector[PublicKey]),
        ("key_approvals_to_remove", Vector[PublicKey]),
        ("extensions", Extension[EmptyExtension])
    ])

class ProposalDeleteOperation(Operation):

    opid = 24
    definition = OrderedDict([
        ("fee", Asset),
        ("fee_paying_account", AccountID),
        ("using_owner_authority", Bool),
        ("proposal", ProposalID),
        ("extensions", Extension[EmptyExtension])
    ])

class WithdrawPermissionCreateOperation(Operation):

    opid = 25
    definition = OrderedDict([
        ("fee", Asset),
        ("withdraw_from_account", AccountID),
        ("authorized_account", AccountID),
        ("withdrawal_limit", Asset),
        ("withdrawal_period_sec", Uint32),
        ("periods_until_expiration", Uint32),
        ("period_start_time", Uint32)
    ])

class WithdrawPermissionUpdateOperation(Operation):

    opid = 26
    definition = OrderedDict([
        ("fee", Asset),
        ("withdraw_from_account", AccountID),
        ("authorized_account", AccountID),
        ("permission_to_update", WithdrawPermissionID),
        ("withdrawal_limit", Asset),
        ("withdrawal_period_sec", Uint32),
        ("period_start_time", Uint32),
        ("periods_until_expiration", Uint32)
    ])

class WithdrawPermissionClaimOperation(Operation):

    opid = 27
    definition = OrderedDict([
        ("fee", Asset),
        ("withdraw_permission", WithdrawPermissionID),
        ("withdraw_from_account", AccountID),
        ("withdraw_to_account", AccountID),
        ("amount_to_withdraw", Asset),
        ("memo", Optional[Memo])
    ])

class WithdrawPermissionDeleteOperation(Operation):

    opid = 28
    definition = OrderedDict([
        ("fee", Asset),
        ("withdraw_from_account", AccountID),
        ("authorized_account", AccountID),
        ("withdraw_permission", WithdrawPermissionID)
    ])

class CommitteeMemberCreateOperation(Operation):

    opid = 29
    definition = OrderedDict([
        ("fee", Asset),
        ("committee_member_account", AccountID),
        ("url", String)
    ])

class CommitteeMemberUpdateOperation(Operation):

    opid = 30
    definition = OrderedDict([
        ("fee", Asset),
        ("committee_member", CommitteeMemberID),
        ("committee_member_account", AccountID),
        ("new_url", Optional[String])
    ])

# TODO: This is not working
class CommitteeMemberUpdateGlobalParametersOperation(Operation):

    opid = 31
    definition = {}
    # Late declaration of definition

class VestingBalanceCreateOperation(Operation):
    
    opid = 32
    definition = OrderedDict([
        ("fee", Asset),
        ("creator", AccountID),
        ("owner", AccountID),
        ("amount", Asset),
        ("policy", StaticVariant[
            LinearVesting,
            CDDVesting,
            InstantVesting
        ])
    ])
    
class VestingBalanceWithdrawOperation(Operation):
    
    opid = 33
    definition = OrderedDict([
        ("fee", Asset),
        ("vesting_balance", VestingBalanceID),
        ("owner", AccountID),
        ("amount", Asset)
    ])

class WorkerCreateOperation(Operation):

    opid = 34
    definition = OrderedDict([
        ("fee", Asset),
        ("owner", AccountID),
        ("work_begin_date", Uint32),
        ("work_end_date", Uint32),
        ("daily_pay", Int64),
        ("name", String),
        ("url", String),
        ("initializer", WorkerInitializer)
    ])

class CustomOperation(Operation):

    opid = 35
    definition = OrderedDict([
        ("fee", Asset),
        ("payer", AccountID),
        ("required_auths", Vector[AccountID]),
        ("id", Uint16),
        ("data", Data),
    ])

class AssertOperation(Operation):

    opid = 36
    definition = OrderedDict([
        ("fee", Asset),
        ("fee_paying_account", AccountID),
        ("predicates", Vector[Predicate]),
        ("required_auths", Vector[AccountID]),
        ("extensions", Extension[EmptyExtension])
    ])
    
class BalanceClaimOperation(Operation):
    
    opid = 37
    definition = OrderedDict([
        ("fee", Asset),
        ("deposit_to_account", AccountID),
        ("balance_to_claim", VestingBalanceID),
        ("balance_owner_key", PublicKey),
        ("total_claimed", Asset)
    ])

class OverrideTransferOperation(Operation):

    opid = 38
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("from", AccountID),
        ("to", AccountID),
        ("amount", Asset)
    ])

class TransferToBlindOperation(Operation):

    opid = 39
    definition = OrderedDict([
        ("fee", Asset),
        ("amount", Asset),
        ("from", AccountID),
        ("blinding_factor", SHA256),
        ("inputs", Vector[BlindInput])
    ])

class BlindTransferOperation(Operation):

    opid = 40
    definition = OrderedDict([
        ("fee", Asset),
        ("inputs", Vector[BlindInput]),
        ("outputs", Vector[BlindOutput])
    ])

class TransferFromBlindOperation(Operation):

    opid = 41
    definition = OrderedDict([
        ("fee", Asset),
        ("amount", Asset),
        ("to", AccountID),
        ("blinding_factor", SHA256),
        ("inputs", Vector[BlindInput])
    ])
    
class AssetClaimFeeOperation(Operation):
    
    opid = 43
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("amount_to_claim", Asset),
        ("extensions", Extension[EmptyExtension])
    ])

class BidCollateralOperation(Operation):

    opid = 45
    definition = OrderedDict([
        ("fee", Asset),
        ("bidder", AccountID),
        ("additional_collateral", Asset),
        ("debt_covered", Asset),
        ("extensions", Extension[EmptyExtension])
    ])
    
class AssetClaimPoolOperation(Operation):
    
    opid = 47
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("asset_id", AssetID),
        ("amount_to_claim", Asset),
        ("extensions", Extension[EmptyExtension])
    ])

class AssetUpdateIssuerOperation(Operation):

    opid = 48
    definition = OrderedDict([
        ("fee", Asset),
        ("issuer", AccountID),
        ("asset_to_update", AssetID),
        ("new_issuer", AccountID),
        ("extensions", Extension[EmptyExtension])
    ])
    
    
OperationVariant = StaticVariant[
    TransferOperation,                  # 0
    LimitOrderCreateOperation,
    LimitOrderCancelOperation,
    CallOrderUpdateOperation,
    type(None),
    AccountCreateOperation,             # 5
    AccountUpdateOperation,
    AccountWhitelistOperation,
    AccountUpgradeOperation,
    AccountTransferOperation,
    AssetCreateOperation,               # 10
    AssetUpdateOperation,
    AssetUpdateBitassetOperation,
    AssetUpdateFeedProducersOperation,
    AssetIssueOperation,
    AssetReserveOperation,              # 15
    AssetFundFeePoolOperation,
    AssetSettleOperation,
    AssetGlobalSettleOperation,
    AssetPublishFeedOperation,
    WitnessCreateOperation,             # 20
    WitnessUpdateOperation,
    ProposalCreateOperation,
    ProposalUpdateOperation,
    ProposalDeleteOperation,
    WithdrawPermissionCreateOperation,  # 25
    WithdrawPermissionUpdateOperation,
    WithdrawPermissionClaimOperation,
    WithdrawPermissionDeleteOperation,
    CommitteeMemberCreateOperation,
    CommitteeMemberUpdateOperation,     # 30
    CommitteeMemberUpdateGlobalParametersOperation,
    VestingBalanceCreateOperation,
    VestingBalanceWithdrawOperation,
    WorkerCreateOperation,
    CustomOperation,                    # 35
    AssertOperation,
    BalanceClaimOperation,
    OverrideTransferOperation,
    TransferToBlindOperation,
    BlindTransferOperation,             # 40
    TransferFromBlindOperation,
    type(None),
    AssetClaimFeeOperation,
    type(None),
    BidCollateralOperation,             # 45
    type(None),
    AssetClaimPoolOperation,
    AssetUpdateIssuerOperation,
    type(None),
    type(None),
    type(None),
    type(None),
    type(None)
]

ProposalCreateOperation.definition = OrderedDict([
        ("fee", Asset),
        ("fee_paying_account", AccountID),
        ("expiration_time", Uint32),
        ("proposed_ops", Vector[OperationVariant]),
        ("review_period_seconds", Optional[Uint32]),
        ("extensions", Extension[EmptyExtension])
    ])

FeeParameters = OperationVariant

class FeeSchedule(Object):

    definition = {
        "parameters": Vector[FeeParameters]
    }

class ChainParameters(Object):

    definition = OrderedDict([
        ("current_fees", FeeSchedule),
        ("block_interval", Uint8),
        ("maintenance_interval", Uint32),
        ("maintenance_skip_slots", Uint8),
        ("committee_proposal_review_period", Uint32),
        ("maximum_transaction_size", Uint32),
        ("maximum_block_size", Uint32),
        ("maximum_time_until_expiration", Uint32),
        ("maximum_proposal_lifetime", Uint32),
        ("maximum_asset_whitelist_authorities", Uint8),
        ("maximum_asset_feed_publishers", Uint8),
        ("maximum_witness_count", Uint16),
        ("maximum_committee_count", Uint16),
        ("maximum_authority_membership", Uint16),
        ("reserve_percent_of_fee", Uint16),
        ("network_percent_of_fee", Uint16),
        ("lifetime_referrer_percent_of_fee", Uint16),
        ("cashback_vesting_period_seconds", Uint32),
        ("cashback_vesting_threshold", Int64),
        ("count_non_member_votes", Bool),
        ("allow_non_member_whitelists", Bool),
        ("witness_pay_per_block", Int64),
        ("witness_pay_vesting_seconds", Uint32),
        ("worker_budget_per_day", Int64),
        ("max_predicate_opcode", Uint16),
        ("fee_liquidation_threshold", Int64),
        ("accounts_per_fee_scale", Uint16),
        ("account_fee_scale_bitshifts", Uint8),
        ("max_authority_depth", Uint8),
    ])

CommitteeMemberUpdateGlobalParametersOperation.definition = OrderedDict([
    ("fee", Asset),
    ("new_parameters", ChainParameters)
])

class PrecomuutableTransaction(Object):
    definition = OrderedDict([
        ("ref_block_num", Uint16),
        ("ref_block_prefix", Uint32),
        ("expiration", Uint32),
        ("operations", Vector[OperationVariant]),
        ("extensions", Extension[EmptyExtension]),
        ("signatures", Vector[Signature])
    ])


OpResult = StaticVariant[Null, FullObjectID, Asset]


class Transaction(Object):
    definition = OrderedDict([
        ("ref_block_num", Uint16),
        ("ref_block_prefix", Uint32),
        ("expiration", Uint32),
        ("operations", Vector[OperationVariant]),
        ("extensions", Extension[EmptyExtension]),
        ("signatures", Vector[Signature]),
        ("operation_results", Vector[OpResult])
    ])


class SignedBlock(Object):
    definition = OrderedDict([
        ("previous", RIPEMD160),
        ("timestamp", Uint32),
        ("witness", WitnessID),
        ("transaction_merkle_root", RIPEMD160),
        ("extensions", Vector[VariantObject]),
        ("witness_signature", Signature),
        ("transactions", Vector[Transaction])
    ])


