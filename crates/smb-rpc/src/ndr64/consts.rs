use smb_dtyp::make_guid;

use crate::pdu::DceRpcSyntaxId;

pub const NDR64_SYNTAX_ID: DceRpcSyntaxId = DceRpcSyntaxId {
    uuid: make_guid!("71710533-beba-4937-8319-b5dbef9ccc36"),
    version: 1,
};

/// NDR 2.0 (32-bit) transfer syntax.
///
/// Used by RPC interfaces that don't support NDR64 (e.g. LSAR on Samba).
pub const NDR20_SYNTAX_ID: DceRpcSyntaxId = DceRpcSyntaxId {
    uuid: make_guid!("8a885d04-1ceb-11c9-9fe8-08002b104860"),
    version: 2,
};
