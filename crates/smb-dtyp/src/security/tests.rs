use super::*;
use std::str::FromStr;

use binrw::prelude::*;
use smb_tests::*;

/// MS-DTYP 2.4.6 allows the OWNER/GROUP/SACL/DACL sections of a self-relative
/// security descriptor to appear in any order. This helper builds the expected
/// value used by both the Samba-layout (header -> owner -> group -> dacl)
/// roundtrip test and the Azure-layout (header -> dacl -> owner -> group)
/// read-only regression test.
fn make_admin_ace(mask: u32, flags: AceFlags, sid: &str) -> ACE {
    ACE {
        ace_flags: flags,
        value: AceValue::AccessAllowed(AccessAce {
            access_mask: AccessMask::from_bytes(mask.to_le_bytes()),
            sid: SID::from_str(sid).unwrap(),
        }),
    }
}

test_binrw! {
    SecurityDescriptor => owner_group:
    SecurityDescriptor {
        sbz1: 0,
        control: SecurityDescriptorControl::new().with_self_relative(true),
        owner_sid: Some(SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001").unwrap()),
        group_sid: Some(SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001").unwrap()),
        sacl: None,
        dacl: None,
    } => "0100008014000000300000000000000000000000010500000000000515000000173da72e955653f915dff280
    e9030000010500000000000515000000173da72e955653f915dff280e9030000"
}

test_binrw! {
    SecurityDescriptor => dacl_only_sd: SecurityDescriptor {
        sbz1: 0,
        control: SecurityDescriptorControl::new()
            .with_self_relative(true)
            .with_dacl_auto_inherited(true)
            .with_dacl_present(true),
        owner_sid: None,
        group_sid: None,
        sacl: None,
        dacl: ACL {
            acl_revision: AclRevision::Nt4,
            ace: vec![
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                        sid: SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001")
                            .unwrap(),
                    }),
                },
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                        sid: SID::from_str(SID::S_ADMINISTRATORS).unwrap(),
                    }),
                },
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                        sid: SID::from_str(SID::S_LOCAL_SYSTEM).unwrap(),
                    }),
                },
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1200a9u32.to_le_bytes()),
                        sid: SID::from_str(SID::S_EVERYONE).unwrap(),
                    }),
                },
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                        sid: SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1002")
                            .unwrap(),
                    }),
                },
            ],
        }
        .into(),
    } => "0100048400000000000000000000000014000000020090000500000000
    132400ff011f00010500000000000515000000173da72e955653f915dff280
    e903000000131800ff011f0001020000000000052000000020020000001314
    00ff011f0001010000000000051200000000131400a9001200010100000000
    00010000000000132400ff011f00010500000000000515000000173da72e95
    5653f915dff280ea030000"
}

// Samba canonical layout: header -> owner -> group -> dacl. This matches the
// writer's field order, so we can roundtrip with test_binrw!.
test_binrw! {
    SecurityDescriptor => owner_group_dacl_layout: SecurityDescriptor {
        sbz1: 0,
        control: SecurityDescriptorControl::new()
            .with_self_relative(true)
            .with_dacl_present(true),
        owner_sid: Some(SID::from_str(SID::S_LOCAL_SYSTEM).unwrap()),
        group_sid: Some(SID::from_str(SID::S_LOCAL_SYSTEM).unwrap()),
        sacl: None,
        dacl: ACL {
            acl_revision: AclRevision::Nt4,
            ace: vec![make_admin_ace(
                0x1f01ff,
                AceFlags::new(),
                SID::S_ADMINISTRATORS,
            )],
        }
        .into(),
    } => "01000480
    14000000 20000000 00000000 2c000000
    01010000 00000005 12000000
    01010000 00000005 12000000
    02002000 01000000
    00001800 ff011f00 01020000 00000005 20000000 20020000"
}

// Azure Files lays sections out as header -> dacl -> owner -> group, which the
// MS-DTYP spec explicitly allows but the previous reader assumed away. This is
// a read-only test against bytes captured from xraytestdatasources.file.core
// .windows.net; the writer canonicalizes the order so a roundtrip would not
// match.
test_binrw_read! {
    SecurityDescriptor => azure_files_layout: SecurityDescriptor {
        sbz1: 0,
        control: SecurityDescriptorControl::new()
            .with_self_relative(true)
            .with_dacl_present(true),
        owner_sid: Some(SID::from_str(SID::S_LOCAL_SYSTEM).unwrap()),
        group_sid: Some(SID::from_str(SID::S_LOCAL_SYSTEM).unwrap()),
        sacl: None,
        dacl: ACL {
            acl_revision: AclRevision::Nt4,
            ace: vec![
                make_admin_ace(
                    0x1f01ff,
                    AceFlags::new()
                        .with_object_inherit(true)
                        .with_container_inherit(true),
                    SID::S_ADMINISTRATORS,
                ),
                make_admin_ace(
                    0x1f01ff,
                    AceFlags::new()
                        .with_object_inherit(true)
                        .with_container_inherit(true),
                    SID::S_LOCAL_SYSTEM,
                ),
                make_admin_ace(0x1200a9, AceFlags::new(), "S-1-5-32-545"),
                make_admin_ace(
                    0xa0000000,
                    AceFlags::new()
                        .with_object_inherit(true)
                        .with_container_inherit(true)
                        .with_inherit_only(true),
                    "S-1-5-32-545",
                ),
                make_admin_ace(
                    0x1301bf,
                    AceFlags::new()
                        .with_object_inherit(true)
                        .with_container_inherit(true),
                    "S-1-5-11",
                ),
                make_admin_ace(0x1f01ff, AceFlags::new(), SID::S_LOCAL_SYSTEM),
                make_admin_ace(
                    0x10000000,
                    AceFlags::new()
                        .with_object_inherit(true)
                        .with_container_inherit(true)
                        .with_inherit_only(true),
                    "S-1-3-0",
                ),
            ],
        }
        .into(),
    } => "01000480 b4000000 c0000000 00000000 14000000
    0200a000 07000000
    00031800 ff011f00 01020000 00000005 20000000 20020000
    00031400 ff011f00 01010000 00000005 12000000
    00001800 a9001200 01020000 00000005 20000000 21020000
    000b1800 000000a0 01020000 00000005 20000000 21020000
    00031400 bf011300 01010000 00000005 0b000000
    00001400 ff011f00 01010000 00000005 12000000
    000b1400 00000010 01010000 00000003 00000000
    01010000 00000005 12000000
    01010000 00000005 12000000"
}
