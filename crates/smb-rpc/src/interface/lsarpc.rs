//! LSAR (Local Security Authority Remote) RPC interface.
//!
//! Implements SID-to-name resolution via the `\lsarpc` named pipe.
//! Uses NDR 2.0 (32-bit) transfer syntax -- most servers (including Samba)
//! do not support NDR64 for this interface.
//!
//! MS-LSAD 3.1.4
//!
//! ## Known limitations
//!
//! Tested with well-known SIDs (0-1 sub-authorities) and unknown SIDs.
//! Not yet tested with:
//! - Domain user/group SIDs with long sub-authority chains (5 sub-authorities).
//!   RPC_SID alignment in request serialization may need padding.
//! - Large batches (50+ SIDs). NDR fragmentation is not handled.
//! - Null Name.Buffer pointers in domain entries (only empty-length seen so far).

use crate::{interface::*, pdu::DceRpcSyntaxId};
use smb_dtyp::make_guid;

use binrw::prelude::*;
use maybe_async::maybe_async;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ACCESS_MASK for LsarOpenPolicy2: allows SID-to-name lookups.
///
/// MS-LSAD 2.2.1.1.2
const POLICY_LOOKUP_NAMES: u32 = 0x0000_0800;

/// NDR20 unique pointer ref_id (non-null).
const REF_ID: u32 = 0x0002_0000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// SID_NAME_USE -- type of the resolved account.
///
/// MS-LSAD 2.2.13
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SidNameUse {
    User,
    Group,
    Domain,
    Alias,
    WellKnownGroup,
    DeletedAccount,
    Invalid,
    Unknown,
    Computer,
    Label,
}

/// A resolved SID name with its type and domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
    pub name: String,
    pub domain: String,
    pub sid_type: SidNameUse,
}

// ---------------------------------------------------------------------------
// LsarOpenPolicy2 (opnum 44) -- NDR20 manual serialization
// ---------------------------------------------------------------------------

struct LsarOpenPolicy2In {
    server_name: String,
}

struct LsarOpenPolicy2Out {
    handle: [u8; 20],
    return_value: u32,
}

impl BinWrite for LsarOpenPolicy2In {
    type Args<'a> = ();
    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        w: &mut W,
        _endian: binrw::endian::Endian,
        _args: (),
    ) -> binrw::BinResult<()> {
        let mut buf = Vec::new();

        // SystemName: [in, unique, string] wchar_t*
        // NDR20: ref_id (u32), then conformant+varying string
        buf.extend_from_slice(&REF_ID.to_le_bytes());
        write_ndr20_string(&mut buf, &self.server_name);

        // ObjectAttributes: embedded struct, all zeros
        // NDR20 layout: Length(u32) + 5 null pointers (u32 each)
        pad_to(&mut buf, 4);
        buf.extend_from_slice(&24u32.to_le_bytes()); // Length
        buf.extend_from_slice(&0u32.to_le_bytes()); // RootDirectory (null)
        buf.extend_from_slice(&0u32.to_le_bytes()); // ObjectName (null)
        buf.extend_from_slice(&0u32.to_le_bytes()); // Attributes
        buf.extend_from_slice(&0u32.to_le_bytes()); // SecurityDescriptor (null)
        buf.extend_from_slice(&0u32.to_le_bytes()); // SecurityQualityOfService (null)

        // DesiredAccess: ACCESS_MASK (u32)
        buf.extend_from_slice(&POLICY_LOOKUP_NAMES.to_le_bytes());

        w.write_all(&buf)?;
        Ok(())
    }
}

impl BinRead for LsarOpenPolicy2Out {
    type Args<'a> = ();
    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        _endian: binrw::endian::Endian,
        _args: (),
    ) -> binrw::BinResult<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let mut off = 0;
        check_bounds(&buf, off, 20)?;
        let mut handle = [0u8; 20];
        handle.copy_from_slice(&buf[off..off + 20]);
        off += 20;
        let return_value = read_u32(&buf, &mut off)?;
        Ok(Self { handle, return_value })
    }
}

impl RpcCall for LsarOpenPolicy2In {
    const OPNUM: u16 = 44;
    type ResponseType = LsarOpenPolicy2Out;
}

// ---------------------------------------------------------------------------
// LsarClose (opnum 0) -- NDR20
// ---------------------------------------------------------------------------

struct LsarCloseIn {
    handle: [u8; 20],
}

#[allow(dead_code)]
struct LsarCloseOut {
    handle: [u8; 20],
    return_value: u32,
}

impl BinWrite for LsarCloseIn {
    type Args<'a> = ();
    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        w: &mut W,
        _endian: binrw::endian::Endian,
        _args: (),
    ) -> binrw::BinResult<()> {
        w.write_all(&self.handle)?;
        Ok(())
    }
}

impl BinRead for LsarCloseOut {
    type Args<'a> = ();
    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        _endian: binrw::endian::Endian,
        _args: (),
    ) -> binrw::BinResult<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let mut off = 0;
        check_bounds(&buf, off, 20)?;
        let mut handle = [0u8; 20];
        handle.copy_from_slice(&buf[off..off + 20]);
        off += 20;
        let return_value = read_u32(&buf, &mut off)?;
        Ok(Self { handle, return_value })
    }
}

impl RpcCall for LsarCloseIn {
    const OPNUM: u16 = 0;
    type ResponseType = LsarCloseOut;
}

// ---------------------------------------------------------------------------
// LsarLookupSids (opnum 15) -- NDR20
//
// Response layout (per-parameter deferral, C706 ch.14):
//
//   [Param 1] ReferencedDomains unique ptr ref_id
//             + immediate referent: LSAPR_REFERENCED_DOMAIN_LIST
//               (Entries, Domains ptr, MaxEntries, deferred Domains array
//                with TI inline + deferred Name.Buffer/Sid per element)
//   [Param 2] TranslatedNames inline struct (top-level ref ptr)
//             Entries, Names unique ptr ref_id
//             + deferred Names array
//               (TN inline + deferred Name.Buffer per element)
//   [Param 3] MappedCount (u32)
//   [Return]  NTSTATUS (u32)
//
// Key NDR20 rules applied:
//   - Top-level pointer params are always reference (no ref_id). C706 ch.14.
//   - pointer_default(unique) makes embedded [size_is] pointer fields unique
//     pointers, NOT conformant arrays. Confirmed by RPC_UNICODE_STRING usage
//     as non-last member (would be illegal if conformant).
//   - SID_NAME_USE is u32 in NDR (enum -> unsigned int).
// ---------------------------------------------------------------------------

struct LsarLookupSidsIn {
    handle: [u8; 20],
    sids: Vec<smb_dtyp::SID>,
}

#[allow(dead_code)]
struct LsarLookupSidsOut {
    domains: Vec<String>,
    names: Vec<LookupSidsEntry>,
    mapped_count: u32,
    return_value: u32,
}

#[derive(Debug, Clone)]
struct LookupSidsEntry {
    sid_type: SidNameUse,
    name: String,
    domain_index: i32,
}

impl BinWrite for LsarLookupSidsIn {
    type Args<'a> = ();
    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        w: &mut W,
        _endian: binrw::endian::Endian,
        _args: (),
    ) -> binrw::BinResult<()> {
        let mut buf = Vec::new();
        let count = self.sids.len() as u32;

        // 1. PolicyHandle (20 bytes)
        buf.extend_from_slice(&self.handle);

        // 2. LSAPR_SID_ENUM_BUFFER (top-level ref ptr, struct inline)
        //    Entries (u32), SidInfo unique ptr (u32)
        buf.extend_from_slice(&count.to_le_bytes());
        buf.extend_from_slice(&REF_ID.to_le_bytes());

        // Deferred: SidInfo conformant array
        buf.extend_from_slice(&count.to_le_bytes()); // max_count
        // Array of LSAPR_SID_INFORMATION: each is { PRPC_SID Sid (u32 ptr) }
        for i in 0..count {
            buf.extend_from_slice(&(REF_ID + (i + 1) * 4).to_le_bytes());
        }
        // Deferred: each RPC_SID
        for sid in &self.sids {
            write_ndr20_rpc_sid(&mut buf, sid);
        }

        // 3. LSAPR_TRANSLATED_NAMES (top-level ref ptr, struct inline)
        //    Entries = 0, Names unique ptr = null
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());

        // 4. LookupLevel: LSAP_LOOKUP_LEVEL (enum -> u32 in NDR)
        //    LsapLookupWksta = 1
        buf.extend_from_slice(&1u32.to_le_bytes());

        // 5. MappedCount (top-level ref ptr, u32 inline) = 0
        buf.extend_from_slice(&0u32.to_le_bytes());

        w.write_all(&buf)?;
        Ok(())
    }
}

impl BinRead for LsarLookupSidsOut {
    type Args<'a> = ();
    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        _endian: binrw::endian::Endian,
        _args: (),
    ) -> binrw::BinResult<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let d = &buf;
        let mut off = 0usize;

        // === Param 1: ReferencedDomains ===
        // Top-level [out] ref ptr (invisible), inner unique ptr ref_id
        let ref_domains_ptr = read_u32(d, &mut off)?;

        let mut domains = Vec::new();
        if ref_domains_ptr != 0 {
            // LSAPR_REFERENCED_DOMAIN_LIST inline:
            //   Entries (u32), Domains unique ptr (u32), MaxEntries (u32)
            let domain_count = read_u32(d, &mut off)?;
            let domains_array_ptr = read_u32(d, &mut off)?;
            let _max_entries = read_u32(d, &mut off)?;

            if domains_array_ptr != 0 {
                // Deferred: Domains conformant array
                let _max_count = read_u32(d, &mut off)?; // max_count

                // LSAPR_TRUST_INFORMATION inline pass
                struct DomainInline {
                    name_length: u16,
                    name_buffer_ptr: u32,
                    sid_ptr: u32,
                }
                let mut domain_inlines = Vec::with_capacity(domain_count as usize);
                for _ in 0..domain_count {
                    let name_length = read_u16(d, &mut off)?;
                    let _name_max_length = read_u16(d, &mut off)?;
                    let name_buffer_ptr = read_u32(d, &mut off)?;
                    let sid_ptr = read_u32(d, &mut off)?;
                    domain_inlines.push(DomainInline {
                        name_length,
                        name_buffer_ptr,
                        sid_ptr,
                    });
                }

                // Deferred pass: Name.Buffer then Sid, per element
                for di in &domain_inlines {
                    if di.name_buffer_ptr != 0 {
                        let name = read_ndr20_unicode_buffer(d, &mut off, di.name_length)?;
                        domains.push(name);
                    } else {
                        domains.push(String::new());
                    }
                    if di.sid_ptr != 0 {
                        skip_ndr20_rpc_sid(d, &mut off)?;
                    }
                }
            }
        }

        // === Param 2: TranslatedNames ===
        // Top-level [in,out] ref ptr (invisible), struct inline
        let translated_count = read_u32(d, &mut off)?;
        let translated_names_ptr = read_u32(d, &mut off)?;

        let mut names = Vec::new();
        if translated_names_ptr != 0 {
            // Deferred: Names conformant array
            let _max_count = read_u32(d, &mut off)?;

            // LSAPR_TRANSLATED_NAME inline pass
            struct NameInline {
                sid_type: u32,
                name_length: u16,
                name_buffer_ptr: u32,
                domain_index: i32,
            }
            let mut name_inlines = Vec::with_capacity(translated_count as usize);
            for _ in 0..translated_count {
                // SID_NAME_USE is u32 in NDR (enum -> unsigned int)
                let sid_type = read_u32(d, &mut off)?;
                let name_length = read_u16(d, &mut off)?;
                let _name_max_length = read_u16(d, &mut off)?;
                let name_buffer_ptr = read_u32(d, &mut off)?;
                let domain_index = read_i32(d, &mut off)?;
                name_inlines.push(NameInline {
                    sid_type,
                    name_length,
                    name_buffer_ptr,
                    domain_index,
                });
            }

            // Deferred pass: Name.Buffer per element
            for ni in &name_inlines {
                let name = if ni.name_buffer_ptr != 0 {
                    read_ndr20_unicode_buffer(d, &mut off, ni.name_length)?
                } else {
                    String::new()
                };
                names.push(LookupSidsEntry {
                    sid_type: sid_name_use_from_u32(ni.sid_type),
                    name,
                    domain_index: ni.domain_index,
                });
            }
        }

        // === Param 3: MappedCount ===
        let mapped_count = read_u32(d, &mut off)?;

        // === Return value ===
        let return_value = read_u32(d, &mut off)?;

        Ok(LsarLookupSidsOut {
            domains,
            names,
            mapped_count,
            return_value,
        })
    }
}

impl RpcCall for LsarLookupSidsIn {
    const OPNUM: u16 = 15;
    type ResponseType = LsarLookupSidsOut;
}

// ---------------------------------------------------------------------------
// Lsar interface
// ---------------------------------------------------------------------------

/// LSAR RPC interface (MS-LSAD).
///
/// Provides SID-to-name resolution via the `\lsarpc` named pipe.
/// Uses NDR 2.0 transfer syntax -- bind with `pipe.bind_ndr20()`.
pub struct Lsar<T>
where
    T: BoundRpcConnection,
{
    bound_pipe: T,
    policy_handle: Option<[u8; 20]>,
}

impl<T> RpcInterface<T> for Lsar<T>
where
    T: BoundRpcConnection,
{
    /// LSAR interface UUID (MS-LSAD 1.9)
    const SYNTAX_ID: DceRpcSyntaxId = DceRpcSyntaxId {
        uuid: make_guid!("12345778-1234-abcd-ef00-0123456789ab"),
        version: 0,
    };

    fn new(bound_pipe: T) -> Self {
        Lsar {
            bound_pipe,
            policy_handle: None,
        }
    }
}

#[maybe_async]
impl<T> Lsar<T>
where
    T: BoundRpcConnection,
{
    /// Opens a policy handle. Called automatically by `lookup_sids` if needed.
    pub async fn open_policy(&mut self, server: &str) -> crate::Result<()> {
        let input = LsarOpenPolicy2In {
            server_name: format!(r"\\{server}"),
        };
        let result = self.bound_pipe.send_receive(input).await?;
        if result.return_value != 0 {
            return Err(crate::SmbRpcError::InvalidResponseData(
                "LsarOpenPolicy2 failed",
            ));
        }
        self.policy_handle = Some(result.handle);
        Ok(())
    }

    /// Resolves SIDs to account names.
    ///
    /// Opens a policy handle automatically if one hasn't been opened yet.
    /// Returns one `ResolvedName` per input SID, in order. SIDs that
    /// couldn't be resolved have `sid_type = Unknown` and an empty name.
    pub async fn lookup_sids(
        &mut self,
        server: &str,
        sids: &[smb_dtyp::SID],
    ) -> crate::Result<Vec<ResolvedName>> {
        if self.policy_handle.is_none() {
            self.open_policy(server).await?;
        }
        let handle = self.policy_handle.unwrap();

        let input = LsarLookupSidsIn {
            handle,
            sids: sids.to_vec(),
        };
        let result = self.bound_pipe.send_receive(input).await?;

        // STATUS_SUCCESS or STATUS_SOME_NOT_MAPPED are acceptable.
        // STATUS_NONE_MAPPED means total failure but we return Unknown entries.
        if result.return_value != 0
            && result.return_value != 0x0000_0107
            && result.return_value != 0xC000_0073
        {
            return Err(crate::SmbRpcError::InvalidResponseData(
                "LsarLookupSids failed",
            ));
        }

        let mut resolved = Vec::with_capacity(result.names.len());
        for entry in &result.names {
            let domain = if entry.domain_index >= 0
                && (entry.domain_index as usize) < result.domains.len()
            {
                result.domains[entry.domain_index as usize].clone()
            } else {
                String::new()
            };
            resolved.push(ResolvedName {
                name: entry.name.clone(),
                domain,
                sid_type: entry.sid_type,
            });
        }
        Ok(resolved)
    }

    /// Closes the policy handle.
    pub async fn close(&mut self) -> crate::Result<()> {
        if let Some(handle) = self.policy_handle.take() {
            let input = LsarCloseIn { handle };
            let _result = self.bound_pipe.send_receive(input).await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NDR20 serialization helpers
// ---------------------------------------------------------------------------

fn pad_to(buf: &mut Vec<u8>, align: usize) {
    let pos = buf.len();
    let pad = (align - (pos % align)) % align;
    buf.extend(std::iter::repeat_n(0u8, pad));
}

/// Write a conformant+varying wide string in NDR20 format.
fn write_ndr20_string(buf: &mut Vec<u8>, s: &str) {
    let chars: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let len = chars.len() as u32;
    // max_count (u32)
    buf.extend_from_slice(&len.to_le_bytes());
    // offset (u32) = 0
    buf.extend_from_slice(&0u32.to_le_bytes());
    // actual_count (u32)
    buf.extend_from_slice(&len.to_le_bytes());
    // data (u16 LE each)
    for &c in &chars {
        buf.extend_from_slice(&c.to_le_bytes());
    }
}

/// Write an RPC_SID in NDR20 format.
fn write_ndr20_rpc_sid(buf: &mut Vec<u8>, sid: &smb_dtyp::SID) {
    let sub_count = sid.sub_authority.len() as u32;
    // max_count (u32) for conformant SubAuthority array
    buf.extend_from_slice(&sub_count.to_le_bytes());
    // Revision (u8)
    buf.push(1);
    // SubAuthorityCount (u8)
    buf.push(sub_count as u8);
    // IdentifierAuthority (6 bytes, big-endian)
    buf.extend_from_slice(&sid.identifier_authority.to_be_bytes()[2..8]);
    // SubAuthority array (u32 LE each)
    for &sub in &sid.sub_authority {
        buf.extend_from_slice(&sub.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// NDR20 deserialization helpers
// ---------------------------------------------------------------------------

fn pad_off(off: &mut usize, align: usize) {
    let pad = (align - (*off % align)) % align;
    *off += pad;
}

fn check_bounds(d: &[u8], off: usize, need: usize) -> binrw::BinResult<()> {
    if off + need > d.len() {
        Err(binrw::Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("need {} bytes at offset {}, have {}", need, off, d.len()),
        )))
    } else {
        Ok(())
    }
}

fn read_u16(d: &[u8], off: &mut usize) -> binrw::BinResult<u16> {
    check_bounds(d, *off, 2)?;
    let v = u16::from_le_bytes([d[*off], d[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn read_u32(d: &[u8], off: &mut usize) -> binrw::BinResult<u32> {
    check_bounds(d, *off, 4)?;
    let v = u32::from_le_bytes([d[*off], d[*off + 1], d[*off + 2], d[*off + 3]]);
    *off += 4;
    Ok(v)
}

fn read_i32(d: &[u8], off: &mut usize) -> binrw::BinResult<i32> {
    check_bounds(d, *off, 4)?;
    let v = i32::from_le_bytes([d[*off], d[*off + 1], d[*off + 2], d[*off + 3]]);
    *off += 4;
    Ok(v)
}

/// Read a conformant+varying u16 buffer in NDR20 format.
fn read_ndr20_unicode_buffer(
    d: &[u8],
    off: &mut usize,
    byte_length: u16,
) -> binrw::BinResult<String> {
    pad_off(off, 4);
    let _max_count = read_u32(d, off)?;
    let _offset = read_u32(d, off)?;
    let actual_count = read_u32(d, off)? as usize;

    let char_len = byte_length as usize / 2;
    let read_len = actual_count.min(char_len);

    check_bounds(d, *off, actual_count * 2)?;
    let mut chars = Vec::with_capacity(read_len);
    for i in 0..read_len {
        let idx = *off + i * 2;
        chars.push(u16::from_le_bytes([d[idx], d[idx + 1]]));
    }
    *off += actual_count * 2;
    pad_off(off, 4);

    String::from_utf16(&chars).map_err(|e| {
        binrw::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    })
}

/// Skip over an RPC_SID in NDR20 format.
fn skip_ndr20_rpc_sid(d: &[u8], off: &mut usize) -> binrw::BinResult<()> {
    pad_off(off, 4);
    let max_count = read_u32(d, off)?;
    // Revision (1) + SubAuthorityCount (1) + IdentifierAuthority (6) = 8
    check_bounds(d, *off, 8)?;
    *off += 8;
    // SubAuthority array: max_count * 4 bytes
    let array_bytes = max_count as usize * 4;
    check_bounds(d, *off, array_bytes)?;
    *off += array_bytes;
    Ok(())
}

fn sid_name_use_from_u32(v: u32) -> SidNameUse {
    match v {
        1 => SidNameUse::User,
        2 => SidNameUse::Group,
        3 => SidNameUse::Domain,
        4 => SidNameUse::Alias,
        5 => SidNameUse::WellKnownGroup,
        6 => SidNameUse::DeletedAccount,
        7 => SidNameUse::Invalid,
        9 => SidNameUse::Computer,
        10 => SidNameUse::Label,
        _ => SidNameUse::Unknown,
    }
}
