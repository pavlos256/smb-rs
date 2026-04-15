#![cfg(feature = "test-ndr64")]

mod common;
use common::make_server_connection;
use smb_dtyp::SID;
use smb_rpc::interface::SidNameUse;
use std::str::FromStr;

#[tokio::test]
async fn test_lsar_lookup_well_known_sids() -> smb::Result<()> {
    let (client, path) = make_server_connection("IPC$", None).await?;

    let sids = vec![
        SID::from_str("S-1-1-0").unwrap(),  // Everyone
        SID::from_str("S-1-5-18").unwrap(), // Local System
    ];

    let results = client.lookup_sids(&path.server(), &sids).await?;
    assert_eq!(results.len(), 2);

    // Everyone
    assert_eq!(results[0].name, "Everyone");
    assert_eq!(results[0].sid_type, SidNameUse::WellKnownGroup);

    // Local System
    assert_eq!(results[1].name, "SYSTEM");
    assert_eq!(results[1].sid_type, SidNameUse::WellKnownGroup);
    assert_eq!(results[1].domain, "NT Authority");

    Ok(())
}

#[tokio::test]
async fn test_lsar_lookup_unknown_sid() -> smb::Result<()> {
    let (client, path) = make_server_connection("IPC$", None).await?;

    // A SID that doesn't exist on the server
    let sids = vec![
        SID::from_str("S-1-5-21-1111111111-2222222222-3333333333-9999").unwrap(),
    ];

    let results = client.lookup_sids(&path.server(), &sids).await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].sid_type, SidNameUse::Unknown);

    Ok(())
}
