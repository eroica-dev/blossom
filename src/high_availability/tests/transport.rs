//! Authenticated HA transport, timeout, and broadcast tests.

use super::*;

#[tokio::test]
async fn isolated_tcp_profile_serves_handshake_and_parameter_bound_status() {
    let mut nodes = runtimes(2);
    let peer_handshake = nodes[1].handshake();
    let server_runtime = nodes.remove(0);
    let server_key = server_runtime
        .members()
        .member(server_runtime.self_slot())
        .unwrap()
        .public_key();
    let expected_parameters_hash = server_runtime.parameters_hash();
    let transport_key = HaTransportKey::new([7; HA_TRANSPORT_KEY_BYTES]);
    let client = HighAvailabilityTcpClient::for_runtime(&nodes[0], transport_key.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key).unwrap();
    let task = tokio::spawn(server.serve(listener));
    let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);

    let status = client.status(&service).await.unwrap();
    assert_eq!(status.parameters_hash, expected_parameters_hash);

    let receipt = client
        .send_message(&service, HaMessage::Handshake(peer_handshake))
        .await
        .unwrap();
    assert_eq!(receipt.kind, "handshake_accepted");
    task.abort();
}

#[tokio::test]
async fn ha_transport_rejects_raw_clients_and_wrong_keys() {
    let mut nodes = runtimes(2);
    let server_runtime = nodes.remove(0);
    let server_key = server_runtime
        .members()
        .member(server_runtime.self_slot())
        .unwrap()
        .public_key();
    let transport_key = HaTransportKey::new([11; HA_TRANSPORT_KEY_BYTES]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key).unwrap();
    let task = tokio::spawn(server.serve(listener));
    let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);

    let mut raw_stream = TcpStream::connect(service.socket_addr()).await.unwrap();
    write_frame(&mut raw_stream, &HaWireRequest::Status)
        .await
        .unwrap();
    assert!(
        read_frame::<HaWireResponse, _>(&mut raw_stream)
            .await
            .is_err()
    );

    let wrong_key_client = HighAvailabilityTcpClient::for_runtime(
        &nodes[0],
        HaTransportKey::new([12; HA_TRANSPORT_KEY_BYTES]),
    );
    assert!(wrong_key_client.status(&service).await.is_err());
    task.abort();
}

#[tokio::test]
async fn ha_transport_binds_protocol_sender_to_authenticated_peer() {
    let mut nodes = runtimes(3);
    let spoofed_handshake = nodes[2].handshake();
    let server_runtime = nodes.remove(0);
    let server_key = server_runtime
        .members()
        .member(server_runtime.self_slot())
        .unwrap()
        .public_key();
    let transport_key = HaTransportKey::new([21; HA_TRANSPORT_KEY_BYTES]);
    let client = HighAvailabilityTcpClient::for_runtime(&nodes[0], transport_key.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key).unwrap();
    let task = tokio::spawn(server.serve(listener));
    let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);

    let error = client
        .send_message(&service, HaMessage::Handshake(spoofed_handshake))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("sender does not match authenticated transport peer")
    );
    task.abort();
}

#[tokio::test]
async fn ha_transport_times_out_a_blackholed_peer() {
    let nodes = runtimes(2);
    let server_key = nodes[0]
        .members()
        .member(nodes[0].self_slot())
        .unwrap()
        .public_key();
    let context = HaTransportContext::from_runtime(&nodes[1]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let blackhole = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);
    let limits = HaNetworkLimits {
        connect_timeout: Duration::from_millis(100),
        request_timeout: Duration::from_millis(20),
        idle_timeout: Duration::from_millis(100),
        max_connections: 2,
    };
    let error = match HaAuthenticatedConnection::connect(
        &service,
        &context,
        &HaTransportKey::new([44; HA_TRANSPORT_KEY_BYTES]),
        limits,
    )
    .await
    {
        Ok(_) => panic!("blackholed peer unexpectedly completed the HA handshake"),
        Err(error) => error,
    };
    assert!(
        matches!(error, BlossomError::ExternalService(message) if message.contains("timed out"))
    );
    blackhole.abort();
}

#[tokio::test]
async fn ha_transport_rejects_replayed_session_sequence() {
    let mut nodes = runtimes(2);
    let server_runtime = nodes.remove(0);
    let server_key = server_runtime
        .members()
        .member(server_runtime.self_slot())
        .unwrap()
        .public_key();
    let transport_key = HaTransportKey::new([31; HA_TRANSPORT_KEY_BYTES]);
    let context = HaTransportContext::from_runtime(&nodes[0]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server =
        HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key.clone()).unwrap();
    let task = tokio::spawn(server.serve(listener));
    let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);
    let mut connection = HaAuthenticatedConnection::connect(
        &service,
        &context,
        &transport_key,
        HaNetworkLimits::default(),
    )
    .await
    .unwrap();
    let body = HaAuthenticatedRequestBody {
        session_id: connection.session_id,
        sequence: 1,
        request: HaWireRequest::Status,
    };
    let request = HaAuthenticatedRequest {
        mac: ha_transport_mac(&connection.session_key, HA_TRANSPORT_REQUEST_DOMAIN, &body).unwrap(),
        body,
    };

    write_frame(&mut connection.stream, &request).await.unwrap();
    let first: HaAuthenticatedResponse = read_frame(&mut connection.stream).await.unwrap();
    assert_eq!(first.body.sequence, 1);
    verify_ha_transport_mac(
        &connection.session_key,
        HA_TRANSPORT_RESPONSE_DOMAIN,
        &first.body,
        &first.mac,
    )
    .unwrap();

    write_frame(&mut connection.stream, &request).await.unwrap();
    assert!(
        read_frame::<HaAuthenticatedResponse, _>(&mut connection.stream)
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn ha_transport_rejects_frame_modified_after_authentication() {
    let mut nodes = runtimes(2);
    let server_runtime = nodes.remove(0);
    let server_key = server_runtime
        .members()
        .member(server_runtime.self_slot())
        .unwrap()
        .public_key();
    let transport_key = HaTransportKey::new([32; HA_TRANSPORT_KEY_BYTES]);
    let context = HaTransportContext::from_runtime(&nodes[0]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server =
        HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key.clone()).unwrap();
    let task = tokio::spawn(server.serve(listener));
    let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);
    let mut connection = HaAuthenticatedConnection::connect(
        &service,
        &context,
        &transport_key,
        HaNetworkLimits::default(),
    )
    .await
    .unwrap();
    let authenticated_body = HaAuthenticatedRequestBody {
        session_id: connection.session_id,
        sequence: 1,
        request: HaWireRequest::Status,
    };
    let mut request = HaAuthenticatedRequest {
        mac: ha_transport_mac(
            &connection.session_key,
            HA_TRANSPORT_REQUEST_DOMAIN,
            &authenticated_body,
        )
        .unwrap(),
        body: authenticated_body,
    };
    request.body.request = HaWireRequest::Health;

    write_frame(&mut connection.stream, &request).await.unwrap();
    assert!(
        read_frame::<HaAuthenticatedResponse, _>(&mut connection.stream)
            .await
            .is_err()
    );
    task.abort();
}

#[test]
fn authenticated_ha_process_worker() {
    if std::env::var("BLOSSOM_HA_PROCESS_WORKER").as_deref() != Ok("1") {
        return;
    }
    let path = std::env::var_os("BLOSSOM_HA_PROCESS_PATH")
        .map(std::path::PathBuf::from)
        .expect("worker durable path");
    let port = std::env::var("BLOSSOM_HA_PROCESS_PORT")
        .expect("worker port")
        .parse::<u16>()
        .expect("numeric worker port");
    let transport_key = HaTransportKey::from_hex(
        &std::env::var("BLOSSOM_HA_PROCESS_KEY").expect("worker transport key"),
    )
    .unwrap();
    let identities = (0..2u8).map(member).collect::<Vec<_>>();
    let mut runtime = HighAvailabilityRuntime::open(
        &path,
        ConsensusGroupId::named("ha-authenticated-process-qualification"),
        identities[0].public_key(),
        identities,
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    if runtime.current_round().received_mask == 0 {
        runtime
            .build_dispatch_at(vec![Transaction::new("worker-mid-epoch")], 1)
            .unwrap();
        runtime.acknowledge().unwrap();
    }
    let executor = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    executor.block_on(async move {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let node = HighAvailabilityTcpNode::new(runtime, Vec::new(), transport_key).unwrap();
        node.serve(listener).await.unwrap();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_transport_and_durable_state_survive_forced_process_restart() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "blossom-ha-process-{}-{unique}",
        std::process::id()
    ));
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);

    let identities = (0..2u8).map(member).collect::<Vec<_>>();
    let client_runtime = HighAvailabilityRuntime::new(
        ConsensusGroupId::named("ha-authenticated-process-qualification"),
        identities[1].public_key(),
        identities.clone(),
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    let client_handshake = client_runtime.handshake();
    let transport_key = HaTransportKey::new([41; HA_TRANSPORT_KEY_BYTES]);
    let client = HighAvailabilityTcpClient::for_runtime(&client_runtime, transport_key.clone());
    let service = Service::new(
        ServiceKind::Consensus,
        identities[0].public_key(),
        "tcp",
        "127.0.0.1",
        port,
    );

    let mut first = spawn_authenticated_ha_worker(&path, port, &transport_key);
    let first_status = await_authenticated_worker(&client, &service, &mut first).await;
    assert_eq!(first_status.head_nonce, Nonce::default());
    client
        .send_message(&service, HaMessage::Handshake(client_handshake))
        .await
        .unwrap();
    first.kill().unwrap();
    let first_exit = first.wait().unwrap();
    assert!(!first_exit.success(), "forced worker kill should be abrupt");

    let mut restarted = spawn_authenticated_ha_worker(&path, port, &transport_key);
    let restarted_status = await_authenticated_worker(&client, &service, &mut restarted).await;
    assert_eq!(restarted_status.head_hash, first_status.head_hash);
    assert_eq!(restarted_status.head_nonce, first_status.head_nonce);
    assert_eq!(
        restarted_status.parameters_hash,
        first_status.parameters_hash
    );
    client
        .send_message(&service, HaMessage::Handshake(client_handshake))
        .await
        .unwrap();
    restarted.kill().unwrap();
    restarted.wait().unwrap();
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn ha_transport_key_parsing_and_debug_do_not_expose_secret() {
    let encoded = "ab".repeat(HA_TRANSPORT_KEY_BYTES);
    let key = HaTransportKey::from_hex(&encoded).unwrap();
    assert_eq!(key.to_hex(), encoded);
    assert_eq!(format!("{key:?}"), "HaTransportKey([REDACTED])");
    assert_eq!(
        HaTransportKey::from_hex("abcd").unwrap_err(),
        BlossomError::InvalidLength {
            expected: HA_TRANSPORT_KEY_BYTES,
            actual: 2,
        }
    );
}
