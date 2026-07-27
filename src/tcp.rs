use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fast_telemetry::Counter;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::address_book::{Service, ServiceKind};
#[cfg(feature = "availability-gossip")]
use crate::availability::FilteredPayloadMissing;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::HashType;
use crate::messages::Msg;
use crate::overlay::{BroadcastReceipt, BroadcastReport};
use crate::runtime::{MultiGroupRuntime, NodeRuntime};
use crate::service_client::TcpServiceClient;
use crate::wire::{
    AddressBookUpdate, ApplicationRequest, ApplicationResponse, EncodedFrame, NodeHealth, NodePong,
    WireRequest, WireRequestFrame, WireResponse, read_encoded_frame,
    read_wire_request_frame_optional, read_wire_response, write_encoded_frame, write_wire_request,
    write_wire_response,
};

pub type ApplicationHandler =
    Arc<dyn Fn(ApplicationRequest) -> ApplicationHandlerFuture + Send + Sync>;
pub type ApplicationHandlerFuture =
    Pin<Box<dyn Future<Output = Result<ApplicationResponse>> + Send>>;

#[derive(Clone)]
pub struct TcpNode {
    pub runtime: NodeRuntime,
    pub services: TcpServiceClient,
    metrics: Option<TcpNodeMetrics>,
    application_handler: Option<ApplicationHandler>,
    driver_notify: Arc<Notify>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusDriverConfig {
    pub interval: Duration,
    /// Wake the driver immediately when a state-changing protocol message is
    /// received. Request-driven deployments should combine this with
    /// `require_local_pending_block` so notifications cannot create idle
    /// epochs.
    pub event_driven: bool,
    pub max_round: u8,
    pub drive_prefill: bool,
    pub drive_dispatch: bool,
    /// Do not initiate an epoch until this node has a locally submitted block.
    ///
    /// This is useful for request-driven deployments and benchmarks that must
    /// not create empty epochs while idle. The compatibility default remains
    /// `false`.
    pub require_local_pending_block: bool,
    /// Keep serving and retry the next driver tick after a transient error.
    ///
    /// Production callers retain fail-fast behavior by default. Controlled
    /// benchmark clusters enable retries so one connection race cannot tear
    /// down the node's TCP listener.
    pub continue_after_error: bool,
}

impl Default for ConsensusDriverConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(25),
            event_driven: false,
            max_round: 0,
            drive_prefill: false,
            drive_dispatch: true,
            require_local_pending_block: false,
            continue_after_error: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConsensusDriverTick {
    pub prefill_broadcasts: usize,
    pub dispatch_broadcasts: usize,
    pub trusted_acknowledgement_broadcasts: usize,
    pub verification_broadcasts: usize,
    pub proposal_broadcasts: usize,
    pub commit_broadcasts: usize,
    pub epoch_started_broadcasts: usize,
    pub echo_redispatch_responses: usize,
    pub manifest_repair_fetches: usize,
    pub catch_up_updates: usize,
}

impl ConsensusDriverTick {
    pub fn broadcasts(&self) -> usize {
        self.prefill_broadcasts
            + self.dispatch_broadcasts
            + self.trusted_acknowledgement_broadcasts
            + self.verification_broadcasts
            + self.proposal_broadcasts
            + self.commit_broadcasts
            + self.epoch_started_broadcasts
            + self.echo_redispatch_responses
    }
}

impl TcpNode {
    pub fn new(runtime: NodeRuntime) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            metrics: None,
            application_handler: None,
            driver_notify: Arc::new(Notify::new()),
        }
    }

    pub fn with_services(runtime: NodeRuntime, services: TcpServiceClient) -> Self {
        Self {
            runtime,
            services,
            metrics: None,
            application_handler: None,
            driver_notify: Arc::new(Notify::new()),
        }
    }

    pub fn with_metrics(runtime: NodeRuntime, metrics: TcpNodeMetrics) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            metrics: Some(metrics),
            application_handler: None,
            driver_notify: Arc::new(Notify::new()),
        }
    }

    pub fn with_application_handler(
        runtime: NodeRuntime,
        handler: impl Fn(ApplicationRequest) -> ApplicationHandlerFuture + Send + Sync + 'static,
    ) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            metrics: None,
            application_handler: Some(Arc::new(handler)),
            driver_notify: Arc::new(Notify::new()),
        }
    }

    pub fn metrics(&self) -> Option<TcpNodeMetricsSnapshot> {
        self.metrics.as_ref().map(TcpNodeMetrics::snapshot)
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|err| BlossomError::Io(err.to_string()))?;
            let node = self.clone();
            if let Some(metrics) = &node.metrics {
                metrics.record_connection();
            }
            tokio::spawn(async move {
                if let Err(err) = node.handle_connection(stream).await {
                    node.runtime.emit_telemetry_failure(
                        "transport",
                        "connection_failed",
                        &err,
                        None,
                    );
                    log::error!("connection failed: {err}");
                }
            });
        }
    }

    pub async fn serve_with_consensus_driver(
        self,
        listener: TcpListener,
        config: ConsensusDriverConfig,
    ) -> Result<()> {
        let serving = self.clone().serve(listener);
        let driving = self.run_consensus_driver(config);
        tokio::pin!(serving);
        tokio::pin!(driving);

        tokio::select! {
            result = &mut serving => result,
            result = &mut driving => result,
        }
    }

    pub async fn run_consensus_driver(self, config: ConsensusDriverConfig) -> Result<()> {
        let mut interval = tokio::time::interval(config.interval);
        let mut active_nonce = None;
        interval.tick().await;
        loop {
            if config.event_driven {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = self.driver_notify.notified() => {}
                }
            } else {
                interval.tick().await;
            }
            if config.require_local_pending_block {
                let status = self.runtime.status()?;
                if active_nonce.is_some_and(|nonce| nonce != status.next_nonce) {
                    active_nonce = None;
                }
                if active_nonce.is_none() {
                    if status.pending_blocks == 0 {
                        continue;
                    }
                    active_nonce = Some(status.next_nonce);
                }
            }
            if let Err(error) = self.drive_consensus_once(&config).await {
                if config.continue_after_error {
                    self.runtime.emit_telemetry_failure(
                        "service",
                        "consensus_driver_retry",
                        &error,
                        None,
                    );
                    log::warn!("consensus driver tick failed and will be retried: {error}");
                } else {
                    return Err(error);
                }
            }
        }
    }

    pub async fn drive_consensus_once(
        &self,
        config: &ConsensusDriverConfig,
    ) -> Result<ConsensusDriverTick> {
        let mut tick = ConsensusDriverTick::default();
        if config.drive_prefill
            && config.max_round > 0
            && self
                .runtime
                .try_broadcast_prefill_dispatch()
                .await?
                .is_some()
        {
            tick.prefill_broadcasts += 1;
        }

        if config.drive_prefill
            && config.max_round > 0
            && !self.runtime.try_activate_prefill_round()?
        {
            return Ok(tick);
        }

        let round = self.runtime.current_consensus_round()?;
        if round > config.max_round {
            return Err(crate::BlossomError::WireProtocol(format!(
                "consensus advanced to round {round}, beyond configured maximum {}",
                config.max_round
            )));
        }
        for message in self.runtime.drain_buffered_current_round_messages()? {
            self.runtime.receive_message(message)?;
        }
        if config.drive_dispatch
            && let Some(dispatch) = self.runtime.try_produce_dispatch(round)?
        {
            let blocks_hash = dispatch.body.blocks_hash;
            let report = self
                .broadcast_round_message(round, Msg::Dispatch(dispatch))
                .await?;
            if self.runtime.trust_mode().is_trusted() && report.failed() != 0 {
                self.runtime
                    .schedule_trusted_dispatch_retry(round, blocks_hash)?;
            }
            tick.dispatch_broadcasts += 1;
        }
        if self.runtime.trust_mode().is_trusted()
            && let Some(acknowledgement) =
                self.runtime.try_produce_trusted_acknowledgement(round)?
        {
            let blocks_hash = acknowledgement.body.blocks_hash;
            let report = self
                .broadcast_round_message(round, Msg::TrustedAcknowledgement(acknowledgement))
                .await?;
            if report.failed() != 0 {
                self.runtime
                    .schedule_trusted_acknowledgement_retry(round, blocks_hash)?;
            }
            tick.trusted_acknowledgement_broadcasts += 1;
        }
        if let Some(verification) = self.runtime.try_produce_verification(round)? {
            let blocks_hash = verification.body.blocks_hash;
            let report = self
                .broadcast_round_message(round, Msg::Verification(verification))
                .await?;
            if self.runtime.trust_mode().is_trusted() && report.failed() != 0 {
                self.runtime
                    .schedule_trusted_confirmation_retry(round, blocks_hash)?;
            }
            tick.verification_broadcasts += 1;
            if self.runtime.trust_mode().is_trusted() {
                self.runtime
                    .complete_trusted_verification(round, blocks_hash)?;
            }
        }
        if self.runtime.trust_mode().is_trusted() {
            self.runtime.try_complete_trusted_verification(round)?;
            if let Some(epoch_started) = self.runtime.try_produce_epoch_started()? {
                self.broadcast_round_message(0, Msg::EpochStarted(epoch_started))
                    .await?;
                tick.epoch_started_broadcasts += 1;
            }
            return Ok(tick);
        }
        if let Some(proposal) = self.runtime.try_produce_proposal(round)? {
            self.broadcast_round_message(round, Msg::Proposal(proposal))
                .await?;
            tick.proposal_broadcasts += 1;
        }
        if let Some(proposal) = self.runtime.try_produce_false_proposal(round)? {
            self.broadcast_round_message(round, Msg::Proposal(proposal))
                .await?;
            tick.proposal_broadcasts += 1;
        }
        if let Some(commit) = self.runtime.try_produce_commit(round)? {
            self.broadcast_round_message(round, Msg::Commit(commit))
                .await?;
            tick.commit_broadcasts += 1;
        }
        if let Some(epoch_started) = self.runtime.try_produce_epoch_started()? {
            self.broadcast_round_message(0, Msg::EpochStarted(epoch_started))
                .await?;
            tick.epoch_started_broadcasts += 1;
        }
        Ok(tick)
    }

    /// Drives only the Dispatch stage for the current round.
    ///
    /// Deterministic protocol harnesses use this to establish an all-writer
    /// admission barrier before allowing acknowledgement or confirmation
    /// production. Normal autonomous operation continues to use
    /// [`Self::drive_consensus_once`].
    pub async fn drive_dispatch_stage_once(&self, max_round: u8) -> Result<ConsensusDriverTick> {
        let round = self.runtime.current_consensus_round()?;
        if round > max_round {
            return Err(crate::BlossomError::WireProtocol(format!(
                "consensus advanced to round {round}, beyond configured maximum {max_round}"
            )));
        }
        for message in self.runtime.drain_buffered_current_round_messages()? {
            self.runtime.receive_message(message)?;
        }
        let mut tick = ConsensusDriverTick::default();
        if let Some(dispatch) = self.runtime.try_produce_dispatch(round)? {
            let blocks_hash = dispatch.body.blocks_hash;
            let report = self
                .broadcast_round_message(round, Msg::Dispatch(dispatch))
                .await?;
            if self.runtime.trust_mode().is_trusted() && report.failed() != 0 {
                self.runtime
                    .schedule_trusted_dispatch_retry(round, blocks_hash)?;
            }
            tick.dispatch_broadcasts = 1;
        }
        Ok(tick)
    }

    pub async fn repair_manifest_from_holders(
        &self,
        manifest: &crate::round_skip::DataDisseminationManifest,
    ) -> Result<usize> {
        let plan = self.runtime.manifest_repair_plan(manifest)?;
        if plan.missing_blocks.is_empty() {
            return Ok(0);
        }
        let services = self.runtime.address_book();
        let mut fetched = std::collections::BTreeMap::new();
        for (holder, hashes) in plan.requests_by_holder {
            let Some(service) = services.iter().find(|service| {
                service.kind == ServiceKind::Consensus && service.public_key == holder
            }) else {
                continue;
            };
            match send_wire_request(
                service.socket_addr(),
                WireRequest::GetBlocksByHash { hashes },
            )
            .await?
            {
                WireResponse::BlocksByHash(blocks) => {
                    fetched.extend(blocks);
                }
                WireResponse::Error(message) => {
                    return Err(BlossomError::ExternalService(message));
                }
                response => {
                    return Err(BlossomError::WireProtocol(format!(
                        "expected blocks_by_hash response from manifest holder, got {}",
                        response.kind()
                    )));
                }
            }
        }
        let receipt = self.runtime.repair_manifest_blocks(manifest, fetched)?;
        if !receipt.missing_blocks.is_empty() {
            return Err(BlossomError::WireProtocol(format!(
                "manifest repair still missing {} carried blocks",
                receipt.missing_blocks.len()
            )));
        }
        Ok(receipt.inserted_blocks)
    }

    pub async fn catch_up_from_epoch_started_peers(&self, peers: &[Service]) -> Result<usize> {
        let mut updates = 0usize;
        for service in peers {
            let local_tip = self
                .runtime
                .epochchain()
                .epochchain
                .last()
                .cloned()
                .ok_or(BlossomError::EmptyEpochChain)?;
            let request = if self.runtime.trust_mode().is_trusted() {
                WireRequest::EpochChain
            } else {
                WireRequest::CertifiedEpochSuffix {
                    anchor_hash: local_tip.hash,
                    anchor_nonce: local_tip.body.nonce,
                    max_epochs: 4096,
                }
            };
            match send_wire_request(service.socket_addr(), request).await? {
                WireResponse::CertifiedEpochSuffix(suffix) => {
                    updates += usize::from(self.runtime.catch_up_certified_suffix(suffix)?);
                }
                WireResponse::EpochChain(chain) => {
                    updates += usize::from(self.runtime.catch_up_from_epoch_started(chain)?);
                }
                WireResponse::Error(message) => {
                    return Err(BlossomError::ExternalService(message));
                }
                response => {
                    return Err(BlossomError::WireProtocol(format!(
                        "expected epoch_chain response during catch-up, got {}",
                        response.kind()
                    )));
                }
            }
        }
        Ok(updates)
    }

    async fn broadcast_round_message(&self, round: u8, msg: Msg) -> Result<BroadcastReport> {
        let targets = self.runtime.round_consensus_services(round)?;
        let frame = EncodedFrame::encode_wire_request(&WireRequest::Message(msg))?;
        let mut handles = Vec::with_capacity(targets.len());
        for service in targets {
            let client = self.services.clone();
            let frame = frame.clone();
            let service_for_task = service.clone();
            handles.push((
                service,
                tokio::spawn(async move { client.request_frame(&service_for_task, &frame).await }),
            ));
        }
        let mut receipts = Vec::with_capacity(handles.len());
        for (service, handle) in handles {
            let response = match handle.await {
                Ok(response) => response,
                Err(error) => Err(BlossomError::Io(format!(
                    "persistent broadcast task failed: {error}"
                ))),
            };
            receipts.push(BroadcastReceipt {
                target: service.public_key,
                service,
                response,
            });
        }
        Ok(BroadcastReport { receipts })
    }

    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        configure_tcp_stream(&stream)?;
        while let Some(request) = read_wire_request_frame_optional(&mut stream).await? {
            let started = Instant::now();
            let result = self.handle_request_frame(request).await;
            if let Some(metrics) = &self.metrics {
                metrics.record_request(started.elapsed().as_nanos(), result.is_ok());
            }
            let response = match result {
                Ok(response) => response,
                Err(err) => WireResponse::Error(err.to_string()),
            };
            write_wire_response(&mut stream, &response).await?;
        }
        Ok(())
    }

    pub async fn handle_request_frame(&self, request: WireRequestFrame) -> Result<WireResponse> {
        match request {
            WireRequestFrame::Request(request) => {
                let drives_consensus = request_drives_consensus(&request);
                let response = self.handle_request(request).await;
                if drives_consensus && response.is_ok() {
                    self.driver_notify.notify_one();
                }
                response
            }
            WireRequestFrame::HotDispatch(dispatch) => {
                let response =
                    WireResponse::MessageReceipt(self.runtime.receive_hot_dispatch(dispatch)?);
                self.driver_notify.notify_one();
                Ok(response)
            }
        }
    }

    pub async fn handle_request(&self, request: WireRequest) -> Result<WireResponse> {
        match request {
            WireRequest::Application(request) => {
                let handler = self.application_handler.as_ref().ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "application requests are not configured on this node".to_string(),
                    )
                })?;
                Ok(WireResponse::Application(handler(request).await?))
            }
            WireRequest::Group { group_id, request } => {
                if group_id != self.runtime.group_id() {
                    return Err(unknown_group(group_id));
                }
                handle_runtime_request(&self.runtime, &self.services, *request).await
            }
            request => handle_runtime_request(&self.runtime, &self.services, request).await,
        }
    }
}

fn request_drives_consensus(request: &WireRequest) -> bool {
    match request {
        WireRequest::Group { request, .. } => request_drives_consensus(request),
        WireRequest::RegisterService(_)
        | WireRequest::SubmitBlock(_)
        | WireRequest::PrefillDispatch(_)
        | WireRequest::Message(_)
        | WireRequest::SendNonce(_)
        | WireRequest::BlockNonce(_)
        | WireRequest::SendBlock(_) => true,
        _ => false,
    }
}

#[derive(Clone, Default)]
pub struct TcpNodeMetrics {
    inner: Arc<TcpNodeMetricsInner>,
}

struct TcpNodeMetricsInner {
    connections: Counter,
    requests: Counter,
    responses: Counter,
    errors: Counter,
    handler_nanos: Counter,
}

impl Default for TcpNodeMetricsInner {
    fn default() -> Self {
        Self {
            connections: Counter::new(64),
            requests: Counter::new(64),
            responses: Counter::new(64),
            errors: Counter::new(64),
            handler_nanos: Counter::new(64),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpNodeMetricsSnapshot {
    pub connections: u64,
    pub requests: u64,
    pub responses: u64,
    pub errors: u64,
    pub handler_nanos: u64,
}

impl TcpNodeMetrics {
    pub fn snapshot(&self) -> TcpNodeMetricsSnapshot {
        TcpNodeMetricsSnapshot {
            connections: counter_sum_u64(&self.inner.connections),
            requests: counter_sum_u64(&self.inner.requests),
            responses: counter_sum_u64(&self.inner.responses),
            errors: counter_sum_u64(&self.inner.errors),
            handler_nanos: counter_sum_u64(&self.inner.handler_nanos),
        }
    }

    fn record_connection(&self) {
        self.inner.connections.inc();
    }

    fn record_request(&self, nanos: u128, success: bool) {
        self.inner.requests.inc();
        match success {
            true => self.inner.responses.inc(),
            false => self.inner.errors.inc(),
        };
        counter_add_u128(&self.inner.handler_nanos, nanos);
    }
}

fn counter_sum_u64(counter: &Counter) -> u64 {
    u64::try_from(counter.sum()).unwrap_or_default()
}

fn counter_add_u128(counter: &Counter, value: u128) {
    counter.add(isize::try_from(value).unwrap_or(isize::MAX));
}

#[derive(Clone)]
pub struct TcpMultiGroupNode {
    pub runtime: MultiGroupRuntime,
    pub services: TcpServiceClient,
}

impl TcpMultiGroupNode {
    pub fn new(runtime: MultiGroupRuntime) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
        }
    }

    pub fn with_services(runtime: MultiGroupRuntime, services: TcpServiceClient) -> Self {
        Self { runtime, services }
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|err| BlossomError::Io(err.to_string()))?;
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(err) = node.handle_connection(stream).await {
                    node.runtime.root_runtime().emit_telemetry_failure(
                        "transport",
                        "multi_group_connection_failed",
                        &err,
                        None,
                    );
                    log::error!("connection failed: {err}");
                }
            });
        }
    }

    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        configure_tcp_stream(&stream)?;
        while let Some(request) = read_wire_request_frame_optional(&mut stream).await? {
            let response = match self.handle_request_frame(request).await {
                Ok(response) => response,
                Err(err) => WireResponse::Error(err.to_string()),
            };
            write_wire_response(&mut stream, &response).await?;
        }
        Ok(())
    }

    pub async fn handle_request_frame(&self, request: WireRequestFrame) -> Result<WireResponse> {
        match request {
            WireRequestFrame::Request(request) => self.handle_request(request).await,
            WireRequestFrame::HotDispatch(dispatch) => {
                let runtime = self
                    .runtime
                    .group_for_epoch(&dispatch.header.last_epoch)
                    .ok_or_else(|| unknown_epoch_group(dispatch.header.last_epoch))?;
                Ok(WireResponse::MessageReceipt(
                    runtime.receive_hot_dispatch(dispatch)?,
                ))
            }
        }
    }

    pub async fn handle_request(&self, request: WireRequest) -> Result<WireResponse> {
        match request {
            WireRequest::Group { group_id, request } => {
                let runtime = self
                    .runtime
                    .group(&group_id)
                    .ok_or_else(|| unknown_group(group_id))?;
                handle_runtime_request(&runtime, &self.services, *request).await
            }
            request => {
                let runtime = self.runtime.root_runtime();
                handle_runtime_request(&runtime, &self.services, request).await
            }
        }
    }
}

async fn handle_runtime_request(
    runtime: &NodeRuntime,
    services: &TcpServiceClient,
    request: WireRequest,
) -> Result<WireResponse> {
    match request {
        WireRequest::Health => Ok(WireResponse::Health(NodeHealth::new(
            "ok",
            runtime.self_node().public_key(),
        ))),
        WireRequest::Ping(ping) => Ok(WireResponse::Pong(NodePong::new_with_consensus_parameters(
            runtime.group_id(),
            runtime.self_node().public_key(),
            runtime.consensus_parameters(),
            ping.nonce,
            ping.payload,
        ))),
        WireRequest::Application(_) => Err(BlossomError::WireProtocol(
            "application requests require an application handler".to_string(),
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::AvailabilityGossip(gossip) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_availability_gossip(gossip)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::GetFilteredPayload(fetch) => {
            let missing = FilteredPayloadMissing {
                scope: fetch.body.scope,
                holder: runtime.self_node().public_key(),
                slot_hash: fetch.body.slot_hash,
                payload_commitment: fetch.body.payload_commitment,
            };
            match runtime.serve_filtered_payload_fetch(fetch)? {
                Some(delivery) => Ok(WireResponse::FilteredPayload(delivery)),
                None => Ok(WireResponse::FilteredPayloadMissing(missing)),
            }
        }
        #[cfg(feature = "availability-gossip")]
        WireRequest::GetFilteredPayloadBatch(fetch) => Ok(WireResponse::FilteredPayloadBatch(
            runtime.serve_filtered_payload_batch_fetch(fetch)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::StoreFilteredPayload(delivery) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_filtered_payload(delivery)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::StoreFilteredPayloadBatch(delivery) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_filtered_payload_batch(delivery)?,
        )),
        WireRequest::State => Ok(WireResponse::State(runtime.status()?)),
        WireRequest::EpochChain => Ok(WireResponse::EpochChain(runtime.epochchain())),
        WireRequest::CertifiedEpochSuffix {
            anchor_hash,
            anchor_nonce,
            max_epochs,
        } => Ok(WireResponse::CertifiedEpochSuffix(
            runtime.certified_epoch_suffix(anchor_hash, anchor_nonce, max_epochs as usize)?,
        )),
        WireRequest::AddressBook => Ok(WireResponse::AddressBook(runtime.address_book())),
        WireRequest::RegisterService(registration) => {
            let (service, admission, signed_record) = registration.into_parts();
            let previous = match signed_record {
                Some(record) => runtime.register_signed_service(record)?,
                None => {
                    let admission = admission.as_ref().ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "service registration has no authentication evidence".to_string(),
                        )
                    })?;
                    admission.verify()?;
                    runtime.register_service(service.clone())
                }
            };
            let admitted_node = match admission {
                Some(admission) => runtime.stage_node_admission(admission)?,
                None => None,
            };
            let nonce_announced = if service.kind == ServiceKind::Block {
                let target = runtime.next_epoch_target()?;
                services.send_nonce(&service, target.nonce).await?;
                Some(target.nonce)
            } else {
                None
            };
            Ok(WireResponse::AddressBookUpdated(AddressBookUpdate {
                service,
                previous,
                nonce_announced,
                admitted_node,
            }))
        }
        WireRequest::NextNonce => Ok(WireResponse::NextNonce(runtime.next_epoch_target()?)),
        WireRequest::SubmitBlock(block) => {
            Ok(WireResponse::BlockAccepted(runtime.submit_block(block)?))
        }
        WireRequest::Dispatch { round } => {
            Ok(WireResponse::Dispatch(runtime.dispatch_local_block(round)?))
        }
        WireRequest::PrefillDispatch(dispatch) => Ok(WireResponse::MessageReceipt(
            runtime.receive_prefill_dispatch(dispatch)?,
        )),
        WireRequest::Message(message) => match message {
            Msg::EchoRequest(request) => {
                let redispatch = runtime.respond_to_echo_request(&request)?;
                runtime.receive_message(Msg::EchoRequest(request))?;
                Ok(WireResponse::EchoReDispatch(redispatch))
            }
            message => Ok(WireResponse::MessageReceipt(
                runtime.receive_message(message)?,
            )),
        },
        WireRequest::SendNonce(_) | WireRequest::BlockNonce(_) => Ok(WireResponse::Ok),
        WireRequest::GetBlock(nonce) => match runtime.durable_block_by_nonce(nonce)? {
            Some(block) => Ok(WireResponse::Block(block)),
            None => Err(BlossomError::WireProtocol(
                "this node does not have a durable block for the requested nonce".to_string(),
            )),
        },
        WireRequest::GetBlocksByHash { hashes } => Ok(WireResponse::BlocksByHash(
            runtime.durable_blocks_by_hash(hashes)?,
        )),
        WireRequest::SendBlock(block) => {
            runtime.submit_block(block)?;
            Ok(WireResponse::Ok)
        }
        WireRequest::Group { group_id, .. } => Err(BlossomError::WireProtocol(format!(
            "nested grouped request for group {group_id} is not allowed"
        ))),
    }
}

fn unknown_group(group_id: ConsensusGroupId) -> BlossomError {
    BlossomError::WireProtocol(format!("unknown consensus group {group_id}"))
}

fn unknown_epoch_group(last_epoch: HashType) -> BlossomError {
    BlossomError::WireProtocol(format!("no consensus group is tracking epoch {last_epoch}"))
}

pub struct TcpConnection {
    stream: TcpStream,
}

impl TcpConnection {
    pub async fn connect(addr: impl AsRef<str>) -> Result<Self> {
        let stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        configure_tcp_stream(&stream)?;
        Ok(Self { stream })
    }

    pub async fn request(&mut self, request: &WireRequest) -> Result<WireResponse> {
        write_wire_request(&mut self.stream, request).await?;
        read_wire_response(&mut self.stream).await
    }

    pub async fn request_frame(&mut self, frame: &EncodedFrame) -> Result<WireResponse> {
        write_encoded_frame(&mut self.stream, frame).await?;
        read_wire_response(&mut self.stream).await
    }

    pub async fn request_raw_response(&mut self, request: &WireRequest) -> Result<EncodedFrame> {
        write_wire_request(&mut self.stream, request).await?;
        read_encoded_frame(&mut self.stream).await
    }
}

fn configure_tcp_stream(stream: &TcpStream) -> Result<()> {
    stream
        .set_nodelay(true)
        .map_err(|err| BlossomError::Io(err.to_string()))
}

pub async fn send_wire_request(
    addr: impl AsRef<str>,
    request: WireRequest,
) -> Result<WireResponse> {
    let mut connection = TcpConnection::connect(addr).await?;
    connection.request(&request).await
}

pub async fn send_wire_frame(addr: impl AsRef<str>, frame: &EncodedFrame) -> Result<WireResponse> {
    let mut connection = TcpConnection::connect(addr).await?;
    connection.request_frame(frame).await
}

pub async fn send_wire_request_raw_response(
    addr: impl AsRef<str>,
    request: WireRequest,
) -> Result<EncodedFrame> {
    let mut connection = TcpConnection::connect(addr).await?;
    connection.request_raw_response(&request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, Transaction};
    use crate::blossom::{BlossomBody, EchoRequest, Header};
    use crate::crypto::Keypair;
    use crate::group::ConsensusGroupId;
    use crate::messages::MSGKey;
    use crate::node::NodeIdentity;
    use crate::runtime::{
        MultiGroupRuntime, RuntimeConfig, genesis_epoch, genesis_epoch_for_group,
    };

    fn tcp_node() -> (TcpNode, Keypair) {
        let keypair = Keypair::generate();
        let identity = NodeIdentity::new(
            keypair.public,
            Some(keypair.secret.clone()),
            "tcp",
            "127.0.0.1",
            8080,
            false,
        );
        (
            TcpNode::new(crate::NodeRuntime::new(RuntimeConfig::new(identity))),
            keypair,
        )
    }

    fn signed_test_header<T: BlossomBody>(
        signer: &Keypair,
        target: &crate::EpochTarget,
        round: u8,
        kind: MSGKey,
        body: &T,
    ) -> Header {
        let signature_hash = Header::signature_hash_for_body(
            &signer.public,
            &target.last_epoch,
            target.nonce,
            round,
            kind,
            body,
        );
        Header {
            sender: signer.public,
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round,
            signature: signer.signer().sign(signature_hash.as_ref()),
        }
    }

    fn six_node_tcp_runtime() -> (TcpNode, Vec<Keypair>) {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let identities = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    (index == 0).then_some(keypair.secret.clone()),
                    "tcp",
                    "127.0.0.1",
                    8700 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let genesis = genesis_epoch(identities.clone());
        let mut config = RuntimeConfig::new(identities[0].clone());
        config.genesis = Some(genesis);
        (TcpNode::new(crate::NodeRuntime::new(config)), keypairs)
    }

    #[tokio::test]
    async fn handle_request_returns_health_and_errors() {
        let (node, keypair) = tcp_node();

        match node.handle_request(WireRequest::Health).await.unwrap() {
            WireResponse::Health(health) => {
                assert_eq!(health.public_key, keypair.public);
                assert!(health.protocol_hash_compatible());
            }
            response => panic!("expected health, got {}", response.kind()),
        }

        match node
            .handle_request(WireRequest::GetBlock(crate::Nonce::new(1)))
            .await
            .unwrap_err()
        {
            BlossomError::WireProtocol(message) => assert!(message.contains("does not have")),
            error => panic!("unexpected error: {error}"),
        }
    }

    #[tokio::test]
    async fn application_handler_round_trips_over_node_request_path() {
        let (base_node, keypair) = tcp_node();
        let node = TcpNode::with_application_handler(base_node.runtime, |request| {
            Box::pin(async move {
                assert_eq!(request.kind, "test/echo");
                Ok(ApplicationResponse::new("test/echo", request.payload))
            })
        });

        match node
            .handle_request(WireRequest::Application(ApplicationRequest::new(
                "test/echo",
                b"payload",
            )))
            .await
            .unwrap()
        {
            WireResponse::Application(response) => {
                assert_eq!(response.kind, "test/echo");
                assert_eq!(response.payload, b"payload");
            }
            response => panic!(
                "expected application response from {}, got {}",
                keypair.public,
                response.kind()
            ),
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(node.clone().serve(listener));
        let service = Service::new(
            ServiceKind::Engine,
            keypair.public,
            "tcp",
            "127.0.0.1",
            port,
        );
        let response = TcpServiceClient::new()
            .application(&service, ApplicationRequest::new("test/echo", b"network"))
            .await
            .unwrap();
        assert_eq!(response.kind, "test/echo");
        assert_eq!(response.payload, b"network");
        server.abort();
    }

    #[tokio::test]
    async fn handle_request_serves_durable_blocks_by_nonce() {
        let keypair = Keypair::generate();
        let identity = NodeIdentity::new(
            keypair.public,
            Some(keypair.secret.clone()),
            "tcp",
            "127.0.0.1",
            8080,
            false,
        );
        let root = std::env::temp_dir().join(format!(
            "blossom-tcp-block-store-{}-{}",
            std::process::id(),
            keypair.public
        ));
        let mut config = RuntimeConfig::new(identity);
        config.block_store_path = Some(root.clone());
        let node = TcpNode::new(crate::NodeRuntime::new(config));
        let target = node.runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.sign(&keypair.secret);
        let hash = block.hash;

        node.handle_request(WireRequest::SendBlock(block))
            .await
            .unwrap();

        match node
            .handle_request(WireRequest::GetBlock(target.nonce))
            .await
            .unwrap()
        {
            WireResponse::Block(block) => assert_eq!(block.hash, hash),
            response => panic!("expected block, got {}", response.kind()),
        }
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn handle_request_returns_direct_pong_without_consensus() {
        let (node, keypair) = tcp_node();
        let ping = crate::NodePing::with_payload(42, b"hello-peer");

        match node.handle_request(WireRequest::Ping(ping)).await.unwrap() {
            WireResponse::Pong(pong) => {
                assert_eq!(pong.group_id, ConsensusGroupId::root());
                assert_eq!(pong.public_key, keypair.public);
                assert!(pong.protocol_hash_compatible());
                assert_eq!(pong.nonce, 42);
                assert_eq!(pong.payload, b"hello-peer");
            }
            response => panic!("expected pong, got {}", response.kind()),
        }
    }

    #[tokio::test]
    async fn handle_request_serves_durable_blocks_by_hash() {
        let keypair = Keypair::generate();
        let identity = NodeIdentity::new(
            keypair.public,
            Some(keypair.secret.clone()),
            "tcp",
            "127.0.0.1",
            8610,
            false,
        );
        let root = std::env::temp_dir().join(format!(
            "blossom-tcp-block-store-hash-{}-{}",
            std::process::id(),
            keypair.public
        ));
        let mut config = RuntimeConfig::new(identity);
        config.block_store_path = Some(root.clone());
        let runtime = NodeRuntime::new(config);
        let target = runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.txs.push(Transaction::new("tcp-hash-repair"));
        block.sign(&keypair.secret);
        runtime.submit_block(block.clone()).unwrap();
        let node = TcpNode::new(runtime);

        match node
            .handle_request(WireRequest::GetBlocksByHash {
                hashes: vec![block.hash, HashType([9; 32])],
            })
            .await
            .unwrap()
        {
            WireResponse::BlocksByHash(blocks) => {
                assert_eq!(blocks.len(), 1);
                assert_eq!(blocks.get(&block.hash).unwrap().hash, block.hash);
            }
            response => panic!("expected blocks_by_hash, got {}", response.kind()),
        }

        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn echo_request_returns_targeted_redispatch_response() {
        let (node, keypairs) = six_node_tcp_runtime();
        let target = node.runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.txs.push(Transaction::new("tcp-echo-redispatch"));
        block.sign(&keypairs[0].secret);
        node.runtime.submit_block(block).unwrap();
        let dispatch = node.runtime.dispatch_local_block(0).unwrap();
        let block_hash = *dispatch.body.blocks.keys().next().unwrap();
        let requested_blocks = [(block_hash, ())].into_iter().collect();
        let request = EchoRequest {
            header: signed_test_header(
                &keypairs[1],
                &target,
                0,
                MSGKey::EchoRequest,
                &requested_blocks,
            ),
            requested_blocks,
        };

        match node
            .handle_request(WireRequest::Message(Msg::EchoRequest(request)))
            .await
            .unwrap()
        {
            WireResponse::EchoReDispatch(Some(redispatch)) => {
                assert_eq!(redispatch.header.sender, keypairs[0].public);
                assert!(redispatch.redispatched_blocks.contains_key(&block_hash));
            }
            response => panic!("expected echo_redispatch response, got {}", response.kind()),
        }
    }

    #[tokio::test]
    async fn consensus_driver_broadcasts_prefill_once_before_verified_rounds() {
        let keypairs = (0..36).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let identities = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    (index == 0).then_some(keypair.secret.clone()),
                    "tcp",
                    "127.0.0.1",
                    8600 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();
        let genesis = genesis_epoch(identities.clone());
        let mut config = RuntimeConfig::new(identities[0].clone());
        config.genesis = Some(genesis);
        let runtime = NodeRuntime::new(config);
        let target = runtime.next_epoch_target().unwrap();
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.txs.push(Transaction::new("tcp-driver-prefill"));
        block.sign(&keypairs[0].secret);
        runtime.submit_block(block).unwrap();

        let node = TcpNode::new(runtime.clone());
        let driver = ConsensusDriverConfig {
            max_round: 1,
            drive_prefill: true,
            drive_dispatch: false,
            ..ConsensusDriverConfig::default()
        };
        let first = node.drive_consensus_once(&driver).await.unwrap();
        let second = node.drive_consensus_once(&driver).await.unwrap();

        assert_eq!(first.prefill_broadcasts, 1);
        assert_eq!(first.dispatch_broadcasts, 0);
        assert_eq!(second.prefill_broadcasts, 0);
        assert!(runtime.has_local_prefill_dispatch().unwrap());
    }

    #[tokio::test]
    async fn multi_group_node_routes_grouped_requests_to_subnets() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let identities = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    (index == 0).then_some(keypair.secret.clone()),
                    "tcp",
                    "127.0.0.1",
                    8000 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();

        let root_genesis = genesis_epoch(identities.clone());
        let subnet_id = ConsensusGroupId::named("cache-hotset-a");
        let subnet_genesis = genesis_epoch_for_group(subnet_id, identities[..3].to_vec());

        let mut root_config = RuntimeConfig::new(identities[0].clone());
        root_config.genesis = Some(root_genesis.clone());
        let root_runtime = NodeRuntime::new(root_config);

        let mut subnet_config = RuntimeConfig::new(identities[0].clone());
        subnet_config.group_id = subnet_id;
        subnet_config.genesis = Some(subnet_genesis.clone());
        let subnet_runtime = NodeRuntime::new(subnet_config);
        subnet_runtime
            .set_application_state(b"subnet-only")
            .unwrap();

        let root_target = root_runtime.next_epoch_target().unwrap();
        let subnet_target = subnet_runtime.next_epoch_target().unwrap();
        let node = TcpMultiGroupNode::new(MultiGroupRuntime::with_groups(
            root_runtime,
            [subnet_runtime],
        ));

        match node.handle_request(WireRequest::NextNonce).await.unwrap() {
            WireResponse::NextNonce(target) => {
                assert_eq!(target.last_epoch, root_target.last_epoch)
            }
            response => panic!("expected root next nonce, got {}", response.kind()),
        }

        let grouped_next = WireRequest::Group {
            group_id: subnet_id,
            request: Box::new(WireRequest::NextNonce),
        };
        match node.handle_request(grouped_next).await.unwrap() {
            WireResponse::NextNonce(target) => {
                assert_eq!(target.last_epoch, subnet_target.last_epoch);
                assert_eq!(target.nonce, subnet_target.nonce);
            }
            response => panic!("expected subnet next nonce, got {}", response.kind()),
        }

        let grouped_ping = WireRequest::Group {
            group_id: subnet_id,
            request: Box::new(WireRequest::Ping(crate::NodePing::new(7))),
        };
        match node.handle_request(grouped_ping).await.unwrap() {
            WireResponse::Pong(pong) => {
                assert_eq!(pong.group_id, subnet_id);
                assert_eq!(pong.public_key, keypairs[0].public);
                assert_eq!(pong.nonce, 7);
                assert!(pong.payload.is_empty());
            }
            response => panic!("expected subnet pong, got {}", response.kind()),
        }

        let grouped_dispatch = WireRequest::Group {
            group_id: subnet_id,
            request: Box::new(WireRequest::Dispatch { round: 0 }),
        };
        match node.handle_request(grouped_dispatch).await.unwrap() {
            WireResponse::Dispatch(dispatch) => {
                assert_eq!(dispatch.header.last_epoch, subnet_target.last_epoch);
                let block = dispatch.body.blocks.values().next().unwrap();
                assert_eq!(block.application_state(), b"subnet-only");
            }
            response => panic!("expected subnet dispatch, got {}", response.kind()),
        }

        let unknown_group = WireRequest::Group {
            group_id: ConsensusGroupId::named("not-hosted"),
            request: Box::new(WireRequest::NextNonce),
        };
        assert!(matches!(
            node.handle_request(unknown_group).await,
            Err(BlossomError::WireProtocol(message)) if message.contains("unknown consensus group")
        ));
    }
}
