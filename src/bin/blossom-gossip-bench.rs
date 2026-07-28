//! Filtered-payload gossip benchmark and feature-gated fallback.

#[cfg(not(feature = "availability-gossip"))]
fn main() {
    eprintln!("blossom-gossip-bench requires --features availability-gossip");
    std::process::exit(1);
}

#[cfg(feature = "availability-gossip")]
mod bench {
    use std::fs::{OpenOptions, create_dir_all};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::Instant;

    use clap::Parser;

    use blossom::{
        AvailabilityEntry, AvailabilityGossip, AvailabilityGossipBody, BlossomError,
        ConsensusGroupId, FilteredDeliveryPolicy, FilteredPayloadBatchFetch,
        FilteredPayloadBatchFetchBody, FilteredPayloadFetch, FilteredPayloadFetchBody,
        FilteredPayloadRequest, HashType, SimulatedCluster, Transaction, WireRequest, WireResponse,
        ideal_push_gossip_rounds, signed_block, wire_request_framed_len, wire_response_framed_len,
    };

    pub type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    #[derive(Parser, Debug)]
    #[command(
        name = "blossom-gossip-bench",
        about = "Benchmark Blossom availability gossip dissemination and payload fetch"
    )]
    struct Args {
        #[arg(long, default_value_t = 36)]
        nodes: usize,
        #[arg(long, default_value_t = 128)]
        entries: usize,
        #[arg(long, default_value_t = 4096)]
        payload_bytes: usize,
        #[arg(long, default_value_t = 6)]
        fanout: usize,
        #[arg(long, default_value_t = 6)]
        targets_per_entry: usize,
        #[arg(long, default_value_t = 5)]
        iterations: usize,
        #[arg(long, default_value_t = 1)]
        warmup: usize,
        #[arg(long, default_value_t = false)]
        trusted: bool,
        #[arg(long, default_value_t = false)]
        skip_fetch: bool,
        #[arg(long, default_value_t = false)]
        single_fetch: bool,
        /// Drop every Nth gossip send attempt before opening a TCP connection.
        ///
        /// This is a deterministic loss simulation for validation runs. The
        /// default, 0, sends every gossip message.
        #[arg(long, default_value_t = 0)]
        drop_gossip_every: usize,
        /// Fail the run if gossip does not reach every node or target fetches
        /// do not all deliver.
        #[arg(long, default_value_t = false)]
        expect_complete: bool,
        #[arg(long)]
        csv: Option<PathBuf>,
        #[arg(long)]
        append: bool,
    }

    #[derive(Copy, Clone, Debug)]
    struct IterationConfig {
        nodes: usize,
        entries: usize,
        payload_bytes: usize,
        fanout: usize,
        targets_per_entry: usize,
        trusted: bool,
        fetch_payloads: bool,
        batch_fetch: bool,
        drop_gossip_every: usize,
    }

    #[derive(Debug, Clone)]
    struct GossipBenchRow {
        iteration: usize,
        nodes: usize,
        entries: usize,
        payload_bytes: usize,
        fanout: usize,
        targets_per_entry: usize,
        trusted: bool,
        fetch_payloads: bool,
        batch_fetch: bool,
        gossip_rounds: usize,
        ideal_rounds: Option<usize>,
        gossip_sends: usize,
        gossip_accepted: usize,
        fetch_batches: usize,
        fetches_attempted: usize,
        fetches_delivered: usize,
        metadata_wire_bytes: usize,
        fetch_wire_bytes: usize,
        total_wire_bytes: usize,
        spawn_us: u128,
        block_submit_us: u128,
        gossip_build_us: u128,
        gossip_disseminate_us: u128,
        fetch_us: u128,
        total_us: u128,
        informed_nodes: usize,
        gossip_dropped: usize,
    }

    #[derive(Debug, Clone)]
    struct GossipDissemination {
        rounds: usize,
        sends: usize,
        accepted: usize,
        wire_bytes: usize,
        informed_nodes: usize,
        dropped: usize,
        informed: Vec<bool>,
    }

    pub async fn main() -> MainResult<()> {
        let args = Args::parse();
        let config = IterationConfig {
            nodes: args.nodes,
            entries: args.entries,
            payload_bytes: args.payload_bytes,
            fanout: args.fanout,
            targets_per_entry: args.targets_per_entry,
            trusted: args.trusted,
            fetch_payloads: !args.skip_fetch,
            batch_fetch: !args.single_fetch,
            drop_gossip_every: args.drop_gossip_every,
        };

        for _ in 0..args.warmup {
            run_iteration(0, config).await?;
        }

        let mut rows = Vec::with_capacity(args.iterations);
        for iteration in 0..args.iterations {
            let row = run_iteration(iteration, config).await?;
            if args.expect_complete {
                row.validate_complete()?;
            }
            println!("{}", row.to_csv());
            rows.push(row);
        }

        if let Some(path) = args.csv {
            write_csv(&path, args.append, &rows)?;
            eprintln!("wrote {}", path.display());
        }

        Ok(())
    }

    async fn run_iteration(
        iteration: usize,
        config: IterationConfig,
    ) -> MainResult<GossipBenchRow> {
        if config.nodes == 0 {
            return Err(BlossomError::WireProtocol(
                "gossip benchmark requires at least one node".to_string(),
            )
            .into());
        }
        if config.entries == 0 {
            return Err(BlossomError::WireProtocol(
                "gossip benchmark requires at least one entry".to_string(),
            )
            .into());
        }

        let total_start = Instant::now();
        let spawn_start = Instant::now();
        let cluster = if config.trusted {
            SimulatedCluster::spawn_trusted(config.nodes).await?
        } else {
            SimulatedCluster::spawn(config.nodes).await?
        };
        let spawn_us = spawn_start.elapsed().as_micros();

        let holder_index = 0usize;
        let holder = cluster.node(holder_index);
        let mut txs = Vec::with_capacity(config.entries);
        let mut entries = Vec::with_capacity(config.entries);
        for entry_index in 0..config.entries {
            let payload = payload_for(iteration, entry_index, config.payload_bytes);
            let targets = targets_for_entry(&cluster, entry_index, config.targets_per_entry);
            let tx = Transaction::filtered_full(
                key_hash_for(entry_index),
                1,
                targets,
                payload,
                FilteredDeliveryPolicy::Gossip,
            )?;
            let slot = tx
                .filtered_slot()
                .ok_or_else(|| BlossomError::WireProtocol("missing filtered slot".to_string()))?
                .clone();
            entries.push(AvailabilityEntry::new(slot)?);
            txs.push(tx);
        }

        let block_submit_start = Instant::now();
        let target = cluster.next_target(holder_index).await?;
        let block = if config.trusted {
            let mut block = blossom::Block::default();
            block.body.last_epoch = target.last_epoch;
            block.body.nonce = target.nonce;
            block.body.txs = txs;
            block.seal_unsigned(holder.identity.public_key());
            block
        } else {
            signed_block(target, holder.keypair.secret.clone(), txs)
        };
        let submit_request = WireRequest::SubmitBlock(block);
        let submit_request_bytes = wire_request_framed_len(&submit_request)?;
        let submit_response = cluster.request(holder_index, submit_request).await?;
        let submit_response_bytes = wire_response_framed_len(&submit_response)?;
        match submit_response {
            WireResponse::BlockAccepted(_) => {}
            WireResponse::Error(message) => return Err(BlossomError::WireProtocol(message).into()),
            response => return Err(unexpected("block submit", response).into()),
        }
        let block_submit_us = block_submit_start.elapsed().as_micros();

        let gossip_build_start = Instant::now();
        let body = AvailabilityGossipBody {
            scope: ConsensusGroupId::root(),
            holder: holder.identity.public_key(),
            entries: entries.clone(),
        };
        let gossip = if config.trusted {
            AvailabilityGossip::trusted(body)?
        } else {
            AvailabilityGossip::signed(body, &holder.keypair.signer())?
        };
        let gossip_build_us = gossip_build_start.elapsed().as_micros();

        let gossip_start = Instant::now();
        let dissemination = disseminate_gossip(
            &cluster,
            holder_index,
            &gossip,
            config.fanout,
            config.drop_gossip_every,
        )
        .await?;
        let gossip_disseminate_us = gossip_start.elapsed().as_micros();

        let fetch_start = Instant::now();
        let (fetch_batches, fetches_attempted, fetches_delivered, fetch_wire_bytes) =
            if config.fetch_payloads {
                fetch_payloads(
                    &cluster,
                    holder_index,
                    &entries,
                    &dissemination.informed,
                    config.trusted,
                    config.batch_fetch,
                )
                .await?
            } else {
                (0, 0, 0, 0)
            };
        let fetch_us = fetch_start.elapsed().as_micros();

        let total_wire_bytes = submit_request_bytes
            .checked_add(submit_response_bytes)
            .and_then(|sum| sum.checked_add(dissemination.wire_bytes))
            .and_then(|sum| sum.checked_add(fetch_wire_bytes))
            .ok_or_else(|| BlossomError::WireProtocol("wire byte overflow".to_string()))?;

        Ok(GossipBenchRow {
            iteration,
            nodes: config.nodes,
            entries: config.entries,
            payload_bytes: config.payload_bytes,
            fanout: config.fanout,
            targets_per_entry: config.targets_per_entry,
            trusted: config.trusted,
            fetch_payloads: config.fetch_payloads,
            batch_fetch: config.batch_fetch,
            gossip_rounds: dissemination.rounds,
            ideal_rounds: ideal_push_gossip_rounds(config.nodes, config.fanout),
            gossip_sends: dissemination.sends,
            gossip_accepted: dissemination.accepted,
            fetch_batches,
            fetches_attempted,
            fetches_delivered,
            metadata_wire_bytes: dissemination.wire_bytes,
            fetch_wire_bytes,
            total_wire_bytes,
            spawn_us,
            block_submit_us,
            gossip_build_us,
            gossip_disseminate_us,
            fetch_us,
            total_us: total_start.elapsed().as_micros(),
            informed_nodes: dissemination.informed_nodes,
            gossip_dropped: dissemination.dropped,
        })
    }

    async fn disseminate_gossip(
        cluster: &SimulatedCluster,
        holder_index: usize,
        gossip: &AvailabilityGossip,
        fanout: usize,
        drop_gossip_every: usize,
    ) -> MainResult<GossipDissemination> {
        let mut informed = vec![false; cluster.len()];
        informed[holder_index] = true;
        let mut frontier = vec![holder_index];
        let mut rounds = 0usize;
        let mut sends = 0usize;
        let mut attempts = 0usize;
        let mut dropped = 0usize;
        let mut accepted = 0usize;
        let mut wire_bytes = 0usize;
        let mut cursor = holder_index + 1;

        while informed.iter().any(|value| !*value) && !frontier.is_empty() && fanout > 0 {
            let mut next_frontier = Vec::new();
            for _sender in &frontier {
                let recipients = next_uninformed(&informed, &mut cursor, fanout);
                for recipient in recipients {
                    attempts += 1;
                    if drop_gossip_every > 0 && attempts.is_multiple_of(drop_gossip_every) {
                        dropped += 1;
                        continue;
                    }
                    let request = WireRequest::AvailabilityGossip(gossip.clone());
                    let request_bytes = wire_request_framed_len(&request)?;
                    let response = cluster.request(recipient, request).await?;
                    let response_bytes = wire_response_framed_len(&response)?;
                    wire_bytes = wire_bytes
                        .checked_add(request_bytes)
                        .and_then(|sum| sum.checked_add(response_bytes))
                        .ok_or_else(|| {
                            BlossomError::WireProtocol("wire byte overflow".to_string())
                        })?;
                    sends += 1;
                    match response {
                        WireResponse::AvailabilityReceipt(receipt) => {
                            accepted += receipt.entries_accepted;
                            informed[recipient] = true;
                            next_frontier.push(recipient);
                        }
                        WireResponse::Error(message) => {
                            return Err(BlossomError::WireProtocol(message).into());
                        }
                        response => return Err(unexpected("availability gossip", response).into()),
                    }
                }
            }
            rounds += 1;
            frontier = next_frontier;
        }

        let informed_nodes = informed.iter().filter(|value| **value).count();
        Ok(GossipDissemination {
            rounds,
            sends,
            accepted,
            wire_bytes,
            informed_nodes,
            dropped,
            informed,
        })
    }

    async fn fetch_payloads(
        cluster: &SimulatedCluster,
        holder_index: usize,
        entries: &[AvailabilityEntry],
        informed: &[bool],
        trusted: bool,
        batch_fetch: bool,
    ) -> MainResult<(usize, usize, usize, usize)> {
        if batch_fetch {
            fetch_payloads_batched(cluster, holder_index, entries, informed, trusted).await
        } else {
            fetch_payloads_single(cluster, holder_index, entries, informed, trusted).await
        }
    }

    async fn fetch_payloads_single(
        cluster: &SimulatedCluster,
        holder_index: usize,
        entries: &[AvailabilityEntry],
        informed: &[bool],
        trusted: bool,
    ) -> MainResult<(usize, usize, usize, usize)> {
        let mut batches = 0usize;
        let mut attempted = 0usize;
        let mut delivered = 0usize;
        let mut wire_bytes = 0usize;

        for (recipient_index, recipient_informed) in informed.iter().enumerate().take(cluster.len())
        {
            if recipient_index == holder_index || !*recipient_informed {
                continue;
            }
            let recipient = cluster.node(recipient_index);
            let requester = recipient.identity.public_key();
            for entry in entries {
                if !entry.slot.is_target(&requester) {
                    continue;
                }
                batches += 1;

                let body = FilteredPayloadFetchBody {
                    scope: ConsensusGroupId::root(),
                    requester,
                    slot_hash: entry.slot_hash,
                    payload_commitment: entry.slot.payload_commitment,
                };
                let fetch = if trusted {
                    FilteredPayloadFetch::trusted(body)
                } else {
                    FilteredPayloadFetch::signed(body, &recipient.keypair.signer())
                };

                let fetch_request = WireRequest::GetFilteredPayload(fetch);
                let fetch_request_bytes = wire_request_framed_len(&fetch_request)?;
                let fetch_response = cluster.request(holder_index, fetch_request).await?;
                let fetch_response_bytes = wire_response_framed_len(&fetch_response)?;
                wire_bytes = wire_bytes
                    .checked_add(fetch_request_bytes)
                    .and_then(|sum| sum.checked_add(fetch_response_bytes))
                    .ok_or_else(|| BlossomError::WireProtocol("wire byte overflow".to_string()))?;
                attempted += 1;

                let delivery = match fetch_response {
                    WireResponse::FilteredPayload(delivery) => delivery,
                    WireResponse::FilteredPayloadMissing(_) => continue,
                    WireResponse::Error(message) => {
                        return Err(BlossomError::WireProtocol(message).into());
                    }
                    response => return Err(unexpected("filtered payload fetch", response).into()),
                };

                let store_request = WireRequest::StoreFilteredPayload(delivery);
                let store_request_bytes = wire_request_framed_len(&store_request)?;
                let store_response = cluster.request(recipient_index, store_request).await?;
                let store_response_bytes = wire_response_framed_len(&store_response)?;
                wire_bytes = wire_bytes
                    .checked_add(store_request_bytes)
                    .and_then(|sum| sum.checked_add(store_response_bytes))
                    .ok_or_else(|| BlossomError::WireProtocol("wire byte overflow".to_string()))?;
                match store_response {
                    WireResponse::AvailabilityReceipt(receipt) => {
                        if receipt.entries_accepted > 0 {
                            delivered += 1;
                        }
                    }
                    WireResponse::Error(message) => {
                        return Err(BlossomError::WireProtocol(message).into());
                    }
                    response => return Err(unexpected("filtered payload store", response).into()),
                }
            }
        }

        Ok((batches, attempted, delivered, wire_bytes))
    }

    async fn fetch_payloads_batched(
        cluster: &SimulatedCluster,
        holder_index: usize,
        entries: &[AvailabilityEntry],
        informed: &[bool],
        trusted: bool,
    ) -> MainResult<(usize, usize, usize, usize)> {
        let mut batches = 0usize;
        let mut attempted = 0usize;
        let mut delivered = 0usize;
        let mut wire_bytes = 0usize;

        for (recipient_index, recipient_informed) in informed.iter().enumerate().take(cluster.len())
        {
            if recipient_index == holder_index || !*recipient_informed {
                continue;
            }
            let recipient = cluster.node(recipient_index);
            let requester = recipient.identity.public_key();
            let requests = entries
                .iter()
                .filter(|entry| entry.slot.is_target(&requester))
                .map(FilteredPayloadRequest::from)
                .collect::<Vec<_>>();
            if requests.is_empty() {
                continue;
            }

            let body = FilteredPayloadBatchFetchBody {
                scope: ConsensusGroupId::root(),
                requester,
                requests,
            };
            let fetch = if trusted {
                FilteredPayloadBatchFetch::trusted(body)?
            } else {
                FilteredPayloadBatchFetch::signed(body, &recipient.keypair.signer())?
            };
            let requested = fetch.body.requests.len();
            let fetch_request = WireRequest::GetFilteredPayloadBatch(fetch);
            let fetch_request_bytes = wire_request_framed_len(&fetch_request)?;
            let fetch_response = cluster.request(holder_index, fetch_request).await?;
            let fetch_response_bytes = wire_response_framed_len(&fetch_response)?;
            wire_bytes = wire_bytes
                .checked_add(fetch_request_bytes)
                .and_then(|sum| sum.checked_add(fetch_response_bytes))
                .ok_or_else(|| BlossomError::WireProtocol("wire byte overflow".to_string()))?;
            batches += 1;
            attempted += requested;

            let delivery = match fetch_response {
                WireResponse::FilteredPayloadBatch(delivery) => delivery,
                WireResponse::Error(message) => {
                    return Err(BlossomError::WireProtocol(message).into());
                }
                response => return Err(unexpected("filtered payload batch fetch", response).into()),
            };
            let delivered_items = delivery.body.items.len();

            let store_request = WireRequest::StoreFilteredPayloadBatch(delivery);
            let store_request_bytes = wire_request_framed_len(&store_request)?;
            let store_response = cluster.request(recipient_index, store_request).await?;
            let store_response_bytes = wire_response_framed_len(&store_response)?;
            wire_bytes = wire_bytes
                .checked_add(store_request_bytes)
                .and_then(|sum| sum.checked_add(store_response_bytes))
                .ok_or_else(|| BlossomError::WireProtocol("wire byte overflow".to_string()))?;
            match store_response {
                WireResponse::AvailabilityReceipt(receipt) => {
                    delivered += receipt.entries_accepted;
                    if receipt.entries_accepted != delivered_items {
                        return Err(BlossomError::WireProtocol(
                            "batch store receipt count mismatch".to_string(),
                        )
                        .into());
                    }
                }
                WireResponse::Error(message) => {
                    return Err(BlossomError::WireProtocol(message).into());
                }
                response => return Err(unexpected("filtered payload batch store", response).into()),
            }
        }

        Ok((batches, attempted, delivered, wire_bytes))
    }

    fn next_uninformed(informed: &[bool], cursor: &mut usize, fanout: usize) -> Vec<usize> {
        let mut recipients = Vec::with_capacity(fanout.min(informed.len()));
        if informed.is_empty() {
            return recipients;
        }
        let mut scanned = 0usize;
        while recipients.len() < fanout && scanned < informed.len() {
            let index = *cursor % informed.len();
            *cursor += 1;
            scanned += 1;
            if !informed[index] && !recipients.contains(&index) {
                recipients.push(index);
            }
        }
        recipients
    }

    fn targets_for_entry(
        cluster: &SimulatedCluster,
        entry_index: usize,
        targets_per_entry: usize,
    ) -> Vec<blossom::PubKey> {
        let candidate_count = cluster.len().saturating_sub(1);
        if candidate_count == 0 || targets_per_entry == 0 {
            return Vec::new();
        }
        let target_count = targets_per_entry.min(candidate_count);
        (0..target_count)
            .map(|offset| {
                let node_index = 1 + ((entry_index + offset) % candidate_count);
                cluster.node(node_index).identity.public_key()
            })
            .collect()
    }

    fn key_hash_for(entry_index: usize) -> HashType {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&(entry_index as u64).to_le_bytes());
        bytes[8..].copy_from_slice(b"gossip-k");
        HashType::hash(&bytes)
    }

    fn payload_for(iteration: usize, entry_index: usize, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        let mut seed = (iteration as u64)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add((entry_index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93));
        for chunk in bytes.chunks_mut(8) {
            seed = splitmix64(seed);
            let seed_bytes = seed.to_le_bytes();
            let take = chunk.len();
            chunk.copy_from_slice(&seed_bytes[..take]);
        }
        bytes
    }

    fn splitmix64(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = value;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn unexpected(context: &str, response: WireResponse) -> BlossomError {
        BlossomError::WireProtocol(format!(
            "{context}: unexpected response {}",
            response.kind()
        ))
    }

    fn write_csv(path: &PathBuf, append: bool, rows: &[GossipBenchRow]) -> MainResult<()> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }

        let write_header = !append || !path.exists() || path.metadata()?.len() == 0;
        let mut file = OpenOptions::new()
            .create(true)
            .append(append)
            .write(true)
            .truncate(!append)
            .open(path)?;

        if write_header {
            writeln!(
                file,
                "iteration,nodes,entries,payload_bytes,fanout,targets_per_entry,trusted,fetch_payloads,batch_fetch,gossip_rounds,ideal_rounds,gossip_sends,gossip_accepted,fetch_batches,fetches_attempted,fetches_delivered,metadata_wire_bytes,fetch_wire_bytes,total_wire_bytes,spawn_us,block_submit_us,gossip_build_us,gossip_disseminate_us,fetch_us,total_us,informed_nodes,gossip_dropped"
            )?;
        }
        for row in rows {
            writeln!(file, "{}", row.to_csv())?;
        }
        Ok(())
    }

    impl GossipBenchRow {
        fn to_csv(&self) -> String {
            format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                self.iteration,
                self.nodes,
                self.entries,
                self.payload_bytes,
                self.fanout,
                self.targets_per_entry,
                self.trusted,
                self.fetch_payloads,
                self.batch_fetch,
                self.gossip_rounds,
                self.ideal_rounds
                    .map(|rounds| rounds.to_string())
                    .unwrap_or_default(),
                self.gossip_sends,
                self.gossip_accepted,
                self.fetch_batches,
                self.fetches_attempted,
                self.fetches_delivered,
                self.metadata_wire_bytes,
                self.fetch_wire_bytes,
                self.total_wire_bytes,
                self.spawn_us,
                self.block_submit_us,
                self.gossip_build_us,
                self.gossip_disseminate_us,
                self.fetch_us,
                self.total_us,
                self.informed_nodes,
                self.gossip_dropped
            )
        }

        fn validate_complete(&self) -> MainResult<()> {
            if self.informed_nodes != self.nodes {
                return Err(BlossomError::WireProtocol(format!(
                    "gossip reached {}/{} nodes",
                    self.informed_nodes, self.nodes
                ))
                .into());
            }
            if self.fetch_payloads && self.fetches_delivered != self.fetches_attempted {
                return Err(BlossomError::WireProtocol(format!(
                    "filtered payload delivery completed {}/{} fetches",
                    self.fetches_delivered, self.fetches_attempted
                ))
                .into());
            }
            Ok(())
        }
    }
}

#[cfg(feature = "availability-gossip")]
#[tokio::main]
async fn main() -> bench::MainResult<()> {
    bench::main().await
}
