use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{self, Duration, Instant};
use tokio::timer::Interval;

use std::time::{Duration, Instant};

use futures::future;
use futures::prelude::*;
use futures::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use parking_lot::{Mutex, RwLock};
use tokio::runtime::TaskExecutor;
use tokio::timer::Delay;

use codec::{Codec, Decode, Encode};

// dependencies on substrate
use sp_runtime::traits::Block as BlockT;
use sp_core::sr25519::LocalizedSignature;
use sc_consensus_bftml::{AuthorityId, BftmlChannelMsg};


// how to import LocalizedSignature ?
// TODO: import LocalizedSignature, BlockT, AuthorityId

pub type Committed<B> = rhododendron::Committed<B, <B as BlockT>::Hash, LocalizedSignature>;
pub type Communication<B> = rhododendron::Communication<B, <B as BlockT>::Hash, AuthorityId, LocalizedSignature>;
pub type Misbehavior<H> = rhododendron::Misbehavior<H, LocalizedSignature>;
//pub type SharedOfflineTracker = Arc<RwLock<OfflineTracker>>;

/// A future that resolves either when canceled (witnessing a block from the network at same height)
/// or when agreement completes.
pub struct RhdWorker<B> where
    B: BlockT + Clone + Eq,
    B::Hash: sp_std::hash::Hash,
{
    te_tx: Option<UnboundedSender<Communication>>,     // to engine tx, used in this caller layer
    fe_rx: Option<UnboundedReceiver<Communication>>,   // from engine rx, used in this caller layer
    cm_rx: Option<UnboundedReceiver<BftmlChannelMsg>>,

    tc_rx: UnboundedReceiver<BftmlChannelMsg>,
    ts_tx: UnboundedSender<BftmlChannelMsg>,
    cb_tx: UnboundedSender<BftmlChannelMsg>,
    ib_rx: UnboundedReceiver<BftmlChannelMsg>,
    ap_tx: UnboundedSender<BftmlChannelMsg>,
    gp_rx: UnboundedReceiver<BftmlChannelMsg>,

    bft_task_running: bool,
    timer_running: bool,
}

// rhd worker main poll
impl<B> Future for RhdWorker<B> where
    B: BlockT + Clone + Eq,
    B::Hash: sp_std::hash::Hash,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        if !self.timer_running {
            //[XXX]: start a task in a poll? Does it work? Need to test
            self.start_timer();
        }

        // receive protocol msg from bftml, forward it to the rhd engine
        // [XXX]: ? need match corrent error type
        // add this .map_err(|e|())
        match self.tc_rx.poll()? {
            Async::Ready(Some(msg)) => {
                // msg reform
                match msg {
                    BftmlChannelMsg::GossipMsgIncoming(avec) => {
                        if self.te_tx.is_some() {
                            // [XXX]: decode vec<u8> to type Communication<B>, does this work?
                            //let msg: Communication<B> = avec.decode();
                            let msg: Communication<B> = Decode::decode(&mut &avec[..]).expect("GossipMsgIncoming serialized msg is corrupted.");
                            
                            // then forward it
                            // because te_tx here is an Option
                            // self.te_tx.unbounded_send(msg);
                            let _ = self.te_tx.as_ref().map(|c|c.unbounded_send(msg));
                        }
                    }
                    _ => {}
                }

            }
            _ => {}
        }

        // receive rhd engine protocol msg, forward it to bftml
        if self.fe_rx.is_some() {
            // we think taking action always success
            let c = self.fe_rx.take().unwrap();
            match c.poll()? {
                Async::Ready(Some(msg)) => {
                    // msg reform

                    // encode it 
                    // [XXX]: make sure this correct?
                    let avec = msg.encode();

                    // and wrap it to BftmlChannelMsg
                    self.ts_tx.unbounded_send(BftmlChannelMsg::GossipMsgOutgoing(avec));
                }
                _ => {}
            }
            // restore it
            self.fe_rx = Some(c);
        }

        // imported block
        match self.ib_rx.poll()? {
            Async::Ready(Some(msg)) => {
                // Nothing to do here on new design
            }
            _ => {}
        }

        // receive rhd engine block commit msg
        if self.cm_rx.is_some() {
            let c = self.cm_rx.take().unwrap();
            match c.poll()? {
                Async::Ready(Some(commit_msg)) => {
                    // forward commit block msg to bftml
                    self.cb_tx.unbounded_send(commit_msg);
                }
                _ => {},
            }
            // restore it
            self.cm_rx = Some(c);
        }

        Ok(Async::NotReady)
    }
}

impl<B> RhdWorker<B> where
    B: BlockT + Clone + Eq,
    B::Hash: sp_std::hash::Hash,
{
    pub fn new(
        authorities: Vec<AuthorityID>,
        tc_rx: UnboundedReceiver<BftmlChannelMsg>,
        ts_tx: UnboundedSender<BftmlChannelMsg>,
        cb_tx: UnboundedSender<BftmlChannelMsg>,
        ib_rx: UnboundedReceiver<BftmlChannelMsg>,
        ap_tx: UnboundedSender<BftmlChannelMsg>,
        gp_rx: UnboundedReceiver<BftmlChannelMsg>,) -> RhdWorker {

        RhdWorker {
            te_tx: None,
            fe_rx: None,
            cm_rx: None,

            tc_rx,
            ts_tx,
            cb_tx,
            ib_rx,
            ap_tx,
            gp_rx,

            bft_task_running: false,
            timer_running: false,
        }
    }

    fn start_once_bft(&mut self) {
        //[XXX]: could allow clone?
        let arc_rhd_worker = Arc::new(self).clone();

        // TODO: where authorities come from?
        let rhd_context = RhdContext {
            authorities: authorities,
            rhd_worker: arc_rhd_worker,
        };

        let (te_tx, te_rx): (UnboundedSender<Communication<B>>, UnboundedReceiver<Communication<B>>) = mpsc::unbounded();
        let (fe_tx, fe_rx): (UnboundedSender<Communication<B>>, UnboundedReceiver<Communication<B>>) = mpsc::unbounded();
        let (cm_tx, cm_rx): (UnboundedSender<BftmlChannelMsg>, UnboundedReceiver<BftmlChannelMsg>) = mpsc::unbounded();

        let n = authorities.len();
        let max_faulty = n / 3 as u32;
        let mut agreement = rhododendron::agree(
            rhd_context,
            n,
            max_faulty,
            te_rx, // input
            fe_tx, // output
        );

        self.te_tx = Some(te_tx);
        self.fe_rx = Some(fe_rx);
        self.cm_rx = Some(cm_rx);

        tokio::spawn(futures::future::poll_fn(move || -> Poll<(), ()> {
            //[XXX]: could use like this here? this is a cloned arc 
            arc_rhd_worker.bft_task_running = true;

            match agreement.poll()? {
                Async::Ready(Some(commit_msg)) => {
                    // the result of poll of agreement is Committed<>, deal with it
                    // fit it into BftmlChannelMsg
                    cm_tx.unbounded_send(commit_msg);

                    // set back
                    arc_rhd_worker.bft_task_running = false;
                    arc_rhd_worker.te_tx = None;
                    arc_rhd_worker.fe_rx = None;
                    arc_rhd_worker.cm_rx = None;

                    // [TODO]: when this finish, it's better to notify the outer to start next block bft round
                    // do it later

                    return Ok(Async::Ready);
                }
                _ => Ok(Async::NotReady),
            }

            Ok(Async::NotReady)
        }));
    }

    // start the ticks to advance the bft round
    fn start_timer(&mut self) {
        // use 10ms to check it as soon as possible
        let task = Interval::new(Instant::now(), Duration::from_millis(10))
            .for_each(|instant| {
                // when no bft task exist, run one
                if !self.bft_task_running {
                    self.start_once_bft();
                }
                println!("fire; instant={:?}", instant);
                Ok(())
            })
            .map_err(|e| panic!("interval errored; err={:?}", e));

        tokio::spawn(task);
        self.timer_running = true;
    }
}

/// Instance of Rhd engine context
struct RhdContext<B: BlockT> {
    //    key: Arc<ed25519::Pair>,
    authorities: Vec<AuthorityId>,
    rhd_worker: Arc<RhdWorker>,
    //    parent_hash: B::Hash,
    //    round_timeout_multiplier: u64,
    //    cache: Arc<Mutex<RoundCache<B::Hash>>>,
}

impl<B: BlockT> rhododendron::Context for RhdContext<B> where
    B: Clone + Eq,
    B::Hash: sp_std::hash::Hash,
{
    type Error = P::Error;
    type AuthorityId = AuthorityId;
    type Digest = B::Hash;
    type Signature = LocalizedSignature;
    type Candidate = B;
    type RoundTimeout = Box<Future<Item = (), Error = Self::Error>>;
    type CreateProposal = <P::Create as IntoFuture>::Future;
    type EvaluateProposal = <P::Evaluate as IntoFuture>::Future;

    fn local_id(&self) -> AuthorityId {
        self.key.public().into()
    }

    fn proposal(&self) -> Self::CreateProposal {
        //let ask_proposal_msg = ...;
        self.rhd_worker.ap_tx.unbounded_send( ask_proposal_msg );

        poll_fn(move || {
            match self.rhd_worker.gp_rx.poll()? {
                Async::Ready(Some(proposal)) => {
                    Async::Ready(proposal)
                }
                _ => {}
            }
        })
    }

    fn candidate_digest(&self, proposal: &B) -> B::Hash {
        proposal.hash()
    }

    fn sign_local(&self, message: RhdMessage<B, B::Hash>) -> LocalizedMessage<B> {
        sign_message(message, &*self.key, self.parent_hash.clone())
    }

    fn round_proposer(&self, round: u32) -> AuthorityId {
        //self.proposer.round_proposer(round, &self.authorities[..])
    }

    fn proposal_valid(&self, proposal: &B) -> Self::EvaluateProposal {
        //self.proposer.evaluate(proposal).into_future()
        poll_fn(move || Async::Ready(true))
    }

    fn begin_round_timeout(&self, round: u32) -> Self::RoundTimeout {
        let timeout = self.round_timeout_duration(round);
        let fut = Delay::new(Instant::now() + timeout)
            .map_err(|e| Error::from(CommonErrorKind::FaultyTimer(e)))
            .map_err(Into::into);

        Box::new(fut)
    }

    fn on_advance_round(
        &self,
        accumulator: &rhododendron::Accumulator<B, B::Hash, Self::AuthorityId, Self::Signature>,
        round: u32,
        next_round: u32,
        reason: AdvanceRoundReason,
        ) {
        use std::collections::HashSet;

        let collect_pubkeys = |participants: HashSet<&Self::AuthorityId>| {
            participants
                .into_iter()
                .map(|p| ::ed25519::Public::from_raw(p.0))
                .collect::<Vec<_>>()
        };

        let round_timeout = self.round_timeout_duration(next_round);
        debug!(target: "rhd", "Advancing to round {} from {}", next_round, round);
        debug!(target: "rhd", "Participating authorities: {:?}",
               collect_pubkeys(accumulator.participants()));
        debug!(target: "rhd", "Voting authorities: {:?}",
               collect_pubkeys(accumulator.voters()));
        debug!(target: "rhd", "Round {} should end in at most {} seconds from now", next_round, round_timeout.as_secs());

        self.update_round_cache(next_round);

        if let AdvanceRoundReason::Timeout = reason {
            self.proposer
                .on_round_end(round, accumulator.proposal().is_some());
        }
    }
}

use sc_bftml::gen;

//
// We must use some basic types defined in Substrate, imported and use here
// We can specify and wrap all these types in bftml, and import them from bftml module
// to reduce noise on your eye
pub fn make_rhd_worker_pair<B, E, I>(
    client: E,
    block_import: I,
    proposer_factory: E::Proposer,
    imported_block_rx: UnboundedReceiver<BlockImportParams>,
    ) -> Result<
(
    impl futures01::Future<Item = (), Error = ()>,
    impl futures01::Future<Item = (), Error = ()>,
    ),
    sp_consensus::Error,
    >
    where
    B: BlockT,
    E: Environment<B, Error = Error> + Send + Sync,
    E::Proposer: Proposer<B, Error = Error>,
    <E::Proposer as Proposer<B>>::Create: Unpin + Send + 'static,
    I: BlockImport<B, Error = ConsensusError> + Send + Sync + 'static,
{
    // generate channels
    let (tc_tx, tc_rx, ts_tx, ts_rx) = gen::gen_consensus_msg_channels();
    let (cb_tx, cb_rx) = gen::gen_commit_block_channel();
    let (ib_tx, ib_rx) = gen::gen_import_block_channel();
    let (ap_tx, ap_rx) = gen::gen_ask_proposal_channel();
    let (gp_tx, gp_rx) = gen::gen_give_proposal_channel();

    let bftml_worker = BftmlWorker::new(
        client.clone(),
        Arc::new(Mutex::new(block_import)),
        proposer_factory,
        imported_block_rx,
        tc_tx,
        ts_rx,
        cb_rx,
        ib_tx,
        ap_rx,
        gp_tx,);

    let rhd_worker = RhdWorker::new(
        tc_rx,
        ts_tx,
        cb_tx,
        ib_rx,
        ap_tx,
        gp_rx,);

    Ok((bftml_worker, rhd_worker))
}
