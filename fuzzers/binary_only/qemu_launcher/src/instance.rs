use core::{fmt::Debug, ptr::addr_of_mut};
use std::{fs, marker::PhantomData, ops::Range, process, time::Duration};

#[cfg(feature = "simplemgr")]
use libafl::events::SimpleEventManager;
#[cfg(not(feature = "simplemgr"))]
use libafl::events::{LlmpRestartingEventManager, MonitorTypedEventManager};

#[allow(unused_imports)]
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{EventRestarter, NopEventManager},
    executors::{Executor, ShadowExecutor, write_to_file},
    feedback_or, feedback_or_fast, feedback_and_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback, NewHashFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::Monitor,
    mutators::{
        havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations, StdMOptMutator,
        StdScheduledMutator, Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver, BacktraceObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, AflStatsStage, IfStage,
        ShadowTracingStage, StagesTuple, StdMutationalStage,
    },
    state::{HasCorpus, StdState, UsesState},
    Error, HasMetadata, NopFuzzer,
};
#[cfg(not(feature = "simplemgr"))]
use libafl_bolts::shmem::StdShMemProvider;
use libafl_bolts::{
    core_affinity::CoreId, ownedref::{OwnedMutSlice, OwnedRefMut}, rands::StdRand, shmem::ShMemProvider, tuples::{tuple_list, Merge, Prepend}
};
use libafl_qemu::{
    elf::EasyElf,
    modules::{
        cmplog::CmpLogObserver, EmulatorModuleTuple, StdAddressFilter, StdEdgeCoverageModule,
        EdgeCoverageModule, AddressFilter, StdPageFilter, EdgeCoverageFullVariant,
        AsanModule
    },
    Emulator, GuestAddr, Qemu, QemuExecutor,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use typed_builder::TypedBuilder;

use crate::{harness::Harness, options::FuzzerOptions};

pub type ClientState =
    StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

#[cfg(feature = "simplemgr")]
pub type ClientMgr<M> = SimpleEventManager<M, ClientState>;
#[cfg(not(feature = "simplemgr"))]
pub type ClientMgr<M> =
    MonitorTypedEventManager<LlmpRestartingEventManager<(), ClientState, StdShMemProvider>, M>;

#[derive(TypedBuilder)]
pub struct Instance<'a, M: Monitor> {
    options: &'a FuzzerOptions,
    /// The harness. We create it before forking, then `take()` it inside the client.
    #[builder(setter(strip_option))]
    harness: Option<Harness>,
    qemu: Qemu,
    mgr: ClientMgr<M>,
    core_id: CoreId,
    #[builder(default)]
    extra_tokens: Vec<String>,
    #[builder(default=PhantomData)]
    phantom: PhantomData<M>,
}

impl<M: Monitor> Instance<'_, M> {
    #[allow(clippy::similar_names)] // elf != self
    fn coverage_filter(&self, qemu: Qemu) -> Result<StdAddressFilter, Error> {
        /* Conversion is required on 32-bit targets, but not on 64-bit ones */
        if let Some(includes) = &self.options.include {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = includes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(StdAddressFilter::allow_list(rules))
        } else if let Some(excludes) = &self.options.exclude {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = excludes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(StdAddressFilter::deny_list(rules))
        } else {
            let mut elf_buffer = Vec::new();
            let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;
            let range = elf
                .get_section(".text", qemu.load_addr())
                .ok_or_else(|| Error::key_not_found("Failed to find .text section"))?;
            Ok(StdAddressFilter::allow_list(vec![range]))
        }
    }

    pub fn get_dynamic_sanitization_filter(&self, 
        edge_module: &EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageFullVariant>, 
        options: &FuzzerOptions, ratio_elapsed: u64) -> Result<StdAddressFilter, Error> 
        {
        let mut exclude_brutal = Some(vec![Range {
            start: GuestAddr::from_str_radix("7f0000000000", 16).unwrap(),
            end: GuestAddr::from_str_radix("7f0000001000", 16).unwrap(),
        }]);
        // Remove the hardcoded range
        exclude_brutal.as_mut().unwrap().clear();

        if (options.ratio_start == 0) || (u64::from(options.ratio_start) <= ratio_elapsed) {
            let hitcounts = edge_module.get_rolling_hitcounts();

            let mut dynamic_sanitizer_ratio = options.dynamic_sanitizer_ratio;

            if options.reverse_mode {
                // After ratio_elapsed passes 10, set dynamic_sanitizer_ratio to 80, after 20 set to 70, etc.
                if ratio_elapsed >= 10 {
                    dynamic_sanitizer_ratio = 80;
                }
                if ratio_elapsed >= 20 {
                    dynamic_sanitizer_ratio = 70;
                }
                if ratio_elapsed >= 30 {
                    dynamic_sanitizer_ratio = 60;
                }
                if ratio_elapsed >= 40 {
                    dynamic_sanitizer_ratio = 50;
                }
                if ratio_elapsed >= 50 {
                    dynamic_sanitizer_ratio = 40;
                }
                if ratio_elapsed >= 60 {
                    dynamic_sanitizer_ratio = 30;
                }
                if ratio_elapsed >= 70 {
                    dynamic_sanitizer_ratio = 20;
                }
                if ratio_elapsed >= 80 {
                    dynamic_sanitizer_ratio = 10;
                }
                if ratio_elapsed >= 90 {
                    dynamic_sanitizer_ratio = 0;
                }
            }

            if dynamic_sanitizer_ratio != 0 {
                // Sort the hitcounts by value
                let mut hitcounts: Vec<_> = hitcounts.iter().collect();
                hitcounts.sort_by(|a, b| b.1.cmp(a.1));

                // Get only top dynamic_sanitizer_ratio% of the hitcounts
                let cutoff = hitcounts.len() * dynamic_sanitizer_ratio as usize / 100;
                let hitcounts = hitcounts.iter().take(cutoff).collect::<Vec<_>>();

                for (key, value) in hitcounts.iter() {
                    let cutoff = self.options.dynamic_sanitizer_cutoff;
                    if **value > cutoff {
                        let addr_start = GuestAddr::from_str_radix(&format!("{:x}", key.0), 16).unwrap();
                        let addr_end = GuestAddr::from_str_radix(&format!("{:x}", key.1), 16).unwrap();
                        exclude_brutal.as_mut().unwrap().push(Range {
                            start: addr_start,
                            end: addr_end,
                        });
                    }
                }
            } else {
                for (key, value) in hitcounts.iter() {
                    let cutoff = self.options.dynamic_sanitizer_cutoff;
                    if *value > cutoff {
                        let addr_start = GuestAddr::from_str_radix(&format!("{:x}", key.0), 16).unwrap();
                        let addr_end = GuestAddr::from_str_radix(&format!("{:x}", key.1), 16).unwrap();
                        exclude_brutal.as_mut().unwrap().push(Range {
                            start: addr_start,
                            end: addr_end,
                        });
                    }
                }
            }
        }
        
        #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
        if let Some(excludes) = &exclude_brutal {
            let rules = excludes
            .iter()
            .map(|x| Range {
                start: x.start.into(),
                end: x.end.into(),
            })
            .collect::<Vec<Range<GuestAddr>>>();
            Ok(StdAddressFilter::deny_list(rules))
        } else {
            Err(Error::empty_optional("Failed to get dynamic sanitization filter"))
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn run<ET>(&mut self, mut modules: ET, state: Option<ClientState>, core_id: CoreId, ratio_elapsed: u64) -> Result<(), Error>
    where
        ET: EmulatorModuleTuple<ClientState> + Debug,
    {
        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                addr_of_mut!(MAX_EDGES_FOUND),
            ))
            .track_indices()
        };

        let use_edge_dynamic_sanitization = self.options.dynamic_sanitizer && !self.options.use_blocks;

        let edge_coverage_module = StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .address_filter(self.coverage_filter(self.qemu)?)
            .core_id(core_id.0)
            .dynamic_sanitization(use_edge_dynamic_sanitization)
            .build()?;

        if use_edge_dynamic_sanitization {
            let asan_filter = self.get_dynamic_sanitization_filter(&edge_coverage_module, self.options, ratio_elapsed)?;
            let filter_string = asan_filter.convert_to_string();
            let filter_file = format!("resulting_filter{}", core_id.0);
            write_to_file("./tmp", &filter_file, &filter_string);

            if (self.options.reverse_mode && ratio_elapsed > 10) || !self.options.reverse_mode  {
                let asan_module: &mut AsanModule = modules.match_first_type_mut().unwrap();
                asan_module.set_filter(asan_filter);
            }
            
        }
        
        let modules = modules.prepend(edge_coverage_module);

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new(&edges_observer);

        let calibration = CalibrationStage::new(&map_feedback);

        let stats_stage = IfStage::new(
            |_, _, _, _| Ok(self.options.tui),
            tuple_list!(AflStatsStage::new(Duration::from_secs(5))),
        );

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut bt = shmem_provider.new_on_shmem::<Option<u64>>(None).unwrap();
        let bt_observer = BacktraceObserver::new(
            "BacktraceObserver",
            unsafe { OwnedRefMut::from_shmem(&mut bt) },
            libafl::observers::HarnessType::InProcess,
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_and_fast!(CrashFeedback::new());

        // // If not restarting, create a State from scratch
        let mut state = match state {
            Some(x) => x,
            None => {
                StdState::new(
                    // RNG
                    StdRand::new(),
                    // Corpus that will be evolved, we keep it in memory for performance
                    InMemoryOnDiskCorpus::no_meta(self.options.queue_dir(self.core_id))?,
                    // Corpus in which we store solutions (crashes in this example),
                    // on disk so the user can get them after stopping the fuzzer
                    OnDiskCorpus::new(self.options.crashes_dir(self.core_id))?,
                    // States of the feedbacks.
                    // The feedbacks can report the data that should persist in the State.
                    &mut feedback,
                    // Same for objective feedbacks
                    &mut objective,
                )?
            }
        };

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(
            &edges_observer,
            PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
        );

        let observers = tuple_list!(edges_observer, time_observer);

        let mut tokens = Tokens::new();

        for token in &self.extra_tokens {
            let bytes = token.as_bytes().to_vec();
            let _ = tokens.add_token(&bytes);
        }

        if let Some(tokenfile) = &self.options.tokens {
            tokens.add_from_file(tokenfile)?;
        }

        state.add_metadata(tokens);

        let harness = self
            .harness
            .take()
            .expect("The harness can never be None here!");
        harness.post_fork();

        let mut harness = |_emulator: &mut Emulator<_, _, _, _, _>,
                           _state: &mut _,
                           input: &BytesInput| harness.run(input);

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let emulator = Emulator::empty().qemu(self.qemu).modules(modules).build()?;

        if let Some(rerun_input) = &self.options.rerun_input {
            // TODO: We might want to support non-bytes inputs at some point?
            let bytes = fs::read(rerun_input)
                .unwrap_or_else(|_| panic!("Could not load file {rerun_input:?}"));
            let input = BytesInput::new(bytes);

            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            executor
                .run_target(
                    &mut NopFuzzer::new(),
                    &mut state,
                    &mut NopEventManager::new(),
                    &input,
                )
                .expect("Error running target");
            // We're done :)
            process::exit(0);
        }

        if self.options.is_cmplog_core(self.core_id) {
            // Create a QEMU in-process executor
            let executor = QemuExecutor::new(
                emulator,
                &mut harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            // Create an observation channel using cmplog map
            let cmplog_observer = CmpLogObserver::new("cmplog", true);

            let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

            let tracing = ShadowTracingStage::new(&mut executor);

            // Setup a randomic Input2State stage
            let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
                I2SRandReplace::new()
            )));

            // Setup a MOPT mutator
            let mutator = StdMOptMutator::new::<BytesInput, _>(
                &mut state,
                havoc_mutations().merge(tokens_mutations()),
                7,
                5,
            )?;

            let power: StdPowerMutationalStage<_, _, BytesInput, _, _> =
                StdPowerMutationalStage::new(mutator);

            // The order of the stages matter!
            let mut stages = tuple_list!(calibration, tracing, i2s, power, stats_stage);

            self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
        } else {
            // Create a QEMU in-process executor
            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            // Setup an havoc mutator with a mutational stage
            let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
        }
    }

    fn fuzz<Z, E, ST>(
        &mut self,
        state: &mut ClientState,
        fuzzer: &mut Z,
        executor: &mut E,
        stages: &mut ST,
    ) -> Result<(), Error>
    where
        Z: Fuzzer<E, ClientMgr<M>, ST>
            + UsesState<State = ClientState>
            + Evaluator<E, ClientMgr<M>, State = ClientState>,
        E: UsesState<State = ClientState>,
        ST: StagesTuple<E, ClientMgr<M>, ClientState, Z>,
    {
        let corpus_dirs = [self.options.input_dir()];

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(fuzzer, executor, &mut self.mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {corpus_dirs:?}");
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        if let Some(iters) = self.options.iterations {
            fuzzer.fuzz_loop_for(stages, executor, state, &mut self.mgr, iters)?;

            // It's important, that we store the state before restarting!
            // Else, the parent will not respawn a new child and quit.
            self.mgr.on_restart(state)?;
        } else {
            fuzzer.fuzz_loop(stages, executor, state, &mut self.mgr)?;
        }

        Ok(())
    }
}
