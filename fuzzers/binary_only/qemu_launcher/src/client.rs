use std::{env, ops::Range};

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    inputs::BytesInput,
    monitors::Monitor,
    state::StdState,
    Error,
    executors::write_to_file
};
use libafl_bolts::{core_affinity::CoreId, current_time, rands::StdRand, tuples::tuple_list};
#[cfg(feature = "injections")]
use libafl_qemu::modules::injections::InjectionModule;
use libafl_qemu::{
    modules::{
        asan::{init_qemu_with_asan, AsanModule, QemuAsanOptions}, asan_guest::{init_qemu_with_asan_guest, AsanGuestModule}, cmplog::CmpLogModule, DrCovModule,
        // IsFilter, QemuInstrumentationAddressRangeFilter,
        StdAddressFilter, AddressFilter,
        blocks::BlockCoverageModule
    },
    Qemu, GuestAddr
};

use crate::{
    harness::Harness,
    instance::{ClientMgr, Instance},
    options::FuzzerOptions
};

#[allow(clippy::module_name_repetitions)]
pub type ClientState =
    StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl Client<'_> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    pub fn args(&self) -> Result<Vec<String>, Error> {
        let program = env::args()
            .next()
            .ok_or_else(|| Error::empty_optional("Failed to read program name"))?;

        let mut args = self.options.args.clone();
        args.insert(0, program);
        Ok(args)
    }

    #[allow(clippy::unused_self)] // Api should look the same as args above
    pub fn env(&self) -> Vec<(String, String)> {
        env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>()
    }

    pub fn get_dynamic_sanitization_filter(&self, block_module: &BlockCoverageModule<StdAddressFilter>, options: &FuzzerOptions, ratio_elapsed: u64) -> Result<StdAddressFilter, Error> {
        let mut exclude_brutal = Some(vec![Range {
            start: GuestAddr::from_str_radix("7f0000000000", 16).unwrap(),
            end: GuestAddr::from_str_radix("7f0000001000", 16).unwrap(),
        }]);
        // Remove the hardcoded range
        exclude_brutal.as_mut().unwrap().clear();

        if (options.ratio_start == 0) || (u64::from(options.ratio_start) <= ratio_elapsed) {
            let hitcounts = block_module.get_rolling_hitcounts();

            if options.dynamic_sanitizer_ratio != 0 {
                // Sort the hitcounts by value
                let mut hitcounts: Vec<_> = hitcounts.iter().collect();
                hitcounts.sort_by(|a, b| b.1.cmp(a.1));

                // Get only top options.dynamic_sanitizer_ratio% of the hitcounts
                let cutoff = hitcounts.len() * options.dynamic_sanitizer_ratio as usize / 100;
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

    pub fn run<M: Monitor>(
        &self,
        state: Option<ClientState>,
        mgr: ClientMgr<M>,
        core_id: CoreId,
        start_seconds: u64,
        end_seconds: u64,
    ) -> Result<(), Error> {
        let current_seconds = current_time().as_secs();
        if current_seconds >= end_seconds {
            return Err(Error::ShuttingDown);        
        }

        // Get percentage of campaign duration elapsed
        let duration = end_seconds - start_seconds;
        let remaining = end_seconds - current_seconds;
        let ratio_elapsed = 100 - (remaining * 100 / duration);

        let mut args = self.args()?;
        Harness::edit_args(&mut args);
        log::debug!("ARGS: {:#?}", args);

        let mut env = self.env();
        Harness::edit_env(&mut env);
        log::debug!("ENV: {:#?}", env);

        let mut is_asan = self.options.is_asan_core(core_id);
        let is_asan_guest = self.options.is_asan_guest_core(core_id);

        if is_asan && is_asan_guest {
            Err(Error::empty_optional("Multiple ASAN modes configured"))?;
        }

        let (qemu, mut asan, mut asan_lib) = {
            if is_asan {
                let (emu, asan) = init_qemu_with_asan(&mut args, &mut env)?;
                (emu, Some(asan), None)
            } else if is_asan_guest {
                let (emu, asan_lib) = init_qemu_with_asan_guest(&mut args, &mut env)?;
                (emu, None, Some(asan_lib))
            } else {
                (Qemu::init(&args)?, None, None)
            }
        };

        #[cfg(not(feature = "injections"))]
        let injection_module = None;

        #[cfg(feature = "injections")]
        let injection_module = self
            .options
            .injections
            .as_ref()
            .and_then(|injections_file| {
                let lower = injections_file.to_lowercase();
                if lower.ends_with("yaml") || lower.ends_with("yml") {
                    Some(InjectionModule::from_yaml(injections_file).unwrap())
                } else if lower.ends_with("toml") {
                    Some(InjectionModule::from_toml(injections_file).unwrap())
                } else {
                    None
                }
            });

        let harness = Harness::init(qemu).expect("Error setting up harness.");

        let is_cmplog = self.options.is_cmplog_core(core_id);

        let extra_tokens = injection_module
            .as_ref()
            .map(|h| h.tokens.clone())
            .unwrap_or_default();

        let instance_builder = Instance::builder()
            .options(self.options)
            .qemu(qemu)
            .harness(harness)
            .mgr(mgr)
            .core_id(core_id)
            .extra_tokens(extra_tokens);

        if self.options.reverse_mode {
            // If 1 hour hasn't yet passed, set is_asan to false
            if ratio_elapsed < 10 {
                is_asan = false;
            }
        } 

        if self.options.rerun_input.is_some() && self.options.drcov.is_some() {
            // Special code path for re-running inputs with DrCov.
            // TODO: Add ASan support, injection support
            let drcov = self.options.drcov.as_ref().unwrap();
            let drcov = DrCovModule::builder()
                .filename(drcov.clone())
                .full_trace(true)
                .build();
            instance_builder.build().run(tuple_list!(drcov), state, core_id, ratio_elapsed)
        } else if is_asan && is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanModule::default(asan.take().unwrap()),
                        injection_module,
                    ),
                    state,
                    core_id, 
                    ratio_elapsed
                )
            } else {
                instance_builder.build().run(
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanModule::default(asan.take().unwrap()),
                    ),
                    state,
                    core_id, 
                    ratio_elapsed
                )
            }
        } else if is_asan_guest && is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanGuestModule::default(qemu, &asan_lib.take().unwrap()),
                        injection_module
                    ),
                    state,
                    core_id, 
                    ratio_elapsed
                )
            } else {
                instance_builder.build().run(
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanGuestModule::default(qemu, &asan_lib.take().unwrap()),
                    ),
                    state,
                    core_id, 
                    ratio_elapsed
                )
            }
        } else if is_asan {
            if let Some(injection_module) = injection_module {
                if self.options.dynamic_sanitizer {
                    if self.options.use_blocks {
                        let block_module = BlockCoverageModule::new(core_id.0, StdAddressFilter::default());
                        let asan_filter = self.get_dynamic_sanitization_filter(&block_module, self.options, ratio_elapsed)?;
                        let filter_string = asan_filter.convert_to_string();
                        let filter_file = format!("resulting_filter{}", core_id.0);
                        write_to_file("./tmp", &filter_file, &filter_string);
                        instance_builder.build().run(
                            tuple_list!(
                                AsanModule::new(asan.take().unwrap(), asan_filter, &QemuAsanOptions::Snapshot),
                                injection_module,
                                block_module
                            ),
                            state,
                            core_id, 
                            ratio_elapsed
                        )
                    } else {
                        instance_builder.build().run(
                            tuple_list!(
                                AsanModule::default(asan.take().unwrap()),
                                injection_module,
                            ),
                            state,
                            core_id, 
                            ratio_elapsed
                        )
                    }
                } else {
                    instance_builder.build().run(
                        tuple_list!(
                            AsanModule::default(asan.take().unwrap()),
                            injection_module
                        ),
                        state,
                        core_id, 
                        ratio_elapsed
                    )
                }
            } else {
                if self.options.dynamic_sanitizer {
                    if self.options.use_blocks {
                        let block_module = BlockCoverageModule::new(core_id.0, StdAddressFilter::default());
                        let asan_filter = self.get_dynamic_sanitization_filter(&block_module, self.options, ratio_elapsed)?;
                        let filter_string = asan_filter.convert_to_string();
                        let filter_file = format!("resulting_filter{}", core_id.0);
                        write_to_file("./tmp", &filter_file, &filter_string);
                        instance_builder.build().run(
                            tuple_list!(
                                AsanModule::new(asan.take().unwrap(), asan_filter, &QemuAsanOptions::Snapshot),
                                block_module
                            ),
                            state,
                            core_id, 
                            ratio_elapsed
                        )
                    } else {
                        instance_builder.build().run(
                            tuple_list!(
                                AsanModule::default(asan.take().unwrap()),
                            ),
                            state,
                            core_id, 
                            ratio_elapsed
                        )
                    }
                    
                } else {
                    instance_builder.build().run(
                        tuple_list!(AsanModule::default(asan.take().unwrap()),),
                        state,
                        core_id, 
                        ratio_elapsed
                    )
                }
            }
        } else if is_asan_guest {
            let modules = tuple_list!(AsanGuestModule::default(qemu, &asan_lib.take().unwrap()));
            instance_builder.build().run(modules, state, core_id, ratio_elapsed)
        } else if is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    tuple_list!(CmpLogModule::default(), injection_module),
                    state,
                    core_id, 
                    ratio_elapsed
                )
            } else {
                instance_builder
                    .build()
                    .run(tuple_list!(CmpLogModule::default()), state, core_id, ratio_elapsed)
            }
        } else if let Some(injection_module) = injection_module {
            instance_builder
                .build()
                .run(tuple_list!(injection_module), state, core_id, ratio_elapsed)
        } else {
            instance_builder.build().run(tuple_list!(), state, core_id, ratio_elapsed)
        }
    }
}
