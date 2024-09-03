use std::{env, io::BufRead, ops::Range};

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    inputs::BytesInput,
    monitors::Monitor,
    state::StdState,
    Error,
    executors::write_to_file
};
use libafl_bolts::{core_affinity::CoreId, rands::StdRand, tuples::tuple_list};
#[cfg(feature = "injections")]
use libafl_qemu::modules::injections::InjectionModule;
use libafl_qemu::{
    elf::EasyElf,
    modules::{
        asan::{init_qemu_with_asan, AsanModule, QemuAsanOptions}, asan_guest::{init_qemu_with_asan_guest, AsanGuestModule}, cmplog::CmpLogModule, drcov::DrCovModule, edges::EdgeCoverageModule, IsFilter, QemuInstrumentationAddressRangeFilter
    },
    ArchExtras, GuestAddr, Qemu,
};

use crate::{
    instance::{ClientMgr, Instance},
    options::FuzzerOptions,
};

#[allow(clippy::module_name_repetitions)]
pub type ClientState =
    StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl<'a> Client<'a> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    fn args(&self) -> Result<Vec<String>, Error> {
        let program = env::args()
            .next()
            .ok_or_else(|| Error::empty_optional("Failed to read program name"))?;

        let mut args = self.options.args.clone();
        args.insert(0, program);
        Ok(args)
    }

    #[allow(clippy::unused_self)] // Api should look the same as args above
    fn env(&self) -> Vec<(String, String)> {
        env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>()
    }

    fn start_pc(qemu: &Qemu) -> Result<GuestAddr, Error> {
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;

        let start_pc = elf
            .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
            .ok_or_else(|| Error::empty_optional("Symbol LLVMFuzzerTestOneInput not found"))?;
        Ok(start_pc)
    }

    #[allow(clippy::similar_names)] // elf != self
    fn coverage_filter(&self, qemu: &Qemu) -> Result<QemuInstrumentationAddressRangeFilter, Error> {
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
            Ok(QemuInstrumentationAddressRangeFilter::AllowList(rules))
        } else if let Some(excludes) = &self.options.exclude {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = excludes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(QemuInstrumentationAddressRangeFilter::DenyList(rules))
        } else {
            let mut elf_buffer = Vec::new();
            let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;
            let range = elf
                .get_section(".text", qemu.load_addr())
                .ok_or_else(|| Error::key_not_found("Failed to find .text section"))?;
            Ok(QemuInstrumentationAddressRangeFilter::AllowList(vec![
                range,
            ]))
        }
    }

    fn get_dynamic_sanitization_filter(&self) -> Result<QemuInstrumentationAddressRangeFilter, Error> {
        // In this variable we will store arbitrarily addresses from drcov-cleanup.txt
        let mut exclude_brutal = Some(vec![Range {
            start: GuestAddr::from_str_radix("7f0000000000", 16)?,
            end: GuestAddr::from_str_radix("7f0000001000", 16)?,
        }]);

        // Remove the hardcoded range
        exclude_brutal.as_mut().unwrap().clear();

        // Check if the file ./tmp/drcov-cleanup.txt exists first
        if std::path::Path::new("./tmp/drcov-cleanup.txt").exists() {
            let file = std::fs::File::open("./tmp/drcov-cleanup.txt");
            if !file.is_err() {
                // Start reading from file; the format is <address_start>-<address_end>: <hitcount>; one range per line; also the file ends with `END`
                // Example: 7f7d11609f56-7f7d11609f59: 664\n7f7cf3e4c18e-n7f7cf3e4c19e: 169\nEND\n
                // For each address range with hitcount > 50, add it to the exclude_brutal vector
                let reader = std::io::BufReader::new(file.unwrap());
                for line in reader.lines() {
                    let line = line.unwrap();
                    if line == "END" {
                        break;
                    }
                    let parts = line.split(": ").collect::<Vec<&str>>();
                    let hitcount = parts[1].parse::<u64>().unwrap();
                    let cutoff = self.options.dynamic_sanitizer_cutoff;
                    if hitcount > cutoff {
                        let parts = parts[0].split("-").collect::<Vec<&str>>();
                        let addr_start = GuestAddr::from_str_radix(parts[0], 16).unwrap();
                        let addr_end = GuestAddr::from_str_radix(parts[1], 16).unwrap();
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
            Ok(QemuInstrumentationAddressRangeFilter::DenyList(rules))
        } else {
            Err(Error::empty_optional("Failed to get dynamic sanitization filter"))
        }
    }

    pub fn run<M: Monitor>(
        &self,
        state: Option<ClientState>,
        mgr: ClientMgr<M>,
        core_id: CoreId,
    ) -> Result<(), Error> {
        let mut args = self.args()?;
        log::debug!("ARGS: {:#?}", args);

        let mut env = self.env();
        log::debug!("ENV: {:#?}", env);

        let is_asan = self.options.is_asan_core(core_id);
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

        let start_pc = Self::start_pc(&qemu)?;
        log::debug!("start_pc @ {start_pc:#x}");

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

        let extra_tokens = injection_module.as_ref().map(|h| h.tokens.clone());

        qemu.entry_break(start_pc);

        let ret_addr: GuestAddr = qemu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:?}")))?;
        log::debug!("ret_addr = {ret_addr:#x}");
        qemu.set_breakpoint(ret_addr);

        let is_cmplog = self.options.is_cmplog_core(core_id);

        let edge_coverage_module = EdgeCoverageModule::new(self.coverage_filter(&qemu)?);

        let instance = Instance::builder()
            .options(self.options)
            .qemu(&qemu)
            .mgr(mgr)
            .core_id(core_id)
            .extra_tokens(extra_tokens);

        let mut coverage_path = std::path::PathBuf::from("/home/cosmix/thesis/LibAFL/fuzzers/qemu/qemu_launcher/tmp/drcov.log");
        // Turn to PathBuf
        let coverage_name = coverage_path.file_stem().unwrap().to_str().unwrap();
        let coverage_extension = coverage_path.extension().unwrap_or_default().to_str().unwrap();
        let core = core_id.0;
        coverage_path.set_file_name(format!("{coverage_name}-{core:03}.{coverage_extension}"));

        if is_asan && is_cmplog {
            if let Some(injection_module) = injection_module {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_module,
                        CmpLogModule::default(),
                        AsanModule::default(asan.take().unwrap()),
                        injection_module,
                    ),
                    state,
                )
            } else {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_module,
                        CmpLogModule::default(),
                        AsanModule::default(asan.take().unwrap()),
                    ),
                    state,
                )
            }
        } else if is_asan_guest && is_cmplog {
            if let Some(injection_module) = injection_module {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_module,
                        CmpLogModule::default(),
                        AsanGuestModule::default(&qemu, asan_lib.take().unwrap()),
                        injection_module
                    ),
                    state,
                )
            } else {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_module,
                        CmpLogModule::default(),
                        AsanGuestModule::default(&qemu, asan_lib.take().unwrap()),
                    ),
                    state,
                )
            }
        } else if is_asan {
            if let Some(injection_module) = injection_module {
                if self.options.dynamic_sanitizer {
                    let asan_filter = self.get_dynamic_sanitization_filter()?;
                    instance.build().run(
                        tuple_list!(
                            edge_coverage_module,
                            AsanModule::new(asan.take().unwrap(), asan_filter, QemuAsanOptions::Snapshot),
                            injection_module,
                            DrCovModule::new(
                                QemuInstrumentationAddressRangeFilter::None,
                                coverage_path,
                                false,
                            ),
                        ),
                        state,
                    )
                } else {
                    instance.build().run(
                        tuple_list!(
                            edge_coverage_module,
                            AsanModule::default(asan.take().unwrap()),
                            injection_module
                        ),
                        state,
                    )
                }
            } else {
                if self.options.dynamic_sanitizer {
                    let asan_filter = self.get_dynamic_sanitization_filter()?;
                    instance.build().run(
                        tuple_list!(
                            edge_coverage_module,
                            AsanModule::new(asan.take().unwrap(), asan_filter, QemuAsanOptions::Snapshot),
                            DrCovModule::new(
                                QemuInstrumentationAddressRangeFilter::None,
                                coverage_path,
                                false,
                            ),
                        ),
                        state,
                    )
                } else {
                    instance.build().run(
                        tuple_list!(
                            edge_coverage_module,
                            AsanModule::default(asan.take().unwrap()),
                        ),
                        state,
                    )
                }
            }
        } else if is_asan_guest {
            let modules = tuple_list!(
                edge_coverage_module,
                AsanGuestModule::default(&qemu, asan_lib.take().unwrap())
            );
            instance.build().run(modules, state)
        } else if is_cmplog {
            if let Some(injection_module) = injection_module {
                instance.build().run(
                    tuple_list!(
                        edge_coverage_module,
                        CmpLogModule::default(),
                        injection_module
                    ),
                    state,
                )
            } else {
                instance.build().run(
                    tuple_list!(edge_coverage_module, CmpLogModule::default()),
                    state,
                )
            }
        } else if let Some(injection_module) = injection_module {
            instance
                .build()
                .run(tuple_list!(edge_coverage_module, injection_module), state)
        } else {
            instance
                .build()
                .run(tuple_list!(edge_coverage_module), state)
        }
    }
}
