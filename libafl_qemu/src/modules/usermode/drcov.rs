use std::{hash::Hash, path::PathBuf, sync::Mutex};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple, HasMetadata, executors::write_to_file, executors::write_to_file_truncate};
use libafl_qemu_sys::{GuestAddr, GuestUsize};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};

use crate::{
    emu::EmulatorModules,
    modules::{
        EmulatorModule, EmulatorModuleTuple, HasInstrumentationFilter, IsFilter,
        QemuInstrumentationAddressRangeFilter,
    },
    qemu::Hook,
};

static DRCOV_IDS: Mutex<Option<Vec<u64>>> = Mutex::new(None);
static DRCOV_MAP: Mutex<Option<HashMap<GuestAddr, u64>>> = Mutex::new(None);
static DRCOV_LENGTHS: Mutex<Option<HashMap<GuestAddr, GuestUsize>>> = Mutex::new(None);

// Hitcount map; key is the id, value is the number of times the block was hit
pub static HITCOUNTS: Mutex<Option<HashMap<u64, u64>>> = Mutex::new(None);

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DrCovMetadata {
    pub current_id: u64,
}

impl DrCovMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self { current_id: 0 }
    }
}

libafl_bolts::impl_serdeany!(DrCovMetadata);

#[derive(Debug)]
pub struct DrCovModule {
    filter: QemuInstrumentationAddressRangeFilter,
    module_mapping: RangeMap<usize, (u16, String)>,
    filename: PathBuf,
    full_trace: bool,
    drcov_len: usize,
    use_hitcounts: bool,
    core_id: usize,
    hitcounts: HashMap<(GuestAddr, GuestAddr), u64>,
}

impl DrCovModule {
    #[must_use]
    #[allow(clippy::let_underscore_untyped)]
    pub fn new(
        filter: QemuInstrumentationAddressRangeFilter,
        filename: PathBuf,
        full_trace: bool,
        use_hitcounts: bool,
        core_id: usize,
    ) -> Self {
        if full_trace {
            let _ = DRCOV_IDS.lock().unwrap().insert(vec![]);
        }
        
        write_to_file("./tmp", "debug", "Creating new HITCOUNTS map\n");
        let _ = HITCOUNTS.lock().unwrap().insert(HashMap::new());
        let hitcounts = HashMap::new();
        let _ = DRCOV_MAP.lock().unwrap().insert(HashMap::new());
        let _ = DRCOV_LENGTHS.lock().unwrap().insert(HashMap::new());
        Self {
            filter,
            module_mapping: RangeMap::new(),
            filename,
            full_trace,
            drcov_len: 0,
            use_hitcounts,
            core_id,
            hitcounts,
        }
    }

    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.filter.allowed(addr)
    }

    pub fn get_hitcounts(&self) -> Option<HashMap<(GuestAddr, GuestAddr), u64>> {
        Some(self.hitcounts.clone())
    }

    // Read the previous hitcounts from a file, and add them to the current rolling hitcounts in the rolling file
    pub fn save_previous_hitcounts(&mut self) {
        let file_name = format!("drcov-cleanup-{}.txt", self.core_id);
        let file_path = format!("./tmp/{}", file_name);
        // Check if the previous HITCOUNTS file exists
        if !std::path::Path::new(&file_path).exists() {
            write_to_file("./tmp", "debug", "No previous HITCOUNTS to save\n");
            return;
        }
        let file_contents = std::fs::read_to_string(file_path).unwrap();
        let lines = file_contents.lines();
        for line in lines {
            if line == "END" {
                break;
            }
            let parts: Vec<&str> = line.split(": ").collect();
            let pc_range: Vec<&str> = parts[0].split("-").collect();
            let pc_start = u64::from_str_radix(pc_range[0], 16).unwrap();
            let pc_end = u64::from_str_radix(pc_range[1], 16).unwrap();
            let count = parts[1].parse::<u64>().unwrap();
            self.hitcounts.insert((pc_start, pc_end), count);
        }

        let file_name = format!("drcov-rolling-{}.txt", self.core_id);
        let file_path = format!("./tmp/{}", file_name);
        // Check if the rolling HITCOUNTS file exists
        if std::path::Path::new(&file_path).exists() {
            let file_contents = std::fs::read_to_string(file_path).unwrap();
            let lines = file_contents.lines();
            for line in lines {
                if line == "END" {
                    break;
                }
                let parts: Vec<&str> = line.split(": ").collect();
                let pc_range: Vec<&str> = parts[0].split("-").collect();
                let pc_start = u64::from_str_radix(pc_range[0], 16).unwrap();
                let pc_end = u64::from_str_radix(pc_range[1], 16).unwrap();
                let count = parts[1].parse::<u64>().unwrap();
                match self.hitcounts.get_mut(&(pc_start, pc_end)) {
                    Some(c) => {
                        let str_to_write = format!("found rolling: {:x}-{:x}: {}\n", pc_start, pc_end, *c);
                        write_to_file("./tmp", "debug", &str_to_write);
                        *c += count;
                    }
                    None => {
                        self.hitcounts.insert((pc_start, pc_end), count);
                    }
                }
            }
        }
        self.write_hitcounts_rolling();
    }

    fn write_hitcounts_rolling(&self) {
        let mut hitcounts = String::new();
        for (pc, count) in self.hitcounts.iter() {
            hitcounts.push_str(&format!("{:x}-{:x}: {}\n", pc.0, pc.1, count));
        }
        hitcounts.push_str("END\n");
        let file_name = format!("drcov-rolling-{}.txt", self.core_id);
        write_to_file_truncate("./tmp", &file_name, &hitcounts);
        write_to_file("./tmp", "debug", "Written rolling HITCOUNTS\n");
    }

    // Write the global HITCOUNTS to a file
    pub fn write_hitcounts(&mut self) {
        let str_hitcounts = hitcounts_as_map_string();
        let file_name = format!("drcov-cleanup-{}.txt", self.core_id);
        write_to_file_truncate("./tmp", &file_name, &str_hitcounts);
        write_to_file("./tmp", "debug", "Written GLOBAL HITCOUNTS\n");
    }
}

impl Drop for DrCovModule {
    fn drop(&mut self) {
        if self.use_hitcounts {
            self.write_hitcounts();
        }
    }
}

impl HasInstrumentationFilter<QemuInstrumentationAddressRangeFilter> for DrCovModule {
    fn filter(&self) -> &QemuInstrumentationAddressRangeFilter {
        &self.filter
    }

    fn filter_mut(&mut self) -> &mut QemuInstrumentationAddressRangeFilter {
        &mut self.filter
    }
}

impl<S> EmulatorModule<S> for DrCovModule
where
    S: Unpin + UsesInput + HasMetadata,
{
    fn init_module<ET>(&self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        emulator_modules.blocks(
            Hook::Function(gen_unique_block_ids::<ET, S>),
            Hook::Function(gen_block_lengths::<ET, S>),
            Hook::Function(exec_trace_block::<ET, S>),
        );
    }

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        let qemu = emulator_modules.qemu();

        // write_to_file("./tmp", "drcov-first-exec", "First exec\n");

        for (i, (r, p)) in qemu
            .mappings()
            .filter_map(|m| {
                m.path()
                    .map(|p| ((m.start() as usize)..(m.end() as usize), p.to_string()))
                    .filter(|(_, p)| !p.is_empty())
            })
            .enumerate()
        {
            self.module_mapping.insert(r, (i as u16, p));
        }
    }

    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
        let lengths_opt = DRCOV_LENGTHS.lock().unwrap();
        let lengths = lengths_opt.as_ref().unwrap();

        if self.full_trace {
            if DRCOV_IDS.lock().unwrap().as_ref().unwrap().len() > self.drcov_len {
                let mut drcov_vec = Vec::<DrCovBasicBlock>::new();
                for id in DRCOV_IDS.lock().unwrap().as_ref().unwrap() {
                    'pcs_full: for (pc, idm) in DRCOV_MAP.lock().unwrap().as_ref().unwrap() {
                        let mut module_found = false;
                        for module in self.module_mapping.iter() {
                            let (range, (_, _)) = module;
                            if *pc >= range.start.try_into().unwrap()
                                && *pc <= range.end.try_into().unwrap()
                            {
                                module_found = true;
                                break;
                            }
                        }
                        if !module_found {
                            continue 'pcs_full;
                        }
                        if *idm == *id {
                            match lengths.get(pc) {
                                Some(block_length) => {
                                    drcov_vec.push(DrCovBasicBlock::new(
                                        *pc as usize,
                                        *pc as usize + *block_length as usize,
                                    ));
                                }
                                None => {
                                    log::info!("Failed to find block length for: {pc:}");
                                }
                            }
                        }
                    }
                }

                DrCovWriter::new(&self.module_mapping)
                    .write(&self.filename, &drcov_vec)
                    .expect("Failed to write coverage file");
            }
            self.drcov_len = DRCOV_IDS.lock().unwrap().as_ref().unwrap().len();
        } else {
            if DRCOV_MAP.lock().unwrap().as_ref().unwrap().len() > self.drcov_len {
                let mut drcov_vec = Vec::<DrCovBasicBlock>::new();
                'pcs: for (pc, _) in DRCOV_MAP.lock().unwrap().as_ref().unwrap() {
                    let mut module_found = false;
                    for module in self.module_mapping.iter() {
                        let (range, (_, _)) = module;
                        if *pc >= range.start.try_into().unwrap()
                            && *pc <= range.end.try_into().unwrap()
                        {
                            module_found = true;
                            break;
                        }
                    }
                    if !module_found {
                        continue 'pcs;
                    }
                    match lengths.get(pc) {
                        Some(block_length) => {
                            drcov_vec.push(DrCovBasicBlock::new(
                                *pc as usize,
                                *pc as usize + *block_length as usize,
                            ));
                        }
                        None => {
                            log::info!("Failed to find block length for: {pc:}");
                        }
                    }
                }

                DrCovWriter::new(&self.module_mapping)
                    .write(&self.filename, &drcov_vec)
                    .expect("Failed to write coverage file");
            }
            self.drcov_len = DRCOV_MAP.lock().unwrap().as_ref().unwrap().len();
        }
    }
}

pub fn gen_unique_block_ids<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    S: Unpin + UsesInput + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let drcov_module = emulator_modules.get::<DrCovModule>().unwrap();

    if !drcov_module.must_instrument(pc) {
        return None;
    }

    let state = state.expect("The gen_unique_block_ids hook works only for in-process fuzzing");
    if state
        .metadata_map_mut()
        .get_mut::<DrCovMetadata>()
        .is_none()
    {
        state.add_metadata(DrCovMetadata::new());
    }
    let meta = state.metadata_map_mut().get_mut::<DrCovMetadata>().unwrap();

    match DRCOV_MAP.lock().unwrap().as_mut().unwrap().entry(pc) {
        Entry::Occupied(e) => {
            let id = *e.get();
            // if drcov_module.full_trace {
            //     Some(id)
            // } else {
            //     None
            // }
            Some(id)
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = id + 1;
            // if drcov_module.full_trace {
            //     // GuestAddress is u32 for 32 bit guests
            //     #[allow(clippy::unnecessary_cast)]
            //     Some(id as u64)
            // } else {
            //     None
            // }
            #[allow(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

pub fn gen_block_lengths<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    block_length: GuestUsize,
) where
    S: Unpin + UsesInput + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let drcov_module = emulator_modules.get::<DrCovModule>().unwrap();

    if !drcov_module.must_instrument(pc) {
        return;
    }
    DRCOV_LENGTHS
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .insert(pc, block_length);
}

pub fn exec_trace_block<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    id: u64,
) where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput + HasMetadata,
{

    if emulator_modules.get::<DrCovModule>().unwrap().full_trace {
        DRCOV_IDS.lock().unwrap().as_mut().unwrap().push(id);
    }

    if emulator_modules.get::<DrCovModule>().unwrap().use_hitcounts {
        match HITCOUNTS.lock().unwrap().as_mut().unwrap().entry(id) {
            Entry::Occupied(mut e) => {
                *e.get_mut() += 1;
            }
            Entry::Vacant(e) => {
                e.insert(1);
            }
        }
    }
}

pub fn get_hitcount_for_id(id: u64) -> Option<u64> {
    // Get the number of times the id appears in HITCOUNTS
    let binding = HITCOUNTS.lock().unwrap();
    let count = binding.as_ref().unwrap().get(&id)?;

    Some(*count)
}

pub fn hitcounts_as_map_string() -> String {
    let mut hitcounts = String::new();

    for (pc, id) in DRCOV_MAP.lock().unwrap().as_ref().unwrap() {
        let count = match get_hitcount_for_id(id.clone()) {
            Some(c) => c,
            None => 0,
        };

        let pc_start = pc;
        let binding = DRCOV_LENGTHS.lock().unwrap();
        let block_length = binding
        .as_ref()
        .unwrap()
        .get(pc);
        let pc_end = pc_start + block_length.unwrap();
        hitcounts.push_str(&format!("{:x}-{:x}: {}\n", pc_start, pc_end, count));
    }
    hitcounts.push_str("END\n");
    hitcounts
}
