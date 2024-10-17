use std::{fs::read_to_string, path::Path, sync::Mutex};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{inputs::UsesInput, HasMetadata, executors::write_to_file_truncate};
use libafl_qemu_sys::{GuestAddr, GuestUsize};
use serde::{Deserialize, Serialize};

use crate::{
    emu::EmulatorModules,
    modules::{EmulatorModule, EmulatorModuleTuple, AddressFilter},
    qemu::Hook,
};

// Block map; key is the address, value is the id
static ADDR_MAP: Mutex<Option<HashMap<GuestAddr, u64>>> = Mutex::new(None);

// Block lengths; key is the address, value is the length
static BLOCK_LENGTHS: Mutex<Option<HashMap<GuestAddr, GuestUsize>>> = Mutex::new(None);

// Hitcount map; key is the id, value is the number of times the block was hit
pub static HITCOUNTS: Mutex<Option<HashMap<u64, u64>>> = Mutex::new(None);

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BlockMapMetadata {
    current_id: u64,
}

impl BlockMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self { current_id: 0 }
    }
}

libafl_bolts::impl_serdeany!(BlockMapMetadata);

#[derive(Debug)]
pub struct BlockCoverageModule<AF: AddressFilter> {
    core_id: usize,
    address_filter: AF,
}

impl<AF> BlockCoverageModule<AF> 
where 
    AF: AddressFilter
{
    pub fn new(core_id: usize, address_filter: AF) -> Self {
        // Initialize the maps
        let _ = HITCOUNTS.lock().unwrap().insert(HashMap::new());
        let _ = ADDR_MAP.lock().unwrap().insert(HashMap::new());
        let _ = BLOCK_LENGTHS.lock().unwrap().insert(HashMap::new());

        // Return the module
        Self { core_id, address_filter }
    }

    pub fn get_rolling_hitcounts(&self) -> HashMap<(GuestAddr, GuestAddr), u64> {
        let mut hitcounts_map = get_hitcounts_with_address_key();
        hitcounts_map = self.read_rolling_hitcounts(hitcounts_map);

        hitcounts_map
    }

    pub fn update_rolling_hitcounts(&self) {
        let mut hitcounts_map = get_hitcounts_with_address_key();
        hitcounts_map = self.read_rolling_hitcounts(hitcounts_map);
        self.write_rolling_hitcounts(hitcounts_map);
    }

    fn read_rolling_hitcounts(
        &self,
        mut hitcounts_map: HashMap<(GuestAddr, GuestAddr), u64>
    ) -> HashMap<(GuestAddr, GuestAddr), u64> {
        let file_name = format!("drcov-rolling-{}.txt", self.core_id);
        let file_path = format!("./tmp/{}", file_name);

        if Path::new(&file_path).exists() {
            let file_contents = read_to_string(file_path).unwrap();
            let lines = file_contents.lines();
            for line in lines {
                let parts: Vec<&str> = line.split(": ").collect();
                let pc_range: Vec<&str> = parts[0].split("-").collect();
                let pc_start = u64::from_str_radix(pc_range[0], 16).unwrap();
                let pc_end = u64::from_str_radix(pc_range[1], 16).unwrap();
                let hitcount = parts[1].parse::<u64>().unwrap();
                match hitcounts_map.get_mut(&(pc_start, pc_end)) {
                    Some(c) => {
                        *c += hitcount;
                    }
                    None => {
                        hitcounts_map.insert((pc_start, pc_end), hitcount);
                    }
                }
            }
        }

        hitcounts_map
    }

    fn write_rolling_hitcounts(&self, hitcounts_map: HashMap<(GuestAddr, GuestAddr), u64>) {
        let file_name = format!("drcov-rolling-{}.txt", self.core_id);

        let mut file_contents = String::new();
        for ((pc_start, pc_end), hitcount) in hitcounts_map.iter() {
            file_contents.push_str(&format!("{:x}-{:x}: {}\n", pc_start, pc_end, hitcount));
        }

        write_to_file_truncate("./tmp", &file_name, &file_contents);
    }
}

impl<AF> Drop for BlockCoverageModule<AF>
where
    AF: AddressFilter,
{
    fn drop(&mut self) {
        self.update_rolling_hitcounts();
    }
}

impl<S, AF> EmulatorModule<S> for BlockCoverageModule<AF>
where 
    S: Unpin + UsesInput + HasMetadata,
    AF: AddressFilter + 'static,
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
    
    type ModuleAddressFilter = AF;
    
    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        &mut self.address_filter
    }
}

pub fn gen_unique_block_ids<ET, S>(
    _emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    pc: GuestAddr
) -> Option<u64> 
where 
    S: Unpin + UsesInput + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    let state = state.expect("The gen_unique_block_ids hook works only for in-process fuzzing");
    if state
        .metadata_map_mut()
        .get_mut::<BlockMapMetadata>()
        .is_none()
    {
        state.add_metadata(BlockMapMetadata::new());
    }
    let meta = state.metadata_map_mut().get_mut::<BlockMapMetadata>().unwrap();

    match ADDR_MAP.lock().unwrap().as_mut().unwrap().entry(pc) {
        Entry::Occupied(e) => {
            Some(*e.get())
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id += 1;

            #[allow(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

pub fn gen_block_lengths<ET, S>(
    _emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    block_length: GuestUsize
) where 
    S: Unpin + UsesInput + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    BLOCK_LENGTHS
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .insert(pc, block_length);
}

pub fn exec_trace_block<ET, S>(
    _emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    id: u64
) where 
    S: Unpin + UsesInput + HasMetadata,
    ET: EmulatorModuleTuple<S>,
{
    match HITCOUNTS.lock().unwrap().as_mut().unwrap().entry(id) {
        Entry::Occupied(mut e) => {
            *e.get_mut() += 1;
        }
        Entry::Vacant(e) => {
            e.insert(1);
        }
    }
}

pub fn get_hitcounts_with_address_key() -> HashMap<(GuestAddr, GuestAddr), u64> {
    let hitcounts = HITCOUNTS.lock().unwrap();
    let mut hitcounts_ret = HashMap::new();
    for (pc, idm) in ADDR_MAP.lock().unwrap().as_ref().unwrap() {
        match hitcounts.as_ref().unwrap().get(idm) {
            Some(c) => {
                let pc_end = pc + BLOCK_LENGTHS.lock().unwrap().as_ref().unwrap().get(pc).unwrap();
                hitcounts_ret.insert((*pc, pc_end), *c);
            }
            None => {
                log::info!("Failed to find hitcount for: {pc:}");
            }
        }
    }
    hitcounts_ret
}
