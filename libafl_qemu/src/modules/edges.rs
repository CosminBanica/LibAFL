use std::{cell::UnsafeCell, cmp::max, fmt::Debug, ptr, ptr::addr_of, sync::Mutex, path::Path, fs::read_to_string};

use hashbrown::{hash_map::Entry, HashMap, HashSet};
use libafl::{inputs::UsesInput, observers::VariableLengthMapObserver, HasMetadata, executors::write_to_file_truncate};
use libafl_bolts::Error;
use libafl_qemu_sys::GuestAddr;
#[cfg(emulation_mode = "systemmode")]
use libafl_qemu_sys::GuestPhysAddr;
use libafl_targets::EDGES_MAP;
use serde::{Deserialize, Serialize};

use crate::{
    emu::EmulatorModules,
    modules::{
        hash_me, AddressFilter, EmulatorModule, EmulatorModuleTuple, PageFilter, StdAddressFilter,
        StdPageFilter,
    },
    qemu::Hook,
};

#[no_mangle]
static mut LIBAFL_QEMU_EDGES_MAP_PTR: *mut u8 = ptr::null_mut();

#[no_mangle]
static mut LIBAFL_QEMU_EDGES_MAP_SIZE_PTR: *mut usize = ptr::null_mut();

#[no_mangle]
static mut LIBAFL_QEMU_EDGES_MAP_ALLOCATED_SIZE: usize = 0;

#[no_mangle]
static mut LIBAFL_QEMU_EDGES_MAP_MASK_MAX: usize = 0;

// key is the id, value is the block ending address
static ID_TO_BLOCK: Mutex<Option<HashMap<u64, GuestAddr>>> = Mutex::new(None);

// key is the block ending address, value is list of ids of edges that start at this block, stored as a HashSet to avoid duplicates
// static BLOCK_EDGES: Mutex<Option<HashMap<GuestAddr, HashSet<u64>>>> = Mutex::new(None);

// key is block ending address, value is start address of the block
static BLOCK_START: Mutex<Option<HashMap<GuestAddr, GuestAddr>>> = Mutex::new(None);

// key is the block ending address, value is the hitcount
static HITCOUNTS: Mutex<Option<HashMap<GuestAddr, u64>>> = Mutex::new(None);

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QemuEdgesMapMetadata {
    pub map: HashMap<(GuestAddr, GuestAddr), u64>,
    pub current_id: u64,
}

libafl_bolts::impl_serdeany!(QemuEdgesMapMetadata);

impl QemuEdgesMapMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            current_id: 0,
        }
    }
}

/// Standard edge coverage module, adapted to most use cases
pub type StdEdgeCoverageModule = StdEdgeCoverageFullModule;

/// Standard edge coverage module builder, adapted to most use cases
pub type StdEdgeCoverageModuleBuilder = StdEdgeCoverageFullModuleBuilder;

pub type CollidingEdgeCoverageModule<AF, PF> = EdgeCoverageModule<AF, PF, EdgeCoverageChildVariant>;

pub trait EdgeCoverageVariant<AF, PF>: 'static + Debug {
    const DO_SIDE_EFFECTS: bool = true;

    fn jit_hitcount<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("JIT hitcount is not supported.")
    }

    fn jit_hitcount_dyn<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("JIT hitcount dynamic is not supported.")
    }

    fn jit_no_hitcount<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("JIT no hitcount is not supported.")
    }

    fn fn_hitcount<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("Func hitcount is not supported.")
    }

    fn fn_no_hitcount<ET, S>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        panic!("Func no hitcount is not supported.")
    }
}

#[derive(Debug)]
pub struct EdgeCoverageFullVariant;

pub type StdEdgeCoverageFullModule =
    EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageFullVariant>;
pub type StdEdgeCoverageFullModuleBuilder =
    EdgeCoverageModuleBuilder<StdAddressFilter, StdPageFilter, EdgeCoverageFullVariant, false>;

impl<AF, PF> EdgeCoverageVariant<AF, PF> for EdgeCoverageFullVariant {
    fn jit_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Empty,
        );
        unsafe {
            libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_edge_hitcount),
            );
        }
    }

    fn jit_hitcount_dyn<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Raw(trace_block_hitcount),
        );
        unsafe {
            libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_edge_hitcount),
            );
        }
    }

    fn jit_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Empty,
        );
        unsafe {
            libafl_qemu_sys::libafl_qemu_edge_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_edge_single),
            );
        }
    }

    fn fn_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Raw(trace_edge_hitcount),
        );
    }

    fn fn_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.edges(
            Hook::Function(gen_unique_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Raw(trace_edge_single),
        );
    }
}

impl Default for StdEdgeCoverageFullModuleBuilder {
    fn default() -> Self {
        Self {
            variant: EdgeCoverageFullVariant,
            address_filter: StdAddressFilter::default(),
            page_filter: StdPageFilter::default(),
            use_hitcounts: true,
            use_jit: true,
            use_dynamic_sanitization: false,
            core_id: 0,
        }
    }
}

impl StdEdgeCoverageFullModule {
    #[must_use]
    pub fn builder() -> StdEdgeCoverageFullModuleBuilder {
        EdgeCoverageModuleBuilder::default()
    }
}

#[derive(Debug)]
pub struct EdgeCoverageClassicVariant;

pub type StdEdgeCoverageClassicModule =
    EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageClassicVariant>;
pub type StdEdgeCoverageClassicModuleBuilder =
    EdgeCoverageModuleBuilder<StdAddressFilter, StdPageFilter, EdgeCoverageClassicVariant, false>;

impl<AF, PF> EdgeCoverageVariant<AF, PF> for EdgeCoverageClassicVariant {
    const DO_SIDE_EFFECTS: bool = false;

    fn jit_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, S, Self>),
            Hook::Empty,
            Hook::Empty,
        );

        unsafe {
            libafl_qemu_sys::libafl_qemu_block_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_block_hitcount),
            );
        }
    }

    fn jit_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        let hook_id = emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, S, Self>),
            Hook::Empty,
            Hook::Empty,
        );

        unsafe {
            libafl_qemu_sys::libafl_qemu_block_hook_set_jit(
                hook_id.0,
                Some(libafl_qemu_sys::libafl_jit_trace_block_single),
            );
        }
    }

    fn fn_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, S, Self>),
            Hook::Empty,
            Hook::Raw(trace_block_transition_hitcount),
        );
    }

    fn fn_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.blocks(
            Hook::Function(gen_hashed_block_ids::<AF, ET, PF, S, Self>),
            Hook::Empty,
            Hook::Raw(trace_block_transition_single),
        );
    }
}

impl Default for StdEdgeCoverageClassicModuleBuilder {
    fn default() -> Self {
        Self {
            variant: EdgeCoverageClassicVariant,
            address_filter: StdAddressFilter::default(),
            page_filter: StdPageFilter::default(),
            use_hitcounts: true,
            use_jit: true,
            use_dynamic_sanitization: false,
            core_id: 0,
        }
    }
}

impl StdEdgeCoverageClassicModule {
    #[must_use]
    pub fn builder() -> StdEdgeCoverageClassicModuleBuilder {
        EdgeCoverageModuleBuilder::default()
    }
}

#[derive(Debug)]
pub struct EdgeCoverageChildVariant;
pub type StdEdgeCoverageChildModule =
    EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageChildVariant>;
pub type StdEdgeCoverageChildModuleBuilder =
    EdgeCoverageModuleBuilder<StdAddressFilter, StdPageFilter, EdgeCoverageChildVariant, false>;

impl<AF, PF> EdgeCoverageVariant<AF, PF> for EdgeCoverageChildVariant {
    const DO_SIDE_EFFECTS: bool = false;

    fn fn_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.edges(
            Hook::Function(gen_hashed_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Raw(trace_edge_hitcount_ptr),
        );
    }

    fn fn_no_hitcount<ET, S>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        AF: AddressFilter,
        ET: EmulatorModuleTuple<S>,
        PF: PageFilter,
        S: Unpin + UsesInput + HasMetadata,
    {
        emulator_modules.edges(
            Hook::Function(gen_hashed_edge_ids::<AF, ET, PF, S, Self>),
            Hook::Raw(trace_edge_single_ptr),
        );
    }
}

impl Default for StdEdgeCoverageChildModuleBuilder {
    fn default() -> Self {
        Self {
            variant: EdgeCoverageChildVariant,
            address_filter: StdAddressFilter::default(),
            page_filter: StdPageFilter::default(),
            use_hitcounts: true,
            use_jit: true,
            use_dynamic_sanitization: false,
            core_id: 0,
        }
    }
}

impl StdEdgeCoverageChildModule {
    #[must_use]
    pub fn builder() -> StdEdgeCoverageChildModuleBuilder {
        EdgeCoverageModuleBuilder::default().jit(false)
    }
}

#[derive(Debug)]
pub struct EdgeCoverageModuleBuilder<AF, PF, V, const IS_INITIALIZED: bool> {
    variant: V,
    address_filter: AF,
    page_filter: PF,
    use_hitcounts: bool,
    use_jit: bool,
    use_dynamic_sanitization: bool,
    core_id: usize,
}

#[derive(Debug)]
pub struct EdgeCoverageModule<AF, PF, V> {
    variant: V,
    address_filter: AF,
    // we only use it in system mode at the moment.
    #[cfg_attr(not(emulation_mode = "systemmode"), allow(dead_code))]
    page_filter: PF,
    use_hitcounts: bool,
    use_jit: bool,
    use_dynamic_sanitization: bool,
    core_id: usize,
}

impl<AF, PF, V> EdgeCoverageModuleBuilder<AF, PF, V, true> {
    pub fn build(self) -> Result<EdgeCoverageModule<AF, PF, V>, Error> {
        Ok(EdgeCoverageModule::new(
            self.address_filter,
            self.page_filter,
            self.variant,
            self.use_hitcounts,
            self.use_jit,
            self.use_dynamic_sanitization,
            self.core_id,
        ))
    }
}

impl<AF, PF, V, const IS_INITIALIZED: bool> EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED> {
    fn new(
        variant: V,
        address_filter: AF,
        page_filter: PF,
        use_hitcounts: bool,
        use_jit: bool,
        use_dynamic_sanitization: bool,
        core_id: usize,
    ) -> Self {
        Self {
            variant,
            address_filter,
            page_filter,
            use_hitcounts,
            use_jit,
            use_dynamic_sanitization,
            core_id,   
        }
    }

    #[must_use]
    pub fn map_observer<O>(self, map_observer: &mut O) -> EdgeCoverageModuleBuilder<AF, PF, V, true>
    where
        O: VariableLengthMapObserver,
    {
        let map_ptr = map_observer.map_slice_mut().as_mut_ptr() as *mut u8;
        let map_max_size = map_observer.map_slice_mut().len();
        let size_ptr = map_observer.as_mut().size_mut() as *mut usize;

        unsafe {
            LIBAFL_QEMU_EDGES_MAP_PTR = map_ptr;
            LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = size_ptr;
            LIBAFL_QEMU_EDGES_MAP_ALLOCATED_SIZE = map_max_size;
            LIBAFL_QEMU_EDGES_MAP_MASK_MAX = map_max_size - 1;
        }

        EdgeCoverageModuleBuilder::<AF, PF, V, true>::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
            self.use_dynamic_sanitization,
            self.core_id,
        )
    }

    pub fn variant<V2>(self, variant: V2) -> EdgeCoverageModuleBuilder<AF, PF, V2, IS_INITIALIZED> {
        EdgeCoverageModuleBuilder::new(
            variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
            self.use_dynamic_sanitization,
            self.core_id,
        )
    }

    pub fn address_filter<AF2>(
        self,
        address_filter: AF2,
    ) -> EdgeCoverageModuleBuilder<AF2, PF, V, IS_INITIALIZED> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
            self.use_dynamic_sanitization,
            self.core_id,
        )
    }

    pub fn page_filter<PF2>(
        self,
        page_filter: PF2,
    ) -> EdgeCoverageModuleBuilder<AF, PF2, V, IS_INITIALIZED> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            page_filter,
            self.use_hitcounts,
            self.use_jit,
            self.use_dynamic_sanitization,
            self.core_id,
        )
    }

    #[must_use]
    pub fn hitcounts(
        self,
        use_hitcounts: bool,
    ) -> EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            use_hitcounts,
            self.use_jit,
            self.use_dynamic_sanitization,
            self.core_id,
        )
    }

    #[must_use]
    pub fn jit(self, use_jit: bool) -> EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            use_jit,
            self.use_dynamic_sanitization,
            self.core_id,
        )
    }

    #[must_use]
    pub fn dynamic_sanitization(
        self,
        use_dynamic_sanitization: bool,
    ) -> EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED> {
        if use_dynamic_sanitization == true {
            let _ = ID_TO_BLOCK.lock().unwrap().insert(HashMap::new());
            let _ = HITCOUNTS.lock().unwrap().insert(HashMap::new());
            // let _ = BLOCK_EDGES.lock().unwrap().insert(HashMap::new());
            let _ = BLOCK_START.lock().unwrap().insert(HashMap::new());
        }

        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
            use_dynamic_sanitization,
            self.core_id,
        )
    }

    #[must_use]
    pub fn core_id(self, core_id: usize) -> EdgeCoverageModuleBuilder<AF, PF, V, IS_INITIALIZED> {
        EdgeCoverageModuleBuilder::new(
            self.variant,
            self.address_filter,
            self.page_filter,
            self.use_hitcounts,
            self.use_jit,
            self.use_dynamic_sanitization,
            core_id,
        )
    }
}

impl<AF, PF, V> EdgeCoverageModule<AF, PF, V> {
    #[must_use]
    pub fn new(
        address_filter: AF,
        page_filter: PF,
        variant: V,
        use_hitcounts: bool,
        use_jit: bool,
        use_dynamic_sanitization: bool,
        core_id: usize,
    ) -> Self {
        Self {
            variant,
            address_filter,
            page_filter,
            use_hitcounts,
            use_jit,
            use_dynamic_sanitization,
            core_id,
        }
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

    fn write_rolling_hitcounts(
        &self,
        hitcounts_map: HashMap<(GuestAddr, GuestAddr), u64>
    ) {
        let file_name = format!("drcov-rolling-{}.txt", self.core_id);

        let mut file_contents = String::new();
        for ((pc_start, pc_end), hitcount) in hitcounts_map.iter() {
            file_contents.push_str(&format!("{:x}-{:x}: {}\n", pc_start, pc_end, hitcount));
        }

        write_to_file_truncate("./tmp", &file_name, &file_contents);
    }
}

impl<AF, PF, V> EdgeCoverageModule<AF, PF, V>
where
    AF: AddressFilter,
    PF: PageFilter,
{
    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr) -> bool {
        self.address_filter.allowed(&addr)
    }

    #[cfg(emulation_mode = "systemmode")]
    #[must_use]
    pub fn must_instrument(&self, addr: GuestAddr, page_id: Option<GuestPhysAddr>) -> bool {
        if let Some(page_id) = page_id {
            self.address_filter.allowed(&addr) && self.page_filter.allowed(&page_id)
        } else {
            self.address_filter.allowed(&addr)
        }
    }
}

impl<AF, PF, V> Drop for EdgeCoverageModule<AF, PF, V> {
    fn drop(&mut self) {
        if self.use_dynamic_sanitization {
            self.update_rolling_hitcounts();
        }
    }
}

impl<S, AF, PF, V> EmulatorModule<S> for EdgeCoverageModule<AF, PF, V>
where
    AF: AddressFilter + 'static,
    PF: PageFilter + 'static,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF> + 'static,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = V::DO_SIDE_EFFECTS;

    type ModuleAddressFilter = AF;
    #[cfg(emulation_mode = "systemmode")]
    type ModulePageFilter = PF;

    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
    {
        if self.use_hitcounts {
            if self.use_jit {
                if self.use_dynamic_sanitization {
                    self.variant.jit_hitcount_dyn(emulator_modules);
                } else {
                    self.variant.jit_hitcount(emulator_modules);
                }
            } else {
                self.variant.fn_hitcount(emulator_modules);
            }
        } else if self.use_jit {
            self.variant.jit_no_hitcount(emulator_modules);
        } else {
            self.variant.fn_no_hitcount(emulator_modules);
        }
    }

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &self.address_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        &mut self.address_filter
    }

    #[cfg(emulation_mode = "systemmode")]
    fn page_filter(&self) -> &Self::ModulePageFilter {
        &self.page_filter
    }

    #[cfg(emulation_mode = "systemmode")]
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter {
        &mut self.page_filter
    }
}

thread_local!(static PREV_LOC : UnsafeCell<u64> = const { UnsafeCell::new(0) });
pub fn gen_unique_edge_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    let mut use_dynamic_sanitization = false;
    if let Some(module) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
        unsafe {
            assert!(LIBAFL_QEMU_EDGES_MAP_MASK_MAX > 0);
            assert_ne!(*addr_of!(LIBAFL_QEMU_EDGES_MAP_SIZE_PTR), ptr::null_mut());
        }
        use_dynamic_sanitization = module.use_dynamic_sanitization;

        #[cfg(emulation_mode = "usermode")]
        {
            if !module.must_instrument(src) && !module.must_instrument(dest) {
                return None;
            }
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !module.must_instrument(src, paging_id) && !module.must_instrument(dest, paging_id) {
                return None;
            }
        }
    }

    let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing");
    let meta = state.metadata_or_insert_with(QemuEdgesMapMetadata::new);

    match meta.map.entry((src, dest)) {
        Entry::Occupied(e) => {
            let id = *e.get();
            unsafe {
                let nxt = (id as usize + 1) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
                *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = max(*LIBAFL_QEMU_EDGES_MAP_SIZE_PTR, nxt);

                if use_dynamic_sanitization {
                    // Update PREV_LOC
                    PREV_LOC.with(|prev_loc| {
                        *prev_loc.get() = dest;
                    });
                }
            }
            
            Some(id)
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            unsafe {
                meta.current_id = (id + 1) & (LIBAFL_QEMU_EDGES_MAP_MASK_MAX as u64);
                *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = meta.current_id as usize;

                if use_dynamic_sanitization {
                    // Update ID_TO_BLOCK
                    let mut id_to_block = ID_TO_BLOCK.lock().unwrap();
                    id_to_block.as_mut().unwrap().insert(id, src);

                    // // Update BLOCK_EDGES
                    // let mut block_edges = BLOCK_EDGES.lock().unwrap();
                    // match block_edges.as_mut().unwrap().entry(src) {
                    //     Entry::Occupied(mut e) => {
                    //         e.get_mut().insert(id);
                    //     }
                    //     Entry::Vacant(e) => {
                    //         e.insert(HashSet::new()).insert(id);
                    //     }
                    // }

                    // Update BLOCK_START
                    PREV_LOC.with(|prev_loc| {
                        let prev_loc = prev_loc.get();
                        let mut block_start = BLOCK_START.lock().unwrap();
                        block_start.as_mut().unwrap().insert(src, *prev_loc);

                        // Update PREV_LOC
                        *prev_loc = dest;
                    });
                }
            }
            // GuestAddress is u32 for 32 bit guests
            #[allow(clippy::unnecessary_cast)]
            Some(id as u64)
        }
    }
}

/// # Safety
///
/// Calling this concurrently for the same id is racey and may lose updates.
pub unsafe extern "C" fn trace_edge_hitcount(_: *const (), id: u64) {
    unsafe {
        EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
    }
}

pub extern "C" fn trace_edge_single(_: *const (), id: u64) {
    // # Safety
    // Worst case we set the byte to 1 multiple times..
    unsafe {
        EDGES_MAP[id as usize] = 1;
    }
}

pub unsafe extern "C" fn trace_block_hitcount(_: *const (), id: u64) {
    // Get the block ending address
    let block_end_binding = ID_TO_BLOCK.lock().unwrap();
    let block_end = block_end_binding.as_ref().unwrap().get(&id);

    if block_end.is_none() {
        return;
    }

    let block_end_val = block_end.unwrap();

    // Update the hitcount
    match HITCOUNTS.lock().unwrap().as_mut().unwrap().entry(*block_end_val) {
        Entry::Occupied(mut e) => {
            *e.get_mut() += 1;
        }
        Entry::Vacant(e) => {
            e.insert(1);
        }
    }
}

#[allow(clippy::unnecessary_cast)]
pub fn gen_hashed_edge_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    if let Some(module) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
        #[cfg(emulation_mode = "usermode")]
        if !module.must_instrument(src) && !module.must_instrument(dest) {
            return None;
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            let paging_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !module.must_instrument(src, paging_id) && !module.must_instrument(dest, paging_id) {
                return None;
            }
        }

        let id = hash_me(src as u64) ^ hash_me(dest as u64);

        unsafe {
            let nxt = (id as usize + 1) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
            *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = nxt;
        }

        // GuestAddress is u32 for 32 bit guests
        #[allow(clippy::unnecessary_cast)]
        Some(id)
    } else {
        None
    }
}

/// # Safety
/// Increases id at `EDGES_MAP_PTR` - potentially racey if called concurrently.
pub unsafe extern "C" fn trace_edge_hitcount_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = LIBAFL_QEMU_EDGES_MAP_PTR.add(id as usize);
        *ptr = (*ptr).wrapping_add(1);
    }
}

/// # Safety
/// Fine.
/// Worst case we set the byte to 1 multiple times.
pub unsafe extern "C" fn trace_edge_single_ptr(_: *const (), id: u64) {
    unsafe {
        let ptr = LIBAFL_QEMU_EDGES_MAP_PTR.add(id as usize);
        *ptr = 1;
    }
}

#[allow(clippy::unnecessary_cast)]
pub fn gen_hashed_block_ids<AF, ET, PF, S, V>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    AF: AddressFilter,
    ET: EmulatorModuleTuple<S>,
    PF: PageFilter,
    S: Unpin + UsesInput + HasMetadata,
    V: EdgeCoverageVariant<AF, PF>,
{
    // first check if we should filter
    if let Some(module) = emulator_modules.get::<EdgeCoverageModule<AF, PF, V>>() {
        #[cfg(emulation_mode = "usermode")]
        {
            if !module.must_instrument(pc) {
                return None;
            }
        }
        #[cfg(emulation_mode = "systemmode")]
        {
            let page_id = emulator_modules
                .qemu()
                .current_cpu()
                .and_then(|cpu| cpu.current_paging_id());

            if !module.must_instrument(pc, page_id) {
                return None;
            }
        }
    }

    let id = hash_me(pc as u64);

    unsafe {
        let nxt = (id as usize + 1) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
        *LIBAFL_QEMU_EDGES_MAP_SIZE_PTR = nxt;
    }

    // GuestAddress is u32 for 32 bit guests
    #[allow(clippy::unnecessary_cast)]
    Some(id)
}

/// # Safety
/// Dereferences the global `PREV_LOC` variable. May not be called concurrently.
pub unsafe extern "C" fn trace_block_transition_hitcount(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
            let entry = LIBAFL_QEMU_EDGES_MAP_PTR.add(x);
            *entry = (*entry).wrapping_add(1);
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

/// # Safety
/// Dereferences the global `PREV_LOC` variable. May not be called concurrently.
pub unsafe extern "C" fn trace_block_transition_single(_: *const (), id: u64) {
    unsafe {
        PREV_LOC.with(|prev_loc| {
            let x = ((*prev_loc.get() ^ id) as usize) & LIBAFL_QEMU_EDGES_MAP_MASK_MAX;
            let entry = LIBAFL_QEMU_EDGES_MAP_PTR.add(x);
            *entry = 1;
            *prev_loc.get() = id.overflowing_shr(1).0;
        });
    }
}

pub fn get_hitcounts_with_address_key() -> HashMap<(GuestAddr, GuestAddr), u64> {
    let mut hitcounts_ret = HashMap::new();

    // Iterate through BLOCK_START to get each block ending and start address
    // For each block ending address, get the hitcount from HITCOUNTS
    for (pc_end, pc_start) in BLOCK_START.lock().unwrap().as_ref().unwrap() {
        let hitcount_binding = HITCOUNTS.lock().unwrap();
        let hitcount = hitcount_binding.as_ref().unwrap().get(pc_end).unwrap();
        hitcounts_ret.insert((*pc_start, *pc_end), *hitcount);
    }

    hitcounts_ret
}