// ============================================================================
// Optional Gum-backed module services installed by the embedding agent
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleDetails {
    pub name: String,
    pub version: Option<String>,
    pub path: String,
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleIdentity {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSectionDetails {
    pub id: String,
    pub name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleDependencyDetails {
    pub name: String,
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessThreadDetails {
    pub id: u64,
    pub name: Option<String>,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModuleObserverEvent {
    Added(ModuleDetails),
    Removed(ModuleDetails),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreadObserverEvent {
    Added(ProcessThreadDetails),
    Removed(ProcessThreadDetails),
    Renamed {
        thread: ProcessThreadDetails,
        previous_name: Option<String>,
    },
}

#[derive(Clone, Copy)]
pub struct ModuleBackend {
    pub enumerate_modules: fn() -> Vec<ModuleDetails>,
    pub ensure_initialized: fn(&ModuleIdentity) -> Result<(), String>,
    pub enumerate_sections: fn(&ModuleIdentity) -> Result<Vec<ModuleSectionDetails>, String>,
    pub enumerate_dependencies: fn(&ModuleIdentity) -> Result<Vec<ModuleDependencyDetails>, String>,
    pub find_symbol_by_name: fn(&ModuleIdentity, &str) -> Result<Option<u64>, String>,
}

#[derive(Clone, Copy)]
pub struct ProcessObserverBackend {
    pub attach_module_observer: fn() -> Result<Vec<ModuleDetails>, String>,
    pub detach_module_observer: fn() -> Result<(), String>,
    pub attach_thread_observer: fn() -> Result<Vec<ProcessThreadDetails>, String>,
    pub detach_thread_observer: fn() -> Result<(), String>,
    pub start_dispatcher: fn() -> Result<(), String>,
}

static MODULE_BACKEND: std::sync::Mutex<Option<ModuleBackend>> = std::sync::Mutex::new(None);
static PROCESS_OBSERVER_BACKEND: std::sync::Mutex<Option<ProcessObserverBackend>> = std::sync::Mutex::new(None);

pub fn install_module_backend(backend: ModuleBackend) {
    *MODULE_BACKEND.lock().unwrap_or_else(|error| error.into_inner()) = Some(backend);
}

pub fn install_process_observer_backend(backend: ProcessObserverBackend) {
    *PROCESS_OBSERVER_BACKEND
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(backend);
}

fn module_backend() -> Option<ModuleBackend> {
    *MODULE_BACKEND.lock().unwrap_or_else(|error| error.into_inner())
}

fn process_observer_backend() -> Option<ProcessObserverBackend> {
    *PROCESS_OBSERVER_BACKEND
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}
