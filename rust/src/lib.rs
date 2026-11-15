//! Shared Nitro attestation verification for the native CLI and browser WASM.
pub mod verify;
pub mod wasm;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const MAX_DOCUMENT: usize = 16 * 1024;
pub const MAX_ENCODED_DOCUMENT: u64 = 24 * 1024;
const INVALID_DOCUMENT_EXIT: i32 = 2;

// Invalid peer evidence is distinct from local I/O, configuration and crypto
// runtime failures. Both frontends use this distinction: false versus an error
// in the browser, exit 2 versus exit 1 in the CLI.
#[derive(Debug)]
struct InvalidDocument(String);

impl std::fmt::Display for InvalidDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for InvalidDocument {}

pub fn invalid_doc(message: impl std::fmt::Display) -> Box<dyn std::error::Error> {
    Box::new(InvalidDocument(message.to_string()))
}

pub fn exit_code(error: &(dyn std::error::Error + 'static)) -> i32 {
    if error.is::<InvalidDocument>() {
        INVALID_DOCUMENT_EXIT
    } else {
        1
    }
}
