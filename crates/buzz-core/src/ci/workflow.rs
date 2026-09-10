//! Repository-relative workflow registration shared by preflight and the CLI.

/// Default workflow used by ordinary CI and the protected merge gate.
pub const DEFAULT_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
/// Explicit selector for the registered native macOS workflow.
pub const NATIVE_MACOS_SELECTOR: &str = "native-macos";
/// Native macOS workflow location in the trusted base tree.
pub const NATIVE_MACOS_WORKFLOW_PATH: &str = ".buzz/workflows/native-macos.yml";

/// Resolve a selector to a fixed registered path, never a caller-provided path.
///
/// Omission and ordinary name/digest selectors retain the default CI workflow.
/// The caller must still read the trusted base and verify the selector against
/// the resolved workflow identity. This mapping grants no execution authority.
pub fn workflow_path_for_selector(selector: Option<&str>) -> &'static str {
    match selector {
        Some(NATIVE_MACOS_SELECTOR) => NATIVE_MACOS_WORKFLOW_PATH,
        _ => DEFAULT_WORKFLOW_PATH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_native_selector_changes_registered_path() {
        assert_eq!(
            workflow_path_for_selector(Some("native-macos")),
            NATIVE_MACOS_WORKFLOW_PATH
        );
        for selector in [
            None,
            Some("CI"),
            Some("ci"),
            Some(""),
            Some("../native-macos"),
            Some(NATIVE_MACOS_WORKFLOW_PATH),
            Some("NATIVE-MACOS"),
        ] {
            assert_eq!(workflow_path_for_selector(selector), DEFAULT_WORKFLOW_PATH);
        }
        assert_eq!(
            workflow_path_for_selector(Some(&"a".repeat(64))),
            DEFAULT_WORKFLOW_PATH
        );
    }
}
