fn main() {
    windows::build!(
        windows::win32::intl::{ISpellChecker, SpellCheckerFactory, ISpellCheckerFactory},
        windows::win32::com::*
    )
}
