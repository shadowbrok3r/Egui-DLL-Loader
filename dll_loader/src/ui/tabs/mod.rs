pub mod reflective_injection;
pub mod classic_injection;
pub mod process_hollowing;
pub mod manual_mapping;
pub mod help;

#[derive(Debug, Clone, PartialEq)]
pub enum InjectionPage {
    ClassicInjection,
    ProcessHollowing,
    ReflectiveInjection,
    ManualMapping,
    Help,
}
