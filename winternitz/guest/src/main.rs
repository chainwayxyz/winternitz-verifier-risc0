use winternitz_guest::winternitz_circuit;

fn main() {
    let zkvm_guest = winternitz_core::zkvm::Risc0Guest::new();
    winternitz_circuit(&zkvm_guest);
}
