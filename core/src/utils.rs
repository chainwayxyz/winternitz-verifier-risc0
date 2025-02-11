pub fn log_base_ceil(n: u32, base: u32) -> u32 {
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}

pub fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u8> {
    let mut digits = Vec::new();
    if digit_count == -1 {
        while number > 0 {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    } else {
        digits.reserve(digit_count as usize);
        for _ in 0..digit_count {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    }
    let mut digits_u8: Vec<u8> = vec![0; digits.len()];
    for (i, num) in digits.iter().enumerate() {
        let bytes = num.to_le_bytes(); // Convert u32 to 4 bytes (little-endian)
        digits_u8[i] = bytes[0];
    }
    digits_u8
}
