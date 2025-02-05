pub fn log_base_ceil(n: u32, base: u32) -> u32 { 

    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}

pub fn u32_to_le_bytes_minimal(a: u32) -> Vec<u8> {
    let mut a_bytes = a.to_le_bytes().to_vec();
    while let Some(&0) = a_bytes.last() {
        a_bytes.pop(); // Remove trailing zeros
    }
    a_bytes
}

pub fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u32> {
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
    digits
}
