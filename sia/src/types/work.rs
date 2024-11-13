use core::fmt;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

use serde::Serialize;
use thiserror::Error;

/// Work is a 256-bit unsigned integer.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Work {
    hi: u128,
    lo: u128,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("empty string")]
    EmptyString,
    #[error("invalid character")]
    InvalidCharacter,
    #[error("overflow")]
    Overflow,
    #[error("{0}")]
    Custom(String),
}

impl Work {
    pub const fn new(lo: u128, hi: u128) -> Self {
        Work { lo, hi }
    }

    pub fn parse_string(s: &str) -> Result<Self, ParseError> {
        if s.is_empty() {
            return Err(ParseError::EmptyString);
        }

        let mut result = Work::new(0, 0);
        let ten = Work::new(10, 0);

        for c in s.chars() {
            let digit = c.to_digit(10).ok_or(ParseError::InvalidCharacter)?;

            // First multiply by 10
            result = result * ten;

            // Then add the digit
            let digit_work = Work::new(digit as u128, 0);

            // Check for overflow
            if result > (Work::new(u128::MAX, u128::MAX) - digit_work) {
                return Err(ParseError::Overflow);
            }

            result = result + digit_work;
        }

        Ok(result)
    }
}

impl PartialOrd for Work {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Work {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.hi.cmp(&other.hi) {
            std::cmp::Ordering::Equal => self.lo.cmp(&other.lo),
            ord => ord,
        }
    }
}

impl From<&[u8; 32]> for Work {
    fn from(bytes: &[u8; 32]) -> Self {
        Work::new(
            u128::from_le_bytes(bytes[0..16].try_into().unwrap()),
            u128::from_le_bytes(bytes[16..32].try_into().unwrap()),
        )
    }
}

impl Add for Work {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let (lo, carry) = self.lo.overflowing_add(other.lo);
        let (hi, _) = self.hi.overflowing_add(other.hi + carry as u128);
        Work::new(lo, hi)
    }
}

impl AddAssign for Work {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Sub for Work {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let (lo, borrow) = self.lo.overflowing_sub(other.lo);
        let (hi, _) = self.hi.overflowing_sub(other.hi + borrow as u128);
        Work::new(lo, hi)
    }
}

impl SubAssign for Work {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

fn mul_128(x: u128, y: u128) -> (u128, u128) {
    const MASK_64: u128 = (1u128 << 64) - 1;
    let xl = x & MASK_64;
    let xh = x >> 64;
    let yl = y & MASK_64;
    let yh = y >> 64;

    let ll = xl * yl;
    let lh = xl * yh;
    let hl = xh * yl;
    let hh = xh * yh;

    let lo = x.wrapping_mul(y);

    let hi = hh + ((lh + hl + (ll >> 64)) >> 64);
    (hi, lo)
}

impl Mul for Work {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let (overflow, lo) = mul_128(self.lo, other.lo);
        let hi = overflow
            .wrapping_add(self.hi.wrapping_mul(other.lo))
            .wrapping_add(self.lo.wrapping_mul(other.hi));

        Work { hi, lo }
    }
}

impl MulAssign for Work {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

fn div_128(hi: u128, lo: u128, y: u128) -> (u128, u128) {
    if y == 0 {
        panic!("Division by zero");
    } else if y < hi {
        panic!("overflow")
    }

    if hi == 0 {
        return (lo / y, lo % y);
    }

    let s = y.leading_zeros();
    let y = y << s;

    const TWO_64: u128 = 1 << 64;
    const MASK_64: u128 = TWO_64 - 1;

    let yn1 = y >> 64;
    let yn0 = y & MASK_64;
    let un32 = hi << s | lo >> (64 - s);
    let un10 = lo << s;
    let un1 = un10 >> 64;
    let un0 = un10 & MASK_64;
    let mut q1 = un32 / yn1;
    let mut rhat = un32 % yn1;

    while q1 >= TWO_64 || q1 * yn0 > TWO_64 * rhat + un1 {
        q1 -= 1;
        rhat += yn1;
        if rhat >= TWO_64 {
            break;
        }
    }

    let un21 = un32 * TWO_64 + un1 - q1 * y;
    let mut q0 = un21 / yn1;
    rhat = un21 % yn1;

    while q0 >= TWO_64 || q0 * yn0 > TWO_64 * rhat + un0 {
        q0 -= 1;
        rhat += yn1;
        if rhat >= TWO_64 {
            break;
        }
    }

    let hi = q1 * TWO_64 + q0;
    let lo = (un21 * TWO_64 + un0 - q0 * y) >> s;
    (hi, lo)
}

impl Div for Work {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        if other.lo == 0 && other.hi == 0 {
            panic!("Division by zero");
        } else if self < other {
            return Work::default();
        }

        let n = other.hi.leading_zeros();
        let v1 = Work::new(other.lo << n, other.hi << n | other.lo >> (128 - n));
        let u1 = Work::new(self.lo >> 1 | self.hi << 127, self.hi >> 1);
        let (mut tq, _) = div_128(u1.hi, u1.lo, other.hi);
        tq >>= 127 - n;
        if tq != 0 {
            tq -= 1;
        }
        let mut quotient = Work::new(tq, 0);
        let r = self - v1 * quotient;
        if r > other && quotient.lo + 1 == 0 {
            quotient.hi += 1;
        }
        quotient
    }
}

impl DivAssign for Work {
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

impl fmt::Display for Work {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.lo == 0 && self.hi == 0 {
            return write!(f, "0");
        } else if self.hi == 0 {
            return write!(f, "{}", self.lo);
        }

        let mut buf = [0u8; 78];
        let mut i = buf.len();
        let mut n = *self;
        let ten = Work::new(10, 0);

        while n != Work::new(0, 0) {
            let next = n / ten;
            let remainder = n - (next * ten);
            i -= 1;
            buf[i] = b'0' + remainder.lo as u8;
            n = next;
        }

        let s = std::str::from_utf8(&buf[i..]).unwrap();
        f.write_str(s)
    }
}

impl Serialize for Work {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition() {
        let a = Work::new(1, 0);
        let b = Work::new(2, 0);
        assert_eq!(a + b, Work::new(3, 0));

        let a = Work::new(u128::MAX, 0);
        let b = Work::new(1, 0);
        assert_eq!(a + b, Work::new(0, 1));

        let a = Work::new(u128::MAX, 0);
        let b = Work::new(6, 0);
        assert_eq!(a + b, Work::new(5, 1));

        let a = Work::new(u128::MAX - 5, 0);
        let b = Work::new(6, 0);
        assert_eq!(a + b, Work::new(0, 1));

        let a = Work::new(u128::MAX - 4, 0);
        let b = Work::new(6, 0);
        assert_eq!(a + b, Work::new(1, 1));

        let a = Work::new(0, 1);
        let b = Work::new(0, 2);
        assert_eq!(a + b, Work::new(0, 3));
    }

    #[test]
    fn test_subtraction() {
        let a = Work::new(3, 0);
        let b = Work::new(2, 0);
        assert_eq!(a - b, Work::new(1, 0));

        let a = Work::new(0, 1);
        let b = Work::new(1, 0);
        assert_eq!(a - b, Work::new(u128::MAX, 0));

        let a = Work::new(0, 3);
        let b = Work::new(0, 2);
        assert_eq!(a - b, Work::new(0, 1));
    }

    #[test]
    fn test_multiplication() {
        let a = Work::new(2, 0);
        let b = Work::new(3, 0);
        assert_eq!(a * b, Work::new(6, 0));

        let a = Work::new(1 << 127, 0);
        let b = Work::new(2, 0);
        assert_eq!(a * b, Work::new(0, 1));

        let a = Work::new(1 << 64, 0);
        assert_eq!(a * a, Work::new(0, 1));
    }

    #[test]
    fn test_division() {
        let a = Work::new(6, 0);
        let b = Work::new(2, 0);
        assert_eq!(a / b, Work::new(3, 0));

        let a = Work::new(7, 0);
        let b = Work::new(2, 0);
        assert_eq!(a / b, Work::new(3, 0));

        let a = Work::new(0, 2);
        let b = Work::new(2, 0);
        assert_eq!(a / b, Work::new(0, 1));
    }

    #[test]
    fn test_display() {
        assert_eq!(Work::new(0, 0).to_string(), "0");
        assert_eq!(Work::new(123, 0).to_string(), "123");
        assert_eq!(
            Work::new(0, 1).to_string(),
            "340282366920938463463374607431768211456"
        );
        assert_eq!(
            Work::new(u128::MAX, 0).to_string(),
            "340282366920938463463374607431768211455"
        );
        assert_eq!(
            Work::new(u128::MAX, u128::MAX).to_string(),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn test_parse_string() {
        let test_cases = vec![
            Work::new(0, 0),
            Work::new(123, 0),
            Work::new(u128::MAX, 0),
            Work::new(u128::MAX, 1),
            Work::new(u128::MAX, u128::MAX),
        ];
        for (i, tc) in test_cases.iter().enumerate() {
            assert_eq!(
                Work::parse_string(&tc.to_string()).unwrap(),
                *tc,
                "testcase {} failed",
                i
            );
        }
    }
}
