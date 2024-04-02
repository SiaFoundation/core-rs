use std::ops::{Add, Sub, Mul, Div};
use std::num::ParseIntError;
use std::str::FromStr;
use std::fmt;

use crate::SiaEncodable;


// I miss untyped constants
const SIACOIN_PRECISION_I32: i32 = 24;
const SIACOIN_PRECISION_U32: u32 = 24;

// Currency represents a quantity of Siacoins as Hastings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Currency(u128);

impl Currency {
	pub fn new(value: u128) -> Self {
		Currency(value)
	}

	pub fn parse_string(s: &str) -> Result<Self, CurrencyParseError> {
		let i = s.find(|c: char| !c.is_digit(10) && c != '.').unwrap_or(s.len());
		let (value, unit) = s.split_at(i);
		let unit = unit.trim();

		if unit.is_empty() || unit == "H" {
			let value = value.parse::<u128>()?;
			return Ok(Currency::new(value))
		}

		let scaling_factor: i32 = match unit {
			"pS" => -12,
			"nS" => -9,
			"uS" => -6,
			"mS" => -3,
			"SC" => 0,
			"KS" => 3,
			"MS" => 6,
			"GS" => 9,
			"TS" => 12,
			&_ => return Err(CurrencyParseError::InvalidUnit(unit.to_string())),
		};

		let parts: Vec<&str> = value.split('.').collect();
		if parts.len() > 2 {
			return Err(CurrencyParseError::InvalidFormat("too many decimal points".to_string()))
		}

		let integer_part = parts[0].parse::<u128>().map_err(|_| CurrencyParseError::InvalidFormat("invalid integer part".to_string()))?;
		let fraction_part = if parts.len() == 2 {
			parts[1].parse::<u128>().map_err(|_| CurrencyParseError::InvalidFormat("invalid integer part".to_string()))?
		} else {
			0
		};

		let frac_digits = parts.get(1).map_or(0, |frac| frac.len() as i32);
		let integer = integer_part * 10u128.pow((SIACOIN_PRECISION_I32 + scaling_factor) as u32);
		let fraction = fraction_part * 10u128.pow((SIACOIN_PRECISION_I32 - frac_digits + scaling_factor) as u32);

		Ok(Currency::new(integer+fraction))
	}

	/// Converts a given amount of Siacoins into the `Currency` type.
	///
	/// This function takes the amount of Siacoins as a `u64` and converts it into
	/// the `Currency` type, which internally represents the value in Hastings where
	/// 1 SC = 10^24 H.
	///
	/// # Arguments
	///
	/// * `n` - The amount of Siacoins to be converted into `Currency`.
	///
	/// # Returns
	///
	/// Returns a `Currency` instance representing the specified amount of Siacoins.
	pub fn siacoins(n: u64) -> Self {
		Currency::new((n as u128) * 10u128.pow(SIACOIN_PRECISION_U32))
	}

	pub fn checked_add(self, other: Currency) -> Option<Self> {
		let v = self.0.checked_add(other.0)?;
		Some(Currency(v))
	}

	pub fn checked_sub(self, other: Currency) -> Option<Self> {
		let v = self.0.checked_sub(other.0)?;
		Some(Currency(v))
	}

	pub fn checked_mul(self, other: Currency) -> Option<Self> {
		let v = self.0.checked_mul(other.0)?;
		Some(Currency(v))
	}

	pub fn checked_div(self, other: Currency) -> Option<Self> {
		let v = self.0.checked_div(other.0)?;
		Some(Currency(v))
	}
}

impl Add for Currency {
	type Output = Self;

	fn add(self, other: Self) -> Self {
		Self(self.0 + other.0)
	}
}

impl Sub for Currency {
	type Output = Self;

	fn sub(self, other: Self) -> Self {
		Self(self.0 - other.0)
	}
}

impl Mul for Currency {
	type Output = Self;

	fn mul(self, other: Self) -> Self {
		Self(self.0 * other.0)
	}
}

impl Div for Currency {
	type Output = Self;

	fn div(self, other: Self) -> Self {
		Self(self.0 / other.0)
	}
}

impl SiaEncodable for Currency {
	fn encode(&self, buf: &mut Vec<u8>) {
		let currency_buf = self.0.to_be_bytes();
		let i = currency_buf.iter()
        	.enumerate()
        	.find(|&(_index, &value)| value != 0)
        	.map_or(16, |(index, _value)| index); // 16 if all bytes are 0
		
		buf.extend_from_slice(&currency_buf[i..].len().to_le_bytes());
		buf.extend_from_slice(&currency_buf[i..]);
	}
}

#[derive(Debug, PartialEq)]
pub enum CurrencyParseError {
	ParseIntErr(ParseIntError),
	InvalidUnit(String),
	InvalidFormat(String),
}

impl From<ParseIntError> for CurrencyParseError {
    fn from(err: ParseIntError) -> Self {
        CurrencyParseError::ParseIntErr(err)
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if self.0 == 0 {
			return f.write_str("0 SC");
		}

		let value_string = self.0.to_string();
		let mut u = (value_string.len() - 1) / 3;
		if u < 4 {
			return write!(f, "{} H", value_string);
		} else if u > 12 {
			u = 12;
		}

		let mant = &value_string[..value_string.len() - 3 * u];
		let frac = value_string[value_string.len()-u*3..].trim_end_matches('0');
		let unit = match u-4 {
			0 => "pS",
			1 => "nS",
			2 => "uS",
			3 => "mS",
			4 => "SC",
			5 => "KS",
			6 => "MS",
			7 => "GS",
			8 => "TS",
			_ => panic!("unexpected unit")
		};

		if frac.is_empty() {
			return write!(f, "{} {}", mant, unit);
		}
		write!(f, "{}.{} {}", mant, frac, unit)
    }
} 

impl FromStr for Currency {
	type Err = CurrencyParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let i = s.find(|c: char| !c.is_digit(10) && c != '.').unwrap_or(s.len());
		let (value, unit) = s.split_at(i);
		let unit = unit.trim();

		if unit.is_empty() || unit == "H" {
			let value = value.parse::<u128>()?;
			return Ok(Currency::new(value))
		}

		let scaling_factor: i32 = match unit {
			"pS" => -12,
			"nS" => -9,
			"uS" => -6,
			"mS" => -3,
			"SC" => 0,
			"KS" => 3,
			"MS" => 6,
			"GS" => 9,
			"TS" => 12,
			&_ => return Err(CurrencyParseError::InvalidUnit(unit.to_string())),
		};

		let parts: Vec<&str> = value.split('.').collect();
		if parts.len() > 2 {
			return Err(CurrencyParseError::InvalidFormat("too many decimal points".to_string()))
		}

		let integer_part = parts[0].parse::<u128>().map_err(|_| CurrencyParseError::InvalidFormat("invalid integer part".to_string()))?;
		let fraction_part = if parts.len() == 2 {
			parts[1].parse::<u128>().map_err(|_| CurrencyParseError::InvalidFormat("invalid integer part".to_string()))?
		} else {
			0
		};

		let frac_digits = parts.get(1).map_or(0, |frac| frac.len() as i32);
		let integer = integer_part * 10u128.pow((SIACOIN_PRECISION_I32 + scaling_factor) as u32);
		let fraction = fraction_part * 10u128.pow((SIACOIN_PRECISION_I32 - frac_digits + scaling_factor) as u32);

		Ok(Currency::new(integer+fraction))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_display() {
		let test_cases = vec![
			(Currency::new(1), "1 H"),
			(Currency::new(100), "100 H"),
			(Currency::new(1001), "1001 H"),
			(Currency::new(10000), "10000 H"),
			(Currency::siacoins(1)/Currency::new(1_000_000_000_000), "1 pS"),
			(Currency::siacoins(151212312)/Currency::new(1_000_000_000_000), "151.212312 uS"),
			(Currency::siacoins(1)/Currency::new(2), "500 mS"),
			(Currency::siacoins(1), "1 SC"),
			(Currency::siacoins(10), "10 SC"),
			(Currency::siacoins(100), "100 SC"),
			(Currency::siacoins(1000), "1 KS"),
			(Currency::siacoins(10000), "10 KS"),
			(Currency::siacoins(u16::MAX as u64), "65.535 KS"),
			(Currency::siacoins(10_0000), "100 KS"),
			(Currency::siacoins(1_000_000), "1 MS"),
			(Currency::siacoins(10_000_000), "10 MS"),
			(Currency::siacoins(100_000_000), "100 MS"),
			(Currency::siacoins(1_000_000_000), "1 GS"),
			(Currency::siacoins(u32::MAX as u64), "4.294967295 GS"),
			(Currency::siacoins(10_000_000_000), "10 GS"),
			(Currency::siacoins(100_000_000_000), "100 GS"),
			(Currency::siacoins(1_000_000_000_000), "1 TS"),
			(Currency::siacoins(10_000_000_000_000), "10 TS"),
			(Currency::siacoins(100_000_000_000_000), "100 TS"),
			(Currency::siacoins(10) - Currency::new(1), "9.999999999999999999999999 SC"),
			(Currency::new(50_587_566_000_000_000_000_000_000),"50.587566 SC"),
			(Currency::new(2529378333356156158367), "2.529378333356156158367 mS"),
			(Currency::new(u128::MAX), "340.282366920938463463374607431768211455 TS"),
		];

		for (currency, expected) in test_cases {
			assert_eq!(currency.to_string(), expected);
		}
	}
	
	#[test]
	fn test_from_str() {
		let test_cases = vec![
			("1 H", Currency::new(1)),
			("100 H", Currency::new(100)),
			("1001 H", Currency::new(1001)),
			("10000 H", Currency::new(10000)),
			("1 pS", Currency::siacoins(1)/Currency::new(1_000_000_000_000)),
			("151.212312 uS", Currency::siacoins(151212312)/Currency::new(1_000_000_000_000)),
			("500 mS", Currency::siacoins(1)/Currency::new(2)),
			("1 SC", Currency::siacoins(1)),
			("10 SC", Currency::siacoins(10)),
			("100 SC", Currency::siacoins(100)),
			("1 KS", Currency::siacoins(1000)),
			("10 KS", Currency::siacoins(10000)),
			("65.535 KS", Currency::siacoins(u16::MAX as u64)),
			("100 KS", Currency::siacoins(100000)),
			("1 MS", Currency::siacoins(1000000)),
			("10 MS", Currency::siacoins(10000000)),
			("100 MS", Currency::siacoins(100000000)),
			("1 GS", Currency::siacoins(1000000000)),
			("4.294967295 GS", Currency::siacoins(u32::MAX as u64)),
			("10 GS", Currency::siacoins(10000000000)),
			("100 GS", Currency::siacoins(100000000000)),
			("1 TS", Currency::siacoins(1000000000000)),
			("10 TS", Currency::siacoins(10000000000000)),
			("100 TS", Currency::siacoins(100000000000000)),
			("9.999999999999999999999999 SC", Currency::siacoins(10) - Currency::new(1)),
			("50.587566 SC", Currency::new(50587566000000000000000000)),
			("2.529378333356156158367 mS", Currency::new(2529378333356156158367)),
			("340.282366920938463463374607431768211455 TS", Currency::new(u128::MAX)),
		];
		for (input, expected) in test_cases {
			assert_eq!(input.parse::<Currency>().unwrap(), expected);
		}
	}

	#[test]
	fn test_encode() {
		let test_cases = vec![
			(Currency::new(0),vec![0,0,0,0,0,0,0,0]),
			(Currency::new(10000),vec![2,0,0,0,0,0,0,0,39,16]),
			(Currency::new(50587566000000000000000000),vec![11,0,0,0,0,0,0,0,41,216,85,114,169,108,83,1,248,0,0]),
			(Currency::new(2529378333356156158367),vec![9,0,0,0,0,0,0,0,137,30,45,0,247,119,66,129,159]),
			(Currency::new(340282366920938463463374607431768211455),vec![16,0,0,0,0,0,0,0,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255]),
		];

		for (currency, expected) in test_cases {
			let mut buf = Vec::new();
			currency.encode(&mut buf);
			assert_eq!(buf, expected, "failed for {:?}", currency);
		}
	}
}