use rust_decimal::Decimal;

#[derive(Debug)]
pub struct Account {
    pub addr: String,
    pub wei: Decimal,
}
