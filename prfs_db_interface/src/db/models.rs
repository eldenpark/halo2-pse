use rust_decimal::Decimal;

#[derive(Debug)]
pub struct Account {
    pub addr: String,
    pub wei: Decimal,
}

#[derive(Debug)]
pub struct Node {
    pub pos_w: Decimal,
    pub pos_h: Decimal,
    pub val: String,
    pub set_id: String,
}
