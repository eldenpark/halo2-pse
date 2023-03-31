use rust_decimal::Decimal;

#[derive(Debug)]
pub struct Account {
    pub addr: String,
    pub wei: Decimal,
}

impl Account {
    pub fn table_name() -> &'static str {
        "accounts"
    }
}

#[derive(Debug)]
pub struct Node {
    pub pos_w: Decimal,
    pub pos_h: i32,
    pub val: String,
    pub set_id: String,
}

impl Node {
    pub fn table_name() -> &'static str {
        "nodes"
    }
}
