use crate::TreeMakerError;

pub struct SetType {
    pub table_label: String,
    pub query: String,
}

lazy_static::lazy_static! {
    static ref WEI_200: SetType = SetType {
        table_label: "balances_20230327".to_string(),
        query: "wei >= 277229987272358786 and wei < 277329987272358786".to_string(),
    };
}

pub async fn make_set(set_type: SetType) -> Result<(), TreeMakerError> {
    Ok(())
}
