pub const NUMBER_OF_LIMBS: usize = 4;

pub const BIT_LEN_LIMB: usize = 72;

pub const BIT_LEN_LAST_LIMB: usize = 256 - (NUMBER_OF_LIMBS - 1) * BIT_LEN_LIMB;

pub const POS_WIDTH: usize = 3;

pub const POS_RATE: usize = 2;
