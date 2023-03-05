//! Constants for using Poseidon with the Vesta field.
//!
//! The constants can be reproduced by running the following Sage script from
//! [this repository](https://github.com/daira/pasta-hadeshash):
//!
//! ```text
//! sage generate_parameters_grain.sage 1 0 255 3 8 56 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
//! ```
use halo2_proofs::halo2curves::pasta::vesta;
use halo2_proofs::halo2curves::{
    pasta::{pallas, Fp},
    secp256k1,
    // secp256k1
    secp256k1::Fq as SecFq,
    // secp256k1::Fp as SecFq,
};

// Number of round constants: 192
// Round constants for GF(p):
pub(crate) const ROUND_CONSTANTS: [[SecFq; 3]; 64] = [
    [
        SecFq::from_raw([
            0xcf27ab8062e32d20,
            0x62ebf45db50b3c82,
            0x9000679706932707,
            0x218fe5b866ffd7f1,
        ]),
        SecFq::from_raw([
            0xc7f1a5012e3364d2,
            0x4420d11efd62db69,
            0x5bb31eefb1706629,
            0xd9024a16f5ea7a31,
        ]),
        SecFq::from_raw([
            0x464f891edd725401,
            0xfdabd3fda8703fa6,
            0x14c839c75ec06c41,
            0x480abcea775cf581,
        ]),
    ],
    [
        SecFq::from_raw([
            0xdab03b3d1ab89812,
            0x5ec1cf0b5ff1ae75,
            0x1426b46cfcec030b,
            0x937ec4a1d18ec619,
        ]),
        SecFq::from_raw([
            0x5e85b08e05fce7c8,
            0x134ced2d07f50024,
            0xe77fec27c813f03e,
            0x87845234ff2f657d,
        ]),
        SecFq::from_raw([
            0xea3b4a59f1857a10,
            0x16bb05cd654a1ff7,
            0xead599da6dfe7994,
            0x8eb4ec86a61fc535,
        ]),
    ],
    [
        SecFq::from_raw([
            0xba61e205dadfbd78,
            0x4f0d4a2922bab79f,
            0xe290b34f91e736aa,
            0xefb46e12766cb804,
        ]),
        SecFq::from_raw([
            0x3790579438ce60d0,
            0x6d4e30e1fa8cd7e0,
            0xc17598d9451f2940,
            0xcfba216b4f00dac0,
        ]),
        SecFq::from_raw([
            0x4a2f32bcd3251e7b,
            0x89787366af5da641,
            0xdbc2b1ddb6b4d243,
            0x467f4558ebfeb775,
        ]),
    ],
    [
        SecFq::from_raw([
            0x2a7240096abb90cd,
            0xd22ee17641145fd3,
            0x04a3814616074b80,
            0x50b8d7812001a841,
        ]),
        SecFq::from_raw([
            0x2b0b020bfc0124f5,
            0x47bfd0704f539d9b,
            0xba63a31f3c4489dd,
            0x2edaf2d9b6dc4211,
        ]),
        SecFq::from_raw([
            0xe5587ec04028b2f8,
            0x66fe1b861e4cd1a4,
            0x57abd467fd91d342,
            0x2183cc13652e8cb7,
        ]),
    ],
    [
        SecFq::from_raw([
            0xed63223cae10e702,
            0xe437776381778f19,
            0x03a1da508148d857,
            0x2a9bc6ed40a707b4,
        ]),
        SecFq::from_raw([
            0x37cb6027509b812d,
            0x09faa67b6b633661,
            0xd572a54322883ddf,
            0x33245c2edf1e3222,
        ]),
        SecFq::from_raw([
            0x1bed2c1525133850,
            0xcac7163822a0b5a8,
            0x5af2c0f07b9c2d92,
            0x15d215160cf2e0a5,
        ]),
    ],
    [
        SecFq::from_raw([
            0xa90959126673b41f,
            0x4119f759023fa412,
            0x807b23ee25815011,
            0x50c6d61b56fe4b3d,
        ]),
        SecFq::from_raw([
            0x79521405497817ea,
            0xa1e9e33183ee6938,
            0xf30dc8a6b4431039,
            0x8a5c4ac8724eb4a7,
        ]),
        SecFq::from_raw([
            0xcf4255f15ee2b168,
            0x91efb71942f25895,
            0xa9ac30acb8c6c6fe,
            0xd5902ae9cb153c61,
        ]),
    ],
    [
        SecFq::from_raw([
            0x9fd15eab57070ee1,
            0x104e068a1603a820,
            0x1adc68136039c704,
            0xdbed679ec3ca3471,
        ]),
        SecFq::from_raw([
            0xa6b2ffb97a14af83,
            0xf2a8a45d169afd7a,
            0x83dee0aa7208e361,
            0x7324825f3bd54ebc,
        ]),
        SecFq::from_raw([
            0x57060969c8af8019,
            0x0717f0a1b6d75acb,
            0xc55f0ea59885b5e1,
            0xe1563b41aca1f869,
        ]),
    ],
    [
        SecFq::from_raw([
            0x2e370a08f73fd25d,
            0x1e268275d34be575,
            0xd90c9079b0a9d389,
            0x3ba679cc115e909e,
        ]),
        SecFq::from_raw([
            0x03034fe965643856,
            0x9eedca077e241eae,
            0x669f505a39b0a618,
            0x0f9bd05372e74000,
        ]),
        SecFq::from_raw([
            0x87cb1d6eeb697ef1,
            0x640005dd11e96bfd,
            0x5c03245051afba12,
            0x2abc4951c596b4ac,
        ]),
    ],
    [
        SecFq::from_raw([
            0xb196c1108aa1174a,
            0x6896973485961aac,
            0x90f8d5a46f0ffb45,
            0x90f7a7fca1d19bcb,
        ]),
        SecFq::from_raw([
            0xce9c45b7aae68d1e,
            0xb2091278ef77d84d,
            0x0766c51930c75f51,
            0x811f577500e45186,
        ]),
        SecFq::from_raw([
            0x2dfb8d2074945023,
            0x221a2e0967fd58a9,
            0x6583eaf5fa849b18,
            0x6388feb7e34bcfae,
        ]),
    ],
    [
        SecFq::from_raw([
            0x03d4403e3a2ca03b,
            0xc45da5b1dfb44651,
            0x7e33ca9c6719614e,
            0x00b16aac29c19585,
        ]),
        SecFq::from_raw([
            0xbea5d9a66759838d,
            0x9b652b435d85d96f,
            0x1406227cafbb7407,
            0xdfff5c85699a99cb,
        ]),
        SecFq::from_raw([
            0xd71c36e80e285d30,
            0x2d93c45ad766b27a,
            0x296cce918222ae49,
            0x345ca1eaf0ac3bac,
        ]),
    ],
    [
        SecFq::from_raw([
            0x1ff51df6db2c71ea,
            0xfc515dec1e06754f,
            0xd5dedb9638c58ba1,
            0x64878579c501dc26,
        ]),
        SecFq::from_raw([
            0xd621c0ecd001df11,
            0x435b1c6645ce0141,
            0x189edb24ac15da42,
            0x6a6ee0e8068ed5fd,
        ]),
        SecFq::from_raw([
            0x790b690f93045162,
            0xd59c31257a2042f4,
            0xc10424ef5130cf02,
            0x5e153b1150b533ae,
        ]),
    ],
    [
        SecFq::from_raw([
            0x0e67ec68fb9506fb,
            0x1ae7d30216eec8ad,
            0xaf4c6382767ba68b,
            0x198a2ad8fe376c74,
        ]),
        SecFq::from_raw([
            0x1f118234e2ce4cd5,
            0x34ce00c0ff6dfaf9,
            0xa5abfcbd453154eb,
            0x850ff4851e8dfaba,
        ]),
        SecFq::from_raw([
            0x095a9b19d3146409,
            0x73070606dabb7bc1,
            0xf6cda3f41e023013,
            0xb4e64488e1224a78,
        ]),
    ],
    [
        SecFq::from_raw([
            0x99a6521c6ad4bbdf,
            0xa176d33a2cf45d2e,
            0x1d64a2f3482b94f4,
            0x0fd79cc4fe76de03,
        ]),
        SecFq::from_raw([
            0xd145ead2f6db6abd,
            0xe00d595c37aefa8c,
            0xea6505795bf6527c,
            0xa67476e131d2a9b2,
        ]),
        SecFq::from_raw([
            0x97a2b1fd505095d9,
            0x737a2e0288ebc58b,
            0x4736f6698f24d178,
            0x0fcf3bcba62e8ac7,
        ]),
    ],
    [
        SecFq::from_raw([
            0x58057b60daa72d72,
            0xd605033e1e34aefd,
            0xcc6ed89d73797c40,
            0x35e71a60ebcd87f0,
        ]),
        SecFq::from_raw([
            0x37f56c53f93cd99c,
            0xc7e4320394a5d806,
            0xf56780bd7d9c9f2d,
            0x15826935ea9dfbc1,
        ]),
        SecFq::from_raw([
            0x41799197aa332cc8,
            0x8cb1e663bb31b615,
            0x977b1d8e991101fb,
            0x1763b7d1c7e4b4ab,
        ]),
    ],
    [
        SecFq::from_raw([
            0xb0c88006380ae399,
            0x719818b795e76255,
            0xb53afd7e64342bc7,
            0x12112f5b5991350d,
        ]),
        SecFq::from_raw([
            0x78c7a8ae6434655a,
            0x0d220e2e4f1ab336,
            0xb938029ae8d79238,
            0x43413105eb01be49,
        ]),
        SecFq::from_raw([
            0xdab08b79ca670d9d,
            0x415d97adf381caee,
            0xa9a14371a359eab4,
            0x8d694c20161f56bf,
        ]),
    ],
    [
        SecFq::from_raw([
            0xfd1d8236c2ac0f34,
            0xc800bd29919a0cdd,
            0x5ec8246f2aa67000,
            0x37e40345d90178b5,
        ]),
        SecFq::from_raw([
            0x112ca74bd8f1d86a,
            0x0180e16ccf9cef4e,
            0x1b32563e7b17cfd0,
            0x21d6d115826560f4,
        ]),
        SecFq::from_raw([
            0xca9f79fad59b8160,
            0x18657c3291e6efed,
            0x7082f5d7ec16e244,
            0x71f5c70fb0ff4dd6,
        ]),
    ],
    [
        SecFq::from_raw([
            0x910d583a1743706f,
            0x66b94d323982b9ac,
            0x6278b6e276667931,
            0xc96e407a7e6499c7,
        ]),
        SecFq::from_raw([
            0x9b07b33009bfb672,
            0x39024d93c82b8f96,
            0x20a5f47f3db72bae,
            0x9f91dbd0974ed335,
        ]),
        SecFq::from_raw([
            0xaf0e8ef0951f6e81,
            0x1f09849d89e74eb6,
            0x6c0b186d28c1c94e,
            0x432046e14ca352c2,
        ]),
    ],
    [
        SecFq::from_raw([
            0x3d4387473e555b60,
            0xdad605f0637ef488,
            0x18fff269e779454d,
            0x54633f5e9175aae2,
        ]),
        SecFq::from_raw([
            0x8694ebb3f916566b,
            0xc43eb836e55b79b4,
            0x2509968fa43c2872,
            0x6da3991b096e10b5,
        ]),
        SecFq::from_raw([
            0x2cd5f65f9011e478,
            0x331471b5400caf4b,
            0x9f458e504334ae74,
            0x68cda42da84a391b,
        ]),
    ],
    [
        SecFq::from_raw([
            0xffe07d1e17628e4f,
            0x9f6d6241232cf2e6,
            0xc44603654747b562,
            0xcfcc5ea5b020b1c5,
        ]),
        SecFq::from_raw([
            0x11ceb268e42931f7,
            0xdcfe116192c07b27,
            0xdaab2e1c481a1203,
            0x1769dd1c7934ca9e,
        ]),
        SecFq::from_raw([
            0x76d2d4bacd47b66b,
            0x9346cd421961a2af,
            0x7ce30db97a880f92,
            0x4085640721e80863,
        ]),
    ],
    [
        SecFq::from_raw([
            0x2feb2023e10d1a73,
            0x3fe81feefd9b871c,
            0xe373afd2d7641fe9,
            0x09226e6059900df0,
        ]),
        SecFq::from_raw([
            0xde31499c62d690a4,
            0x732691ffa2c20d55,
            0x171a7d866fd393b6,
            0x5ff0fd13dc382a9e,
        ]),
        SecFq::from_raw([
            0xd34918abc12efe20,
            0xffb84642a81e81eb,
            0xda7adbb55831cde3,
            0xd293c68f70d58c18,
        ]),
    ],
    [
        SecFq::from_raw([
            0x69b5d268c98c61a8,
            0xb1ba32cf9dcaf152,
            0x4c7b35c72903970a,
            0x0d4aca2a26f4ebb2,
        ]),
        SecFq::from_raw([
            0x956b1929778f01e3,
            0x279d2c4d9cbbc764,
            0xfe54486f0a1912f9,
            0x39e32f536f54af39,
        ]),
        SecFq::from_raw([
            0x62a3b84a7b251619,
            0x52ebea422494a070,
            0xb3cd901096f03d76,
            0x399cde4a3d4fed41,
        ]),
    ],
    [
        SecFq::from_raw([
            0xc9126ab1bf8ea7cf,
            0x64cfc0d4ae9c0ee9,
            0x82c731f4897cf3ae,
            0xed17f6c23e941b39,
        ]),
        SecFq::from_raw([
            0x3f525ffaf56bf4bb,
            0x9403e4ded3350249,
            0xdc9418badeaae35a,
            0xba9ff6a3be47138a,
        ]),
        SecFq::from_raw([
            0xdabc1ad1b188c250,
            0xf2fc465314afb8ff,
            0x342b555db47c2b42,
            0x73d198e49a5ba537,
        ]),
    ],
    [
        SecFq::from_raw([
            0xc8b8a9027eec859b,
            0x1a439fd276a75842,
            0x15fe9db8712a4f7e,
            0xd3ae59e3c068e2c7,
        ]),
        SecFq::from_raw([
            0x10bec72850f5168a,
            0x4cab23799a5b1ab0,
            0x4785461f0532e532,
            0x323628ee1cc8ffca,
        ]),
        SecFq::from_raw([
            0xcf760eb73656ae37,
            0xbcc8bfb27e53ea35,
            0xb79ecdc7592b0809,
            0x257eed339cc8e1be,
        ]),
    ],
    [
        SecFq::from_raw([
            0x3edda3c65ccf7746,
            0xb73dc0169957d31b,
            0x601b6f4eec5523ae,
            0x216b97559558b222,
        ]),
        SecFq::from_raw([
            0x96ab1fae07097325,
            0x9307ae029ef2f81f,
            0x24b27a27735968e9,
            0xee813ade2cf0ae6d,
        ]),
        SecFq::from_raw([
            0xf2f53a7864cd1974,
            0xc1deb40f1c5b31e8,
            0x9e9fbfa6a814dc24,
            0x61be08729aa65715,
        ]),
    ],
    [
        SecFq::from_raw([
            0x7c015c043538a78f,
            0xec28565b8bd58f21,
            0xcfbd8bd9d0f98baa,
            0xc7a761dcc08b07e3,
        ]),
        SecFq::from_raw([
            0xab4f40071ed57728,
            0xb00194d5f9ccefd2,
            0x64a8be8901d252dc,
            0xe80310e1b7cc5e6f,
        ]),
        SecFq::from_raw([
            0x115249fc32ddd87e,
            0x3a979ce37f424254,
            0xb2cd6d9a4d861a03,
            0xdd2ada833d3ab9f5,
        ]),
    ],
    [
        SecFq::from_raw([
            0xe361e5bc9f60fdc4,
            0xf61244ee819d0884,
            0xeaf3474bb6553877,
            0xe459917758069926,
        ]),
        SecFq::from_raw([
            0x9b3a1e249c585ca9,
            0xcaa5b152a372d6c5,
            0x7d2435f4cf5a8853,
            0xb5ba3eda3af61cec,
        ]),
        SecFq::from_raw([
            0x703627403f2bd298,
            0x983f74d704ea43af,
            0xeb8f4dbbc2c0a414,
            0x1632df1f9f57382a,
        ]),
    ],
    [
        SecFq::from_raw([
            0x11addd157aad8176,
            0xfeeee41985aad1a3,
            0x0a11c1f7410a08ae,
            0x3c5da4efb0671150,
        ]),
        SecFq::from_raw([
            0xf04b4867469be3d4,
            0xa8ff845148fd6a79,
            0xb65b3f9213296b3d,
            0x5e3e288c966b736d,
        ]),
        SecFq::from_raw([
            0x657cea5b71c6885f,
            0x23c21184f23669bd,
            0x44da838746b9b90e,
            0xaa2cd4e6f5ea3cf8,
        ]),
    ],
    [
        SecFq::from_raw([
            0x6bf75c6e788504c3,
            0x826372971eca766a,
            0x2b65fece716cd64a,
            0x57fc4260962d37cb,
        ]),
        SecFq::from_raw([
            0xa4b86d65cc7868fa,
            0x5724f74f2b61c22f,
            0xa206e7b2d684b76e,
            0x209966a1b1356993,
        ]),
        SecFq::from_raw([
            0x26760f6984fbeae7,
            0xb75b9a012b3d3658,
            0xef7ef7fd8048ea02,
            0x5fffafb75ae81f1b,
        ]),
    ],
    [
        SecFq::from_raw([
            0x17e0056592256852,
            0xc83d2b0c712b7b4f,
            0xfff32a35d95eef28,
            0xee7d204c3acd6f10,
        ]),
        SecFq::from_raw([
            0xbc911aa8bd6e709b,
            0xafcda98256aebbc3,
            0x5976a0accbcb6c18,
            0x57579227970323b4,
        ]),
        SecFq::from_raw([
            0x09b837b98c358b54,
            0xc2418338c663b9e0,
            0x68d2b1efc9db6a77,
            0x83efab5492e67470,
        ]),
    ],
    [
        SecFq::from_raw([
            0x0cd88a78d02b2ef4,
            0xc05de9baf3a2b475,
            0x63dca583a2a97895,
            0xd0dc6c609006837e,
        ]),
        SecFq::from_raw([
            0xea44f537f8d7be30,
            0xa9ec38876b22108e,
            0x6a47f54e8b92245f,
            0x21430da26ac07a79,
        ]),
        SecFq::from_raw([
            0x429e6d2fa89922f3,
            0xe16fa4f172e66334,
            0x529ef5ed25237fe8,
            0x9479ed819f2af2a1,
        ]),
    ],
    [
        SecFq::from_raw([
            0x337ada2fbc223746,
            0xb1fc92119ffaa7eb,
            0xa4b8deaf3b2967a6,
            0xa13235ec974c16b7,
        ]),
        SecFq::from_raw([
            0xac5e053ae0a493e5,
            0x73ec8170639b6a12,
            0x88359ec4171ee6ec,
            0xe3a8df05fd6de940,
        ]),
        SecFq::from_raw([
            0x19a50b5989f7b7d4,
            0x5bbec568268b713c,
            0x40ad0671545761c9,
            0x7f17a712ff1602a9,
        ]),
    ],
    [
        SecFq::from_raw([
            0x16b782941f1c11f4,
            0x43d905641f26217a,
            0x73b27d5a1fb6924f,
            0x3319159a8546df85,
        ]),
        SecFq::from_raw([
            0x4c54a334b90fb300,
            0x844aa6f19cfcce19,
            0x703b3c1a27099072,
            0xedee2146127b0d8b,
        ]),
        SecFq::from_raw([
            0xe65fbcd1024dad19,
            0x6ab832b36a2ab783,
            0xd6c3ffd30a697182,
            0xb9a063aaf3e20768,
        ]),
    ],
    [
        SecFq::from_raw([
            0xe0afecf8d9941f15,
            0x99ea647a9c192039,
            0x9b830095057f229f,
            0x5e769953faa47fe0,
        ]),
        SecFq::from_raw([
            0x6926e7de7fe25bcc,
            0x3e48ab13f4df2017,
            0x7c32db5248667815,
            0x57100c1b33e3b1eb,
        ]),
        SecFq::from_raw([
            0x3f758d5b0545d3e9,
            0xbe3f9f93b7764482,
            0xe58ea700e1bb32e1,
            0x9fa1d1667272504f,
        ]),
    ],
    [
        SecFq::from_raw([
            0x7125e7c4c67f6580,
            0x1f959de3e3f70412,
            0x98d8f9eff80b1ccb,
            0x1d9a47898a267dd4,
        ]),
        SecFq::from_raw([
            0xbbfabbd5ef0f09d1,
            0xd5000f9ef105a183,
            0xb8a64f1f131bc69e,
            0xe0f1c7454e6ac737,
        ]),
        SecFq::from_raw([
            0x931f4499fc532729,
            0x7e365b229f67db26,
            0x7c38295dd7ed80a5,
            0xa9e71885e72950d7,
        ]),
    ],
    [
        SecFq::from_raw([
            0xf62472b2397170af,
            0x0684f62d0056dc3b,
            0x44da703a3c65e996,
            0x77283336565fa122,
        ]),
        SecFq::from_raw([
            0x6001e0132e6050f8,
            0x5b8034069e331dd4,
            0x39db1ca47b3dba94,
            0x36955c8200a957be,
        ]),
        SecFq::from_raw([
            0xb385d0f313275345,
            0x734533da15fca713,
            0x033e379f1658c6e9,
            0x98d7b66399475fd6,
        ]),
    ],
    [
        SecFq::from_raw([
            0x721ce12411ae5f72,
            0xada0e8f5e972437b,
            0xbe76df190b1c2c76,
            0x0653d30f8c1437e5,
        ]),
        SecFq::from_raw([
            0xb37ca20f0142eefc,
            0x495b1fc8db7587c4,
            0xd3e76666ebb86404,
            0x527d7a42ff4b7b4b,
        ]),
        SecFq::from_raw([
            0x0979295a7b355f21,
            0x6af4297513d4b09d,
            0xe2a2942bf78ff78f,
            0xb916c1e39d644e78,
        ]),
    ],
    [
        SecFq::from_raw([
            0x2cc92c95629f8628,
            0xa820deb6dc230020,
            0x958fe4e836c3b49f,
            0xe51e4cc917c198c0,
        ]),
        SecFq::from_raw([
            0x389a67713058af5d,
            0x0e40667b785542c7,
            0x50c32ee930d82eb9,
            0xbbda6a9943af04ae,
        ]),
        SecFq::from_raw([
            0x3ad44a701c6796a3,
            0x36f1717bcc7d0550,
            0x2c2cbabd2e16a46e,
            0x5c8ece775f9c331c,
        ]),
    ],
    [
        SecFq::from_raw([
            0x5fe3cc3a5750f351,
            0x9bc50f2af3ef1530,
            0x991468807be52b22,
            0x660bb9527ddf146f,
        ]),
        SecFq::from_raw([
            0x502f61a10c5b01ff,
            0x90c30767337ea912,
            0x52944cddb83d5d7d,
            0x8e6a596c72906f84,
        ]),
        SecFq::from_raw([
            0xf9461588446bbc49,
            0x30d4766bb3481778,
            0xad5737f685ac30c5,
            0xd1e788d189864814,
        ]),
    ],
    [
        SecFq::from_raw([
            0x7df799b3029038f0,
            0x38cba443d018f198,
            0x55a1050fb69fa198,
            0xf27e2989dd5724a3,
        ]),
        SecFq::from_raw([
            0xb49a7bd516d9ea3f,
            0x3614c73a09a9cbb3,
            0xe20a95ab9b82a535,
            0x8809e09aa92e55ef,
        ]),
        SecFq::from_raw([
            0x10efb10ec12ddc98,
            0xffcc3313ceb355f4,
            0x31f93becda9ef3b9,
            0x2758f1cedf6dc152,
        ]),
    ],
    [
        SecFq::from_raw([
            0xe4048193ccaf0b5d,
            0x581b094f38ac4790,
            0x23202eeec66b3b4f,
            0x0522db529ca02ea1,
        ]),
        SecFq::from_raw([
            0xe5b4b9bdc21c04db,
            0x9e63835abd69879e,
            0x18db6881f2f777ac,
            0x259489aab216c081,
        ]),
        SecFq::from_raw([
            0x27ae69b1afc0bd5a,
            0xbaf24d12dbdbc922,
            0xdb99a1ef9c679aa3,
            0xf4991e6461b363f0,
        ]),
    ],
    [
        SecFq::from_raw([
            0xc8dc95b30a529664,
            0xfb6167ad4debba31,
            0x8feae347e5e739f1,
            0x45f35912978af5ee,
        ]),
        SecFq::from_raw([
            0xe7d84c488600abe0,
            0x9fe1977b37d30f78,
            0x499da665701ac0ce,
            0xee6e2a660ac7538c,
        ]),
        SecFq::from_raw([
            0xd04484e04551223f,
            0xdb75c605065a20e4,
            0xbb3c3bf8352a4749,
            0x663b14b9a4ad467c,
        ]),
    ],
    [
        SecFq::from_raw([
            0x4135d12f27fe8250,
            0x0994dfcdb6651d0d,
            0x4aee748d99afeb3c,
            0x755211bb4f52e9eb,
        ]),
        SecFq::from_raw([
            0xb7c611bb9a4c0455,
            0xecb5800114911d7b,
            0xa58847f2a90a38a3,
            0x256f1aeea44f6d1f,
        ]),
        SecFq::from_raw([
            0x87b7afadedcdc521,
            0xb491be1162f18080,
            0xbce88c1b3505c3dd,
            0xaf383cb07bedecb9,
        ]),
    ],
    [
        SecFq::from_raw([
            0x7a650712d7114801,
            0x19d8c8ca3382861f,
            0x35639161e83a876c,
            0x5d7329a0fe0ca1f3,
        ]),
        SecFq::from_raw([
            0x409240811df26857,
            0x767792139d03058d,
            0xcae57e5a3a286685,
            0x158e18cebfccecab,
        ]),
        SecFq::from_raw([
            0xff34d1e6f96fe170,
            0xb623147d0f8031ff,
            0x2428de2734095eac,
            0x7f5c2dc6718e3073,
        ]),
    ],
    [
        SecFq::from_raw([
            0x424d2907889e2c6b,
            0x6d41a27855aec39b,
            0x1ad7e65eb2e98122,
            0x7bfd6dcc77a88b97,
        ]),
        SecFq::from_raw([
            0x90b8ace2757529a0,
            0xecc365603e4803b9,
            0x58308a4c3758e60d,
            0x27b370e06752ce47,
        ]),
        SecFq::from_raw([
            0xa337f5bf7e9fa954,
            0xbed58a4b851df9b9,
            0xcfecb0935ea3efea,
            0xd09bbbbcc7dbbade,
        ]),
    ],
    [
        SecFq::from_raw([
            0xecd5f7da529444c2,
            0xb922cf3fdb25f748,
            0x79120d73badfcfba,
            0x7426adf4d3977ea6,
        ]),
        SecFq::from_raw([
            0x9a77b489038f1f71,
            0xac392033e588377c,
            0x6986b2be66d04083,
            0xee51c38955f32050,
        ]),
        SecFq::from_raw([
            0x46966c2c2377a488,
            0x9ecc11f4da35f3d7,
            0x840f918057190301,
            0xcd9349a4436133f5,
        ]),
    ],
    [
        SecFq::from_raw([
            0xfdf98ce193ede7fa,
            0x31b1f4394f4f93d5,
            0x538ed9a93ed65065,
            0x83e2262631db9974,
        ]),
        SecFq::from_raw([
            0x44a04a315525be94,
            0x0eff145b1ea4fe31,
            0xcf479fc2ab9879de,
            0x6c5c2c97c676e289,
        ]),
        SecFq::from_raw([
            0x11c8c5773e7420fa,
            0x7ef846ea0c0f628a,
            0xa5107679894b11b2,
            0xaeb6e434f4ce8ea0,
        ]),
    ],
    [
        SecFq::from_raw([
            0x540a80dc14a0d0a1,
            0xc2d1aa60b30a86d8,
            0xed8eea4ab1b6dd1a,
            0x0c0572562c2a7606,
        ]),
        SecFq::from_raw([
            0x9716c09c15ae037c,
            0x5c242e7165f58408,
            0x431a4bb77e869279,
            0xde9b285b58d5de28,
        ]),
        SecFq::from_raw([
            0x7794b71d788b5c98,
            0xd66ee757434c7fdc,
            0x09780cacbd492ff2,
            0xdb0a28aa338f0943,
        ]),
    ],
    [
        SecFq::from_raw([
            0x58d08608d9b6e442,
            0x94462aa0d82ba6a0,
            0xc7b86896e77687cd,
            0x952e8e786a9f45b8,
        ]),
        SecFq::from_raw([
            0xa8cb7c8bd559f9f2,
            0x081fe283d84f80db,
            0xab6657c73bc75b9a,
            0xe465c2bfdade7f7f,
        ]),
        SecFq::from_raw([
            0xff0d2b3437dd9496,
            0x6e96fe8fb114a5b1,
            0xe6b06dde21817bdc,
            0xa3cbf907aa46e71f,
        ]),
    ],
    [
        SecFq::from_raw([
            0x7b305b81a12ef110,
            0x71a9d9db37e7ae42,
            0x33b3f96420014bc4,
            0x5a7a30e251c53d5e,
        ]),
        SecFq::from_raw([
            0x3fededa64f9f40be,
            0x68f90b34ea9a2c68,
            0xfe93e07e19bca6de,
            0x481012e0b4210bc9,
        ]),
        SecFq::from_raw([
            0xdd446fa9893d302b,
            0x8c52edd77ea1103b,
            0x9da9e9a6b15e0de4,
            0xdadabad5b8e62e0c,
        ]),
    ],
    [
        SecFq::from_raw([
            0x85a19fe8445bbdce,
            0x92ab463ec72f216a,
            0x6004394306237cbe,
            0x7b69fffabd274da4,
        ]),
        SecFq::from_raw([
            0x4431280d2f884e4a,
            0xaddf05a6e7c7a5c2,
            0xbc83cf82f666beb9,
            0x08d904df23b3a49a,
        ]),
        SecFq::from_raw([
            0x3cd54e56acca6231,
            0x2c5fac8fe058ba70,
            0xc780eee97d1a4594,
            0x42a09538bac6ba33,
        ]),
    ],
    [
        SecFq::from_raw([
            0xe4fad83c2b0e79b0,
            0x7d226ec28ccddeda,
            0x18a030199e6e062a,
            0x4d412751767fff58,
        ]),
        SecFq::from_raw([
            0x9d8b7a3b7fed8678,
            0x1811b30f76261795,
            0x80c5c0632971723d,
            0x3d52c5d9c05129e5,
        ]),
        SecFq::from_raw([
            0xa79a054403220f4e,
            0x472be0806b796b93,
            0x308b97add329b9ae,
            0xd4e390fb6fee7ebe,
        ]),
    ],
    [
        SecFq::from_raw([
            0xdda3c47dea256cb2,
            0x098474831bd8f8b8,
            0x67c397633fba5944,
            0xd6c7716b6f858a64,
        ]),
        SecFq::from_raw([
            0x4ea9173bd803481c,
            0x359d953ca4c14793,
            0x01d0206316ce4bd7,
            0x36ba8fc22e880175,
        ]),
        SecFq::from_raw([
            0x07b4818440bb9242,
            0x83b0f079246b31c1,
            0xc4e1fcd03baff048,
            0xa8455ba40430f98e,
        ]),
    ],
    [
        SecFq::from_raw([
            0xb3d013b109e76806,
            0x4915ddd709e3450c,
            0x9477529055cbb1a4,
            0x4aa5cc42f8c1bb19,
        ]),
        SecFq::from_raw([
            0x685f27ce7134baa9,
            0x77ac907b74406310,
            0x6b9d05f186cf3754,
            0xde45eb902f1d3742,
        ]),
        SecFq::from_raw([
            0xa14b3ae22fe97407,
            0xec35b265433fc1da,
            0x28551d7cf83b0e20,
            0x7bca58f4c9d30dd8,
        ]),
    ],
    [
        SecFq::from_raw([
            0xf85885e2d6374a70,
            0x6068baffbb66066c,
            0x7e1bff3f59deec74,
            0x48a6a4e9ec176e22,
        ]),
        SecFq::from_raw([
            0xe53a2730da221642,
            0x75069ce88b39714f,
            0x0092a2cc34519d34,
            0x9aecf0d7165b7e90,
        ]),
        SecFq::from_raw([
            0x414a926a711e3762,
            0x6411b978e955578f,
            0x26dcd5ccb13b7d96,
            0x662c29da05dc3b95,
        ]),
    ],
    [
        SecFq::from_raw([
            0xcfa74ebf2ee77d0d,
            0x15ad23f052e62326,
            0x334ac7a1dd9ff118,
            0xaa3ccf13155dfe91,
        ]),
        SecFq::from_raw([
            0x5e4a2709de6cf8f2,
            0x85abd6990be0a99c,
            0x71255491bbc83422,
            0x3004e2d1fbeeffd2,
        ]),
        SecFq::from_raw([
            0xf0bc8d1030f775bd,
            0x806ededb6144a131,
            0x597aebdfbd3d21c6,
            0x40940f8c1cd58ae6,
        ]),
    ],
    [
        SecFq::from_raw([
            0xf47b078e3b6e6fc4,
            0x442780e053c27b38,
            0x36deb76535d7091c,
            0x05683dbea800c340,
        ]),
        SecFq::from_raw([
            0x22f793b7bf652008,
            0x98d96ecc63ca139f,
            0x362dc3c3c4451e4f,
            0xc0018dd1e4c4188c,
        ]),
        SecFq::from_raw([
            0x6348685206a487b7,
            0xcb8e0b62a0cfb58a,
            0x5a77b04f8bdaa9a3,
            0x5f1fa64cfd22bea7,
        ]),
    ],
    [
        SecFq::from_raw([
            0x01c0d72e5f0f6194,
            0x3cb39b2e286d6f4a,
            0xd87df6a9d2b8dc99,
            0xf0e3da061d35a4cd,
        ]),
        SecFq::from_raw([
            0x39bfba8b851e7d87,
            0x9e9b14e338c06855,
            0x32ab6b63d865530a,
            0xb978ee99c25ff418,
        ]),
        SecFq::from_raw([
            0x995b7fbac35ad5ef,
            0xdef9b25871bbd318,
            0xb76bd44ec783ed82,
            0x5e056fc78c2aebde,
        ]),
    ],
    [
        SecFq::from_raw([
            0xa66282488a51b916,
            0xc6208099e836fef0,
            0x06f4c411887c49c0,
            0xfea5ae0b8ae64758,
        ]),
        SecFq::from_raw([
            0x7dfa8d0013afd584,
            0x7466be6817ae67fb,
            0xdb34984d5e4cf8bb,
            0x4011df0dcf4ef82d,
        ]),
        SecFq::from_raw([
            0xeb24722f1b8a5f22,
            0x1f396dc0c56c9604,
            0x6a52f93cd305707a,
            0x971d78d355eac2a5,
        ]),
    ],
    [
        SecFq::from_raw([
            0x9bc9ec0812730e29,
            0xc899b8be8ac065ee,
            0x8b45d207ea21a0fe,
            0x888ab55ab647d135,
        ]),
        SecFq::from_raw([
            0xfbc446c9cfd0686d,
            0x9c1e30cde524933b,
            0x5965882063d03e2e,
            0xb272dbea28c3cd8d,
        ]),
        SecFq::from_raw([
            0x9465acb3e1d3871b,
            0x4398724036802ec7,
            0xd4b55777860810fb,
            0x4910d1d2c2872a5c,
        ]),
    ],
    [
        SecFq::from_raw([
            0x5170e9a8d870a2a4,
            0x2505c5787dc27186,
            0x787177f7eb2126cd,
            0x700d1f3b78d6a013,
        ]),
        SecFq::from_raw([
            0x7f2ce3dc0c837c6d,
            0x307d64819009a045,
            0x60fb581719536705,
            0x09716bd482c01f1e,
        ]),
        SecFq::from_raw([
            0x353be238841a20f6,
            0x229ef2bb83b9ccbb,
            0xd711b354fa2404bc,
            0xdffdb7e489adf91d,
        ]),
    ],
    [
        SecFq::from_raw([
            0x91f81d22a549ed5d,
            0x65e67cb3322a4c08,
            0xa9459e12a4ab36f0,
            0x7ad8f5663f7305de,
        ]),
        SecFq::from_raw([
            0xeacda6e99d6f0be1,
            0xd243b5ae2e3e7391,
            0x28b860af4c057beb,
            0x90efd0590e408127,
        ]),
        SecFq::from_raw([
            0xf0afcfccd85c4905,
            0xd831c2b3f010b65d,
            0x272a8afa65cf64eb,
            0x93db57bc26e0644d,
        ]),
    ],
    [
        SecFq::from_raw([
            0x2477883051e01c83,
            0x87ea5eb3f4361dc6,
            0xb39892ad2a3291ea,
            0x4374ab7ac7a70caf,
        ]),
        SecFq::from_raw([
            0xdec825db6ae2a22f,
            0x74f000c555f2f433,
            0x1748dc0fd32a5668,
            0xd40595e3ca026021,
        ]),
        SecFq::from_raw([
            0xcb49801730977315,
            0x14e01bf036d72da6,
            0x1d3200b73365af36,
            0x53bf4a2ba34ec788,
        ]),
    ],
    [
        SecFq::from_raw([
            0x7744e24ca6acc401,
            0x8df8fe077d4de32b,
            0x46c5ab20b4a3a035,
            0xb1edc902961b17f5,
        ]),
        SecFq::from_raw([
            0x4717cf66067337b1,
            0xbe9178726c0e3f1a,
            0x2d78857ecec18053,
            0x1d7665b172ef246a,
        ]),
        SecFq::from_raw([
            0xb6ec49e6b0afd008,
            0x183d12cff7e7ae47,
            0xdac092e4cc344409,
            0x237a5717c098fbf1,
        ]),
    ],
    [
        SecFq::from_raw([
            0x643fda6ee7e50071,
            0x22b768a423e41a50,
            0x86e6b60d7fd8e607,
            0x9e1333925b735445,
        ]),
        SecFq::from_raw([
            0x423edbde2f1783ce,
            0x10241ec5550166b7,
            0x31dcf4a26b975801,
            0x3edfe4ac56205a97,
        ]),
        SecFq::from_raw([
            0x3a1736f3e2d02f1b,
            0x569109a0d96aabc9,
            0x766f3e12d9a67d84,
            0x7bf46946a106bffc,
        ]),
    ],
];

// n: 255
// t: 3
// N: 765
// Result Algorithm 1:
//  [True, 0]
// Result Algorithm 2:
//  [True, None]
// Result Algorithm 3:
//  [True, None]
// Prime number: 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
// MDS matrix:
pub(crate) const MDS: [[SecFq; 3]; 3] = [
    [
        SecFq::from_raw([
            0x81ca564c4b0ac842,
            0x5267e3b4075a0592,
            0xb4e15042a517954c,
            0x34a03a7c72d52949,
        ]),
        SecFq::from_raw([
            0x46d7dd1f096839f6,
            0x9e119b5acaf18d84,
            0x26bf6676fe7df905,
            0xdc329ec1a85792cf,
        ]),
        SecFq::from_raw([
            0x6cc7a74b9dc49a5c,
            0x00e16cfad75ea4a7,
            0xb48c93428a026e79,
            0xfe96b3af80b7211a,
        ]),
    ],
    [
        SecFq::from_raw([
            0x186a7a5170d34032,
            0x940cfc1fddd26db6,
            0x9198f86d28c41e88,
            0xfa076548ca525da9,
        ]),
        SecFq::from_raw([
            0xd85cf3966f7beb04,
            0xa855970fe7927d8e,
            0xef7aa9504f332925,
            0x74d1ee6ee67edb67,
        ]),
        SecFq::from_raw([
            0xb50323138643d9f1,
            0xfe4efd3080aeab40,
            0xf9885c330a5bb2a9,
            0x461d80cb37f0fbd2,
        ]),
    ],
    [
        SecFq::from_raw([
            0xa79abf5274fe921c,
            0x115a5cadd29d1890,
            0xe3d56906f3d7d156,
            0x9c1017421111cced,
        ]),
        SecFq::from_raw([
            0x4369a3f35a9d2a31,
            0xafb842f54eb9c299,
            0x25f9fe9f5eb0a786,
            0xc55b757108e31adf,
        ]),
        SecFq::from_raw([
            0x41ff772d35188703,
            0xa4ad66cf3231ea4f,
            0x52d9b8930de0b4ad,
            0x1d01af1b0c2249db,
        ]),
    ],
];

pub(crate) const MDS_INV: [[SecFq; 3]; 3] = [
    [
        SecFq::from_raw([
            0xbbdba34a59097baa,
            0x7c7aff2488eafec2,
            0x34f63df8c5dfa69f,
            0x8b2a40686080564b,
        ]),
        SecFq::from_raw([
            0xdf0a4d8413b23d7d,
            0x767827b0a1938fb1,
            0x52c13cc8a835cd1e,
            0xfa70c661ed6ab810,
        ]),
        SecFq::from_raw([
            0xa59d2945b0968836,
            0x94d7bd4a582ba611,
            0xcfc5dc217b127caa,
            0x28458acc754fd469,
        ]),
    ],
    [
        SecFq::from_raw([
            0x0320bc7b88083b41,
            0xa13146cf86788d08,
            0xe450ec70bee13a2e,
            0x7c2030d3aecc97f3,
        ]),
        SecFq::from_raw([
            0x988e5de2417ce628,
            0x4ba406f55defd364,
            0xe79550db2b5d9852,
            0x7456729453ea24b0,
        ]),
        SecFq::from_raw([
            0x90f8d7276f73a910,
            0x3ad58eaf0ff82bea,
            0x660dc381686f2362,
            0x19e8145d441908a4,
        ]),
    ],
    [
        SecFq::from_raw([
            0x5f6d743245cc957d,
            0xe45bfeed52d53796,
            0x39d54b3dab5ff3b0,
            0x66c03e28b3a5e73f,
        ]),
        SecFq::from_raw([
            0x7f9f0476aa45e39a,
            0x29a828393775a419,
            0x371e557316cab25f,
            0xe95675bcfe9a749b,
        ]),
        SecFq::from_raw([
            0x8e94fdaff17e24b1,
            0x07deec50b2181086,
            0xb40b3e96b9839a3f,
            0xb7ca61d9cd8db6ba,
        ]),
    ],
];
