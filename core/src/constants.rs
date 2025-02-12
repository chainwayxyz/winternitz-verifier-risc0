use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use std::str::FromStr;

pub fn create_verifying_key() -> VerifyingKey<Bn254> {
    let alpha_g1 = G1Affine::new(
        Fq::from_str(
            "20491192805390485299153009773594534940189261866228447918068658471970481763042",
        )
        .unwrap(),
        Fq::from_str(
            "9383485363053290200918347156157836566562967994039712273449902621266178545958",
        )
        .unwrap(),
    );

    let beta_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "6375614351688725206403948262868962793625744043794305715222011528459656738731",
            )
            .unwrap(),
            Fq::from_str(
                "4252822878758300859123897981450591353533073413197771768651442665752259397132",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "10505242626370262277552901082094356697409835680220590971873171140371331206856",
            )
            .unwrap(),
            Fq::from_str(
                "21847035105528745403288232691147584728191162732299865338377159692350059136679",
            )
            .unwrap(),
        ),
    );

    let gamma_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .unwrap(),
            Fq::from_str(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            )
            .unwrap(),
            Fq::from_str(
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
        ),
    );

    let delta_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "12043754404802191763554326994664886008979042643626290185762540825416902247219",
            )
            .unwrap(),
            Fq::from_str(
                "1668323501672964604911431804142266013250380587483576094566949227275849579036",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "13740680757317479711909903993315946540841369848973133181051452051592786724563",
            )
            .unwrap(),
            Fq::from_str(
                "7710631539206257456743780535472368339139328733484942210876916214502466455394",
            )
            .unwrap(),
        ),
    );

    let gamma_abc_g1 = vec![
        G1Affine::new(
            Fq::from_str(
                "8446592859352799428420270221449902464741693648963397251242447530457567083492",
            )
            .unwrap(),
            Fq::from_str(
                "1064796367193003797175961162477173481551615790032213185848276823815288302804",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "3179835575189816632597428042194253779818690147323192973511715175294048485951",
            )
            .unwrap(),
            Fq::from_str(
                "20895841676865356752879376687052266198216014795822152491318012491767775979074",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "5332723250224941161709478398807683311971555792614491788690328996478511465287",
            )
            .unwrap(),
            Fq::from_str(
                "21199491073419440416471372042641226693637837098357067793586556692319371762571",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "12457994489566736295787256452575216703923664299075106359829199968023158780583",
            )
            .unwrap(),
            Fq::from_str(
                "19706766271952591897761291684837117091856807401404423804318744964752784280790",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "19617808913178163826953378459323299110911217259216006187355745713323154132237",
            )
            .unwrap(),
            Fq::from_str(
                "21663537384585072695701846972542344484111393047775983928357046779215877070466",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "6834578911681792552110317589222010969491336870276623105249474534788043166867",
            )
            .unwrap(),
            Fq::from_str(
                "15060583660288623605191393599883223885678013570733629274538391874953353488393",
            )
            .unwrap(),
        ),
    ];

    VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    }
}

// COMPRESSION - DECOMPRESSION RELATED CONSTANTS
pub static MODULUS: &[u8; 77] =
    b"21888242871839275222246405745257275088696311157297823662689037894645226208583";
pub static EXP_SQRT: &[u8; 76] =
    b"5472060717959818805561601436314318772174077789324455915672259473661306552146";
pub static CONST_1_2: &[u8; 77] =
    b"10944121435919637611123202872628637544348155578648911831344518947322613104292";
pub static CONST_27_82: &[u8; 77] =
    b"19485874751759354771024239261021720505790618469301721065564631296452457478373";
pub static CONST_3_82: &[u8; 77] =
    b"21621313080719284060999498358119991246151234191964923374119659383734918571893";

// GROTH16 RELATED CONSTANTS
pub static PRE_STATE: [u8; 32] =
    hex_literal::hex!("7c213e03c7ff5c4c000904c38317fa2482c09c1dc66d2e9eb6b257e9546c5f17");
pub static POST_STATE: [u8; 32] =
    hex_literal::hex!("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2");
pub static INPUT: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub static ASSUMPTIONS: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub static BN254_CONTROL_ID: [u8; 32] =
    hex_literal::hex!("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");
pub static CLAIM_TAG: [u8; 32] =
    hex_literal::hex!("cb1fefcd1f2d9a64975cbbbf6e161e2914434b0cbb9960b84df5d717e86b48af"); // hash of "risc0.ReceiptClaim"
pub static OUTPUT_TAG: [u8; 32] =
    hex_literal::hex!("77eafeb366a78b47747de0d7bb176284085ff5564887009a5be63da32d3559d4"); // hash of "risc0.Output"
