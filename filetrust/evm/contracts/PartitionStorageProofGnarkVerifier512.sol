
// SPDX-License-Identifier: MIT
// Generated from App/VK512/core/zk/gnark-storage-proof/keys/profiles/partition_512b_d26_n16_m4/partition/PartitionStorageProofGnarkVerifier.sol by scripts/generate_split_partition_verifier.py

pragma solidity ^0.8.0;

import "./BN254MathLib.sol";
import "./PublicInputMSMLib512.sol";

/// @title Groth16 verifier template.
/// @author Remco Bloemen
/// @notice Supports verifying Groth16 proofs. Proofs can be in uncompressed
/// (256 bytes) and compressed (128 bytes) format. A view function is provided
/// to compress proofs.
/// @notice See <https://2π.com/23/bn254-compression> for further explanation.
contract Verifier {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();

    // Precompile addresses used by publicInputMSM and verifyProof.
    // P, FRACTION_*, EXP_* and PRECOMPILE_MODEXP live in BN254MathLib.
    uint256 constant PRECOMPILE_ADD    = 0x06;
    uint256 constant PRECOMPILE_MUL    = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Scalar field Fr order R — used in publicInputMSM range checks.
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X = 8819663586943848660716193572133907084021950648733212985228873718380684155634;
    uint256 constant ALPHA_Y = 1400396802792407635094602373870619899968889206998240761525514738548420502853;

    // Groth16 beta point in G2 in powers of i
    uint256 constant BETA_NEG_X_0 = 15074458398764945616209277322505859222111494790290966443057572898448956716335;
    uint256 constant BETA_NEG_X_1 = 12010503405275303461632237218338560555033072306755845241623532844191454252550;
    uint256 constant BETA_NEG_Y_0 = 3245918779792294941006981970592356978756405801427646489690035092334709645278;
    uint256 constant BETA_NEG_Y_1 = 16860960568815516374647584797166213575022988371752453337730451831720691449261;

    // Groth16 gamma point in G2 in powers of i
    uint256 constant GAMMA_NEG_X_0 = 188366996075006208419824098192097434468889600317641453999753532905370605561;
    uint256 constant GAMMA_NEG_X_1 = 21363541426362847639734761073285655610261971822024162295800993248698118392000;
    uint256 constant GAMMA_NEG_Y_0 = 418962507822157386994935972634262672753744965474674410829141426825134586404;
    uint256 constant GAMMA_NEG_Y_1 = 11815506685777537735631366136246931981879119461243927867050708481101955987602;

    // Groth16 delta point in G2 in powers of i
    uint256 constant DELTA_NEG_X_0 = 8802663199490245531280955771731157866963641178392164093652183051383380645209;
    uint256 constant DELTA_NEG_X_1 = 7185509892922504305348075297953380582479999575214369790066386268883981371073;
    uint256 constant DELTA_NEG_Y_0 = 4850819949010570529850244141169092753162008905018472829779377090700111151863;
    uint256 constant DELTA_NEG_Y_1 = 11355584872807891514350199817917404488665480041098377173212678818799046753463;

    // Constant and public input points
    uint256 constant CONSTANT_X = 18802615900982672280937944533958721923743021039790026264249538635805841320883;
    uint256 constant CONSTANT_Y = 3041906347705197005467912535975573418368473238083191251390840599020307674068;
    uint256 constant PUB_0_X = 0;
    uint256 constant PUB_0_Y = 0;
    uint256 constant PUB_1_X = 0;
    uint256 constant PUB_1_Y = 0;
    uint256 constant PUB_2_X = 0;
    uint256 constant PUB_2_Y = 0;
    uint256 constant PUB_3_X = 6764967722994605503697846056170018264419920474305767334116612302868553462607;
    uint256 constant PUB_3_Y = 18991305931054227209271466164445402458591442748077787583500883032331192771157;
    uint256 constant PUB_4_X = 10758316981928847244111092564542644648440430888556653490666703583984375460884;
    uint256 constant PUB_4_Y = 18836429422807134562848099101247350965108637714210601900123505637041630101933;
    uint256 constant PUB_5_X = 13756394622799272755313170648479293478605930349246442397418988076798088420456;
    uint256 constant PUB_5_Y = 19832224609519346222129178166242728971321535323409608286858380253698571988970;
    uint256 constant PUB_6_X = 8369875377695366474232790605063908773037556123266491528060091743873757225065;
    uint256 constant PUB_6_Y = 17108832036520801765655809284708640458753529137642533816615287312330938839919;
    uint256 constant PUB_7_X = 18287207721240686792368013916992908205490362742321866465042956898850329881075;
    uint256 constant PUB_7_Y = 9874720058370996741032788537757607916552851785495413438587150316308009711312;
    uint256 constant PUB_8_X = 11495148924383644280620025564800845936051265068007633117397434601820046623244;
    uint256 constant PUB_8_Y = 420921719783465698985136024949503492317088240633608661908508716958899692573;
    uint256 constant PUB_9_X = 8582697621522176397231396803121131687223229636516488187986854950868202095498;
    uint256 constant PUB_9_Y = 18580778685510713036246011830536208195000786881235437867178219702094074982839;
    uint256 constant PUB_10_X = 12420422251208610931945623716483122646065265897039216321006471937313283034450;
    uint256 constant PUB_10_Y = 20647521027344995271540359067900607821271672853718707485852869213115491286238;
    uint256 constant PUB_11_X = 9152775822878973868468635743340857929514965643513769175456850020265257355340;
    uint256 constant PUB_11_Y = 2019728894866180513914686200467545321666708998292800382934478465134936053175;
    uint256 constant PUB_12_X = 18796660489915027832227143618352672425355070353967197093336463729601225636750;
    uint256 constant PUB_12_Y = 6269009508166674392619567496622012099338718958107383174311856431780679729443;
    uint256 constant PUB_13_X = 18774496440205808303193047013683311683486306726898193107118209525452980874020;
    uint256 constant PUB_13_Y = 5481798871713912702938373677661212369483213454017094725885124426418739670805;
    uint256 constant PUB_14_X = 10769716910733027109830241668607126218228358826906591487412021283727210127214;
    uint256 constant PUB_14_Y = 12503669583197896336023920912448341672667473855741499603710929478511735734890;
    uint256 constant PUB_15_X = 11251890768556704938594910777158110911057764695169147193979637008361229197656;
    uint256 constant PUB_15_Y = 9792622709943904319691745614472155223616176125992580691437363216614450866803;
    uint256 constant PUB_16_X = 13787357517266311446819144771164916247059810865120039354843693334674780996903;
    uint256 constant PUB_16_Y = 488202395813852781038535622165376695453817377016060236974821503681255845577;
    uint256 constant PUB_17_X = 10743767803244807772565963742822394530911678942919660098244418350340443124553;
    uint256 constant PUB_17_Y = 13878417913276791140361754556760507574287168530105406304082986671529954810007;
    uint256 constant PUB_18_X = 14073526383880147826403997665607877284965320160652235533303549836753733280575;
    uint256 constant PUB_18_Y = 14315626635238019042650750366421075681899584952833173492991333871324808552663;
    uint256 constant PUB_19_X = 15306662254417028663236632425100386050048954916309556080178167522311544119595;
    uint256 constant PUB_19_Y = 20131019753224692998270687660357770749146231994069199061826168023064883651218;
    uint256 constant PUB_20_X = 2160900080010418108043556268821761406165212036743813569192472379648598493152;
    uint256 constant PUB_20_Y = 10439816973899267929334164765609566985594587519950820162931805002902956167303;
    uint256 constant PUB_21_X = 463589815712178151679660541068325788985925113268138000808929084741606134741;
    uint256 constant PUB_21_Y = 15773729904790081416275526077401801193542508296525163850401988986455607136267;
    uint256 constant PUB_22_X = 9356981159175442491900627886274029499966609459762808172460548434301685815260;
    uint256 constant PUB_22_Y = 15917529050490584702602343709643786795869151494758654240334232950134390113744;
    uint256 constant PUB_23_X = 7149048104028600454235913569029327100014896129300400948143958253776897335581;
    uint256 constant PUB_23_Y = 15672424867459649665566941344297926079497080218168264763409519503369200320225;
    uint256 constant PUB_24_X = 1290514537841740277004586862485270069775733977100680108834894250769685104221;
    uint256 constant PUB_24_Y = 6263360717288333430356730637974031958921562469556303585004497079973910557348;
    uint256 constant PUB_25_X = 1249377103388851656084697365981394405422241802388729297829536111187972212209;
    uint256 constant PUB_25_Y = 1002938882284099296080840442630768186992182867398499880517114111121712533218;
    uint256 constant PUB_26_X = 20803611953567436375777750130001891293019619695018462005870102449664988718439;
    uint256 constant PUB_26_Y = 2411549261353087599790633867349127396371657527690294802520053925306000725154;
    uint256 constant PUB_27_X = 19667404035544300263271379988707155244208584766455327789140919085389721082062;
    uint256 constant PUB_27_Y = 872484535064230280379678147036316213676814738416595281258685200405829115712;
    uint256 constant PUB_28_X = 17600487713755030119652062581782267622057811530215220622796004644514189806589;
    uint256 constant PUB_28_Y = 4959281576243693002705780339738174057610097731080583410153182557227310008007;
    uint256 constant PUB_29_X = 3085481253440693940289886109443901073126799995137356304528097148025475236825;
    uint256 constant PUB_29_Y = 10038047861999526251764728240531283147548977565627875444470868285139409046361;
    uint256 constant PUB_30_X = 18438469822813336156555651627414541626938083904677036039484230341898928886311;
    uint256 constant PUB_30_Y = 18145861311944993068349263829746065725139392203368699831604667540321142272761;
    uint256 constant PUB_31_X = 12224392682172999777840462549274178136189566506999198995069967716904598228893;
    uint256 constant PUB_31_Y = 1064303367753412564117463265415039519125878566870595877289864223239450958453;
    uint256 constant PUB_32_X = 21784015206015788445909592469899168404959240986187329378837467972056911147346;
    uint256 constant PUB_32_Y = 8453972698710502851670590948511101786356721751787379059349715644042065835862;
    uint256 constant PUB_33_X = 17733687419805924422968675812906850540060153969315717682840231609666307384399;
    uint256 constant PUB_33_Y = 10311645521543047847483061117874568152235189769452147904067026438123973070688;
    uint256 constant PUB_34_X = 18696071041730789702625477799588105264566567540072068264840410211574303587464;
    uint256 constant PUB_34_Y = 20353439811905241537288407154868399251034248583033591216649196973140526254421;
    uint256 constant PUB_35_X = 0;
    uint256 constant PUB_35_Y = 0;
    uint256 constant PUB_36_X = 0;
    uint256 constant PUB_36_Y = 0;
    uint256 constant PUB_37_X = 0;
    uint256 constant PUB_37_Y = 0;
    uint256 constant PUB_38_X = 0;
    uint256 constant PUB_38_Y = 0;
    uint256 constant PUB_39_X = 0;
    uint256 constant PUB_39_Y = 0;
    uint256 constant PUB_40_X = 0;
    uint256 constant PUB_40_Y = 0;
    uint256 constant PUB_41_X = 0;
    uint256 constant PUB_41_Y = 0;
    uint256 constant PUB_42_X = 0;
    uint256 constant PUB_42_Y = 0;
    uint256 constant PUB_43_X = 0;
    uint256 constant PUB_43_Y = 0;
    uint256 constant PUB_44_X = 0;
    uint256 constant PUB_44_Y = 0;
    uint256 constant PUB_45_X = 0;
    uint256 constant PUB_45_Y = 0;
    uint256 constant PUB_46_X = 0;
    uint256 constant PUB_46_Y = 0;
    uint256 constant PUB_47_X = 0;
    uint256 constant PUB_47_Y = 0;
    uint256 constant PUB_48_X = 0;
    uint256 constant PUB_48_Y = 0;
    uint256 constant PUB_49_X = 0;
    uint256 constant PUB_49_Y = 0;
    uint256 constant PUB_50_X = 0;
    uint256 constant PUB_50_Y = 0;
    uint256 constant PUB_51_X = 15014083390376028992489679798597262509498341244462144829364907141989998350693;
    uint256 constant PUB_51_Y = 21264593813442807167590288605650454574280120991377366119101433326230493822393;
    uint256 constant PUB_52_X = 7006626535579230676346666858554563794904548509464684587252798575147771699586;
    uint256 constant PUB_52_Y = 2955371130664198060092008960567798477618991558069478698359998496218497507258;
    uint256 constant PUB_53_X = 3092099853042171853219739302779907052479372733937866393053730429849496843843;
    uint256 constant PUB_53_Y = 11475980152642154678637246501511903568103249929005109118220583727810336433457;
    uint256 constant PUB_54_X = 19962315020971222979402743351072164816558069222479167295470834247190282701971;
    uint256 constant PUB_54_Y = 10233525353340866978216729273475002516709871600195757226030297931745128318844;
    uint256 constant PUB_55_X = 10971465371823692062504100186520435590584406302925881090398867376910700475487;
    uint256 constant PUB_55_Y = 8946991977448705264386044324244182998939062618608929212030807618486654478644;
    uint256 constant PUB_56_X = 21775541451892313328130064270054540166202580127856279489135438553317706976280;
    uint256 constant PUB_56_Y = 7509033213462706163818790827405070042379569791234022380820345446852847184022;
    uint256 constant PUB_57_X = 12735304319019509168527243348982508819722497122876344578887420095090521596463;
    uint256 constant PUB_57_Y = 13857901749043356747788821050075330778773214225204651163405993612812742095666;
    uint256 constant PUB_58_X = 9466453048526178691570572762961759074006049586183509036483142323029893373305;
    uint256 constant PUB_58_Y = 17933432730943986683229122782234413998941493249782838794502334393446519620854;
    uint256 constant PUB_59_X = 2864599735866133525151808988095061826993168462541194163760730156867329407096;
    uint256 constant PUB_59_Y = 13741165901768342148991054826972362532181958144651315365670445060603787051825;
    uint256 constant PUB_60_X = 15573485276128898013691012617485648763226888059753934850119091061147596577438;
    uint256 constant PUB_60_Y = 14842162955007803618110455445299126191182237690759872902672659683918859530460;
    uint256 constant PUB_61_X = 19315894756535005400384791295021543574020139129410094852416884343117931851997;
    uint256 constant PUB_61_Y = 10022492036817836141580630400977574231855208759821229363061113909842039081282;
    uint256 constant PUB_62_X = 5255568011239212986251439585058785838860579522699235805638059081263811787781;
    uint256 constant PUB_62_Y = 18934246103846608458165595525445448097255724609855863206505256607216727490861;
    uint256 constant PUB_63_X = 11408576998556857810513268510894005586402441730575127359794598164840499296077;
    uint256 constant PUB_63_Y = 2750653111802161360120342555619950601888469176220095612319868782229971951894;
    uint256 constant PUB_64_X = 58982443106019412891320094415004230812934417381107166714428892168819732993;
    uint256 constant PUB_64_Y = 17342966035463578249826414842539611678052202365451039887406813833314579095094;
    uint256 constant PUB_65_X = 12499559610738962811509032171783226375951946230425946707684317117663208973447;
    uint256 constant PUB_65_Y = 17844505931505626414423307918431844573258071407460662901395652647798487506354;

    /// Compute the public input linear combination.
    /// @notice Reverts with PublicInputNotInField if the input is not in the field.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @return x The X coordinate of the resulting G1 point.
    /// @return y The Y coordinate of the resulting G1 point.
    function publicInputMSM(uint256[132] calldata input)
    internal view returns (uint256 x, uint256 y) {
        // Note: The ECMUL precompile does not reject unreduced values, so we check this.
        // Note: Unrolling this loop does not cost much extra in code-size, the bulk of the
        //       code-size is in the PUB_ constants.
        // ECMUL has input (x, y, scalar) and output (x', y').
        // ECADD has input (x1, y1, x2, y2) and output (x', y').
        // We reduce commitments(if any) with constants as the first point argument to ECADD.
        // We call them such that ecmul output is already in the second point
        // argument to ECADD so we can have a tight loop.
        bool success = true;
        uint256 lx;
        uint256 ly;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let g := add(f, 0x40)
            let s
            mstore(f, CONSTANT_X)
            mstore(add(f, 0x20), CONSTANT_Y)
            mstore(g, PUB_0_X)
            mstore(add(g, 0x20), PUB_0_Y)
            s :=  calldataload(input)
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_1_X)
            mstore(add(g, 0x20), PUB_1_Y)
            s :=  calldataload(add(input, 32))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_2_X)
            mstore(add(g, 0x20), PUB_2_Y)
            s :=  calldataload(add(input, 64))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_3_X)
            mstore(add(g, 0x20), PUB_3_Y)
            s :=  calldataload(add(input, 96))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_4_X)
            mstore(add(g, 0x20), PUB_4_Y)
            s :=  calldataload(add(input, 128))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_5_X)
            mstore(add(g, 0x20), PUB_5_Y)
            s :=  calldataload(add(input, 160))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_6_X)
            mstore(add(g, 0x20), PUB_6_Y)
            s :=  calldataload(add(input, 192))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_7_X)
            mstore(add(g, 0x20), PUB_7_Y)
            s :=  calldataload(add(input, 224))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_8_X)
            mstore(add(g, 0x20), PUB_8_Y)
            s :=  calldataload(add(input, 256))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_9_X)
            mstore(add(g, 0x20), PUB_9_Y)
            s :=  calldataload(add(input, 288))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_10_X)
            mstore(add(g, 0x20), PUB_10_Y)
            s :=  calldataload(add(input, 320))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_11_X)
            mstore(add(g, 0x20), PUB_11_Y)
            s :=  calldataload(add(input, 352))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_12_X)
            mstore(add(g, 0x20), PUB_12_Y)
            s :=  calldataload(add(input, 384))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_13_X)
            mstore(add(g, 0x20), PUB_13_Y)
            s :=  calldataload(add(input, 416))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_14_X)
            mstore(add(g, 0x20), PUB_14_Y)
            s :=  calldataload(add(input, 448))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_15_X)
            mstore(add(g, 0x20), PUB_15_Y)
            s :=  calldataload(add(input, 480))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_16_X)
            mstore(add(g, 0x20), PUB_16_Y)
            s :=  calldataload(add(input, 512))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_17_X)
            mstore(add(g, 0x20), PUB_17_Y)
            s :=  calldataload(add(input, 544))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_18_X)
            mstore(add(g, 0x20), PUB_18_Y)
            s :=  calldataload(add(input, 576))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_19_X)
            mstore(add(g, 0x20), PUB_19_Y)
            s :=  calldataload(add(input, 608))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_20_X)
            mstore(add(g, 0x20), PUB_20_Y)
            s :=  calldataload(add(input, 640))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_21_X)
            mstore(add(g, 0x20), PUB_21_Y)
            s :=  calldataload(add(input, 672))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_22_X)
            mstore(add(g, 0x20), PUB_22_Y)
            s :=  calldataload(add(input, 704))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_23_X)
            mstore(add(g, 0x20), PUB_23_Y)
            s :=  calldataload(add(input, 736))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_24_X)
            mstore(add(g, 0x20), PUB_24_Y)
            s :=  calldataload(add(input, 768))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_25_X)
            mstore(add(g, 0x20), PUB_25_Y)
            s :=  calldataload(add(input, 800))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_26_X)
            mstore(add(g, 0x20), PUB_26_Y)
            s :=  calldataload(add(input, 832))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_27_X)
            mstore(add(g, 0x20), PUB_27_Y)
            s :=  calldataload(add(input, 864))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_28_X)
            mstore(add(g, 0x20), PUB_28_Y)
            s :=  calldataload(add(input, 896))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_29_X)
            mstore(add(g, 0x20), PUB_29_Y)
            s :=  calldataload(add(input, 928))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_30_X)
            mstore(add(g, 0x20), PUB_30_Y)
            s :=  calldataload(add(input, 960))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_31_X)
            mstore(add(g, 0x20), PUB_31_Y)
            s :=  calldataload(add(input, 992))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_32_X)
            mstore(add(g, 0x20), PUB_32_Y)
            s :=  calldataload(add(input, 1024))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_33_X)
            mstore(add(g, 0x20), PUB_33_Y)
            s :=  calldataload(add(input, 1056))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_34_X)
            mstore(add(g, 0x20), PUB_34_Y)
            s :=  calldataload(add(input, 1088))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_35_X)
            mstore(add(g, 0x20), PUB_35_Y)
            s :=  calldataload(add(input, 1120))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_36_X)
            mstore(add(g, 0x20), PUB_36_Y)
            s :=  calldataload(add(input, 1152))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_37_X)
            mstore(add(g, 0x20), PUB_37_Y)
            s :=  calldataload(add(input, 1184))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_38_X)
            mstore(add(g, 0x20), PUB_38_Y)
            s :=  calldataload(add(input, 1216))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_39_X)
            mstore(add(g, 0x20), PUB_39_Y)
            s :=  calldataload(add(input, 1248))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_40_X)
            mstore(add(g, 0x20), PUB_40_Y)
            s :=  calldataload(add(input, 1280))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_41_X)
            mstore(add(g, 0x20), PUB_41_Y)
            s :=  calldataload(add(input, 1312))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_42_X)
            mstore(add(g, 0x20), PUB_42_Y)
            s :=  calldataload(add(input, 1344))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_43_X)
            mstore(add(g, 0x20), PUB_43_Y)
            s :=  calldataload(add(input, 1376))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_44_X)
            mstore(add(g, 0x20), PUB_44_Y)
            s :=  calldataload(add(input, 1408))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_45_X)
            mstore(add(g, 0x20), PUB_45_Y)
            s :=  calldataload(add(input, 1440))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_46_X)
            mstore(add(g, 0x20), PUB_46_Y)
            s :=  calldataload(add(input, 1472))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_47_X)
            mstore(add(g, 0x20), PUB_47_Y)
            s :=  calldataload(add(input, 1504))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_48_X)
            mstore(add(g, 0x20), PUB_48_Y)
            s :=  calldataload(add(input, 1536))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_49_X)
            mstore(add(g, 0x20), PUB_49_Y)
            s :=  calldataload(add(input, 1568))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_50_X)
            mstore(add(g, 0x20), PUB_50_Y)
            s :=  calldataload(add(input, 1600))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_51_X)
            mstore(add(g, 0x20), PUB_51_Y)
            s :=  calldataload(add(input, 1632))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_52_X)
            mstore(add(g, 0x20), PUB_52_Y)
            s :=  calldataload(add(input, 1664))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_53_X)
            mstore(add(g, 0x20), PUB_53_Y)
            s :=  calldataload(add(input, 1696))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_54_X)
            mstore(add(g, 0x20), PUB_54_Y)
            s :=  calldataload(add(input, 1728))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_55_X)
            mstore(add(g, 0x20), PUB_55_Y)
            s :=  calldataload(add(input, 1760))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_56_X)
            mstore(add(g, 0x20), PUB_56_Y)
            s :=  calldataload(add(input, 1792))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_57_X)
            mstore(add(g, 0x20), PUB_57_Y)
            s :=  calldataload(add(input, 1824))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_58_X)
            mstore(add(g, 0x20), PUB_58_Y)
            s :=  calldataload(add(input, 1856))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_59_X)
            mstore(add(g, 0x20), PUB_59_Y)
            s :=  calldataload(add(input, 1888))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_60_X)
            mstore(add(g, 0x20), PUB_60_Y)
            s :=  calldataload(add(input, 1920))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_61_X)
            mstore(add(g, 0x20), PUB_61_Y)
            s :=  calldataload(add(input, 1952))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_62_X)
            mstore(add(g, 0x20), PUB_62_Y)
            s :=  calldataload(add(input, 1984))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_63_X)
            mstore(add(g, 0x20), PUB_63_Y)
            s :=  calldataload(add(input, 2016))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_64_X)
            mstore(add(g, 0x20), PUB_64_Y)
            s :=  calldataload(add(input, 2048))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_65_X)
            mstore(add(g, 0x20), PUB_65_Y)
            s :=  calldataload(add(input, 2080))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            lx := mload(f)
            ly := mload(add(f, 0x20))
        }
        if (!success) {
            revert PublicInputNotInField();
        }
        (uint256 hx, uint256 hy) = PublicInputMSMLib512.publicInputMSM_high(input);
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, lx)
            mstore(add(f, 0x20), ly)
            mstore(add(f, 0x40), hx)
            mstore(add(f, 0x60), hy)
            success := staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            x := mload(f)
            y := mload(add(f, 0x20))
        }
        if (!success) {
            revert ProofInvalid();
        }
    }

    /// Compress a proof.
    /// @notice Will revert with InvalidProof if the curve points are invalid,
    /// but does not verify the proof itself.
    /// @param proof The uncompressed Groth16 proof. Elements are in the same order as for
    /// verifyProof. I.e. Groth16 points (A, B, C) encoded as in EIP-197.
    /// @return compressed The compressed proof. Elements are in the same order as for
    /// verifyCompressedProof. I.e. points (A, B, C) in compressed format.
    function compressProof(uint256[8] calldata proof)
    public view returns (uint256[4] memory compressed) {
        compressed[0] = BN254MathLib.compress_g1(proof[0], proof[1]);
        (compressed[2], compressed[1]) = BN254MathLib.compress_g2(proof[3], proof[2], proof[5], proof[4]);
        compressed[3] = BN254MathLib.compress_g1(proof[6], proof[7]);
    }

    /// Verify a Groth16 proof with compressed points.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param compressedProof the points (A, B, C) in compressed format
    /// matching the output of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[132] calldata input
    ) public view {
        uint256[24] memory pairings;

        {
            (uint256 Ax, uint256 Ay) = BN254MathLib.decompress_g1(compressedProof[0]);
            (uint256 Bx0, uint256 Bx1, uint256 By0, uint256 By1) = BN254MathLib.decompress_g2(compressedProof[2], compressedProof[1]);
            (uint256 Cx, uint256 Cy) = BN254MathLib.decompress_g1(compressedProof[3]);
            (uint256 Lx, uint256 Ly) = publicInputMSM(input);

            // Verify the pairing
            // Note: The precompile expects the F2 coefficients in big-endian order.
            // Note: The pairing precompile rejects unreduced values, so we won't check that here.
            // e(A, B)
            pairings[ 0] = Ax;
            pairings[ 1] = Ay;
            pairings[ 2] = Bx1;
            pairings[ 3] = Bx0;
            pairings[ 4] = By1;
            pairings[ 5] = By0;
            // e(C, -δ)
            pairings[ 6] = Cx;
            pairings[ 7] = Cy;
            pairings[ 8] = DELTA_NEG_X_1;
            pairings[ 9] = DELTA_NEG_X_0;
            pairings[10] = DELTA_NEG_Y_1;
            pairings[11] = DELTA_NEG_Y_0;
            // e(α, -β)
            pairings[12] = ALPHA_X;
            pairings[13] = ALPHA_Y;
            pairings[14] = BETA_NEG_X_1;
            pairings[15] = BETA_NEG_X_0;
            pairings[16] = BETA_NEG_Y_1;
            pairings[17] = BETA_NEG_Y_0;
            // e(L_pub, -γ)
            pairings[18] = Lx;
            pairings[19] = Ly;
            pairings[20] = GAMMA_NEG_X_1;
            pairings[21] = GAMMA_NEG_X_0;
            pairings[22] = GAMMA_NEG_Y_1;
            pairings[23] = GAMMA_NEG_Y_0;

            // Check pairing equation.
            bool success;
            uint256[1] memory output;
            assembly ("memory-safe") {
                success := staticcall(gas(), PRECOMPILE_VERIFY, pairings, 0x300, output, 0x20)
            }
            if (!success || output[0] != 1) {
                // Either proof or verification key invalid.
                // We assume the contract is correctly generated, so the verification key is valid.
                revert ProofInvalid();
            }
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the points (A, B, C) in EIP-197 format matching the output
    /// of compressProof.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        uint256[8] calldata proof,
        uint256[132] calldata input
    ) public view {
        (uint256 x, uint256 y) = publicInputMSM(input);

        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40) // Free memory pointer.

            // Copy points (A, B, C) to memory. They are already in correct encoding.
            // This is pairing e(A, B) and G1 of e(C, -δ).
            calldatacopy(f, proof, 0x100)

            // Complete e(C, -δ) and write e(α, -β), e(L_pub, -γ) to memory.
            // OPT: This could be better done using a single codecopy, but
            //      Solidity (unlike standalone Yul) doesn't provide a way to
            //      to do this.
            mstore(add(f, 0x100), DELTA_NEG_X_1)
            mstore(add(f, 0x120), DELTA_NEG_X_0)
            mstore(add(f, 0x140), DELTA_NEG_Y_1)
            mstore(add(f, 0x160), DELTA_NEG_Y_0)
            mstore(add(f, 0x180), ALPHA_X)
            mstore(add(f, 0x1a0), ALPHA_Y)
            mstore(add(f, 0x1c0), BETA_NEG_X_1)
            mstore(add(f, 0x1e0), BETA_NEG_X_0)
            mstore(add(f, 0x200), BETA_NEG_Y_1)
            mstore(add(f, 0x220), BETA_NEG_Y_0)
            mstore(add(f, 0x240), x)
            mstore(add(f, 0x260), y)
            mstore(add(f, 0x280), GAMMA_NEG_X_1)
            mstore(add(f, 0x2a0), GAMMA_NEG_X_0)
            mstore(add(f, 0x2c0), GAMMA_NEG_Y_1)
            mstore(add(f, 0x2e0), GAMMA_NEG_Y_0)

            // Check pairing equation.
            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x300, f, 0x20)
            // Also check returned value (both are either 1 or 0).
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
