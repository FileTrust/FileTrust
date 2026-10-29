
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./BN254MathLib.sol";
import "./PublicInputMSMLib.sol";

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
    uint256 constant ALPHA_X = 19067460028395793847421391059596421109907648957689645194219032930339696580821;
    uint256 constant ALPHA_Y = 411368395494066029648775678387436344159695901467826501013959966596213963675;

    // Groth16 beta point in G2 in powers of i
    uint256 constant BETA_NEG_X_0 = 7364449881903878402590101739715966792980222309531231722034717742821084335419;
    uint256 constant BETA_NEG_X_1 = 15221763556317654550856256416166978156875707553033374246367940656609126782619;
    uint256 constant BETA_NEG_Y_0 = 16722805401922394957212335269643900583381179431394418351133477807777399919022;
    uint256 constant BETA_NEG_Y_1 = 21331708418123504177714600336171397391515597740980361680632613030150259077733;

    // Groth16 gamma point in G2 in powers of i
    uint256 constant GAMMA_NEG_X_0 = 13826064044035122880698842608001428525677838651532907026054121687868302194841;
    uint256 constant GAMMA_NEG_X_1 = 2966746192681621024040836932986931768785287531641250476244862751388953003025;
    uint256 constant GAMMA_NEG_Y_0 = 14910317584347587095161458849531431042122971252560863283446334426012943634957;
    uint256 constant GAMMA_NEG_Y_1 = 829858204777607289124054162787629280648711807395380766724174812434615194785;

    // Groth16 delta point in G2 in powers of i
    uint256 constant DELTA_NEG_X_0 = 21654845116393386385468121022189758304350938708201569191382937846584213333267;
    uint256 constant DELTA_NEG_X_1 = 1247745479546253124714991650440856759257012360098028246515703658777049572220;
    uint256 constant DELTA_NEG_Y_0 = 15165078122004700892161505854753911648166762813464528599878475087416162534153;
    uint256 constant DELTA_NEG_Y_1 = 702054945588428888054263021462054252527744433596491301537967880055850907836;

    // Constant and public input points
    uint256 constant CONSTANT_X = 21101931260765173051081376770247949897636865147021924443934146309857803056228;
    uint256 constant CONSTANT_Y = 18179384687373890884177262617826669099141392936765986306754055957739119788042;
    uint256 constant PUB_0_X = 0;
    uint256 constant PUB_0_Y = 0;
    uint256 constant PUB_1_X = 0;
    uint256 constant PUB_1_Y = 0;
    uint256 constant PUB_2_X = 0;
    uint256 constant PUB_2_Y = 0;
    uint256 constant PUB_3_X = 3211344885524930512410417938827764539754021366828151062775334198622365930705;
    uint256 constant PUB_3_Y = 17787190882549807538539583796939326092424201300699333671413619391418122255989;
    uint256 constant PUB_4_X = 16747901689951623074894332478496351763977778895766096205536320450229574128498;
    uint256 constant PUB_4_Y = 4936879444500110798851498626949672788046503437530234715497582717380554823993;
    uint256 constant PUB_5_X = 9716434299079765816313862451811387652130826954465921949119267515631151891271;
    uint256 constant PUB_5_Y = 10645004301727437369625036695633205260071107710941791638992422360759742531157;
    uint256 constant PUB_6_X = 8259007764424214476391168459543451536006984669861215015484090766608592891086;
    uint256 constant PUB_6_Y = 13372678509623315418942145567944398341744266738233903974941776233247845515675;
    uint256 constant PUB_7_X = 8986556201004419330570409039298139359068521863604402482775476367766959072745;
    uint256 constant PUB_7_Y = 15005153052579067665122775327662231300024008285229266402059101527428592498586;
    uint256 constant PUB_8_X = 2609684209500286613436684678665022086977748604207187017323967264060713618;
    uint256 constant PUB_8_Y = 5098088261800301540254440545692090833474533609257422508150625216510723827464;
    uint256 constant PUB_9_X = 13314445203701740433539628189392617355342675069520176259623063397011802139006;
    uint256 constant PUB_9_Y = 10056264843960184355841552039371899028696726358784761120499152597366445262148;
    uint256 constant PUB_10_X = 19029277935426799137172042975784935761848749594204637799150429718955252849623;
    uint256 constant PUB_10_Y = 9129969870603693756048397105881638264660054678379783204871123785808126562120;
    uint256 constant PUB_11_X = 11635842311635379986996291375751942600138970436629598270660696383632702758498;
    uint256 constant PUB_11_Y = 12339384083731077264740624177924815118841511745622473173450202262574034624919;
    uint256 constant PUB_12_X = 17602703550801937163211816485641937743732225169074591058962045573449512886881;
    uint256 constant PUB_12_Y = 3496800081864400488941694720398161705122914830428705545397473684044176115467;
    uint256 constant PUB_13_X = 14645798293948697319677604746484084464236069695908079620015324577020669844394;
    uint256 constant PUB_13_Y = 10789906617556696615866555520862331098399855311251169027229012702283819626722;
    uint256 constant PUB_14_X = 13330441313185876525796494373590666933663214237452435429110779887775960416123;
    uint256 constant PUB_14_Y = 3481696537485662836874517429032657076424147737889942925257273148839321566206;
    uint256 constant PUB_15_X = 1706135138532202306435658904844452185749050233901007567053690670504722586018;
    uint256 constant PUB_15_Y = 14373890607114237417675894064462627503364631034907810559054451036506570375057;
    uint256 constant PUB_16_X = 3276801024848852872810698409967133496710464332787863348834535739813229009684;
    uint256 constant PUB_16_Y = 6679498818406705941836451876837190244543621601399962946134916754762437230151;
    uint256 constant PUB_17_X = 14841232321100572291010787642492881941612317319037951739876955226257973761232;
    uint256 constant PUB_17_Y = 2296011466395734463738772882853863991880231164583906677826359936781690436539;
    uint256 constant PUB_18_X = 1576598956263550360146367572789457010906529791971906899426957947839423912647;
    uint256 constant PUB_18_Y = 17884268862939637192002071300393727914078840815936295666279863227727268501241;
    uint256 constant PUB_19_X = 10320766116004633890843349901395524850694218596768003455180665186490494082518;
    uint256 constant PUB_19_Y = 14335431414180950907786308602402088633447424526327327123992987693295870906313;
    uint256 constant PUB_20_X = 7095868849911319770900675778020895413709495445061285539085898379423699762281;
    uint256 constant PUB_20_Y = 7626551125464785299338494167742557410407777755014902635097699758688654361911;
    uint256 constant PUB_21_X = 18041935332075988816168028917567944239290700124172376648054033841293085079997;
    uint256 constant PUB_21_Y = 12840265955201426345250946229658827917360831004214132692756387324556140594099;
    uint256 constant PUB_22_X = 21595109546526798841012183869128611968121136882218392214572158358453976511363;
    uint256 constant PUB_22_Y = 21065841897961976875044178020527864034840393496083852657199284493911728214781;
    uint256 constant PUB_23_X = 3504870672806418496350216628263096541286900031634194046238430811317977551811;
    uint256 constant PUB_23_Y = 2737326679282924542601262727905910255414025000418831443756620433650137062615;
    uint256 constant PUB_24_X = 11611162469745937206202198153139323057274248138133459951651957419715639817046;
    uint256 constant PUB_24_Y = 13279177317078495664777820556169585962946512879916023691160495773060904658769;
    uint256 constant PUB_25_X = 13232589539492343836854489860593146960285943792510546656009221009872813713371;
    uint256 constant PUB_25_Y = 966118738076656849163990022927826770885357435497128325816043213571651654567;
    uint256 constant PUB_26_X = 18336436005188796377108144288277007180537768917900179028712075019151833875077;
    uint256 constant PUB_26_Y = 14850730696582656591280186822255410226051289232500611232197271369608002486838;
    uint256 constant PUB_27_X = 12800534947607863839281598410119077891072678654556744673679368155623131202165;
    uint256 constant PUB_27_Y = 10896823350147412087743633887839827317329385888679364568005766912591012424106;
    uint256 constant PUB_28_X = 5176250239584922540670593315491985506386371953907916830617299732125733402608;
    uint256 constant PUB_28_Y = 4154695264120774063671139835235405032076709082976340951985708630217593421381;
    uint256 constant PUB_29_X = 1672150097108690715046177293795844660552789035762755167594279954137750468546;
    uint256 constant PUB_29_Y = 5239803903038085870352998001438324052976661882471875215810862994976087149866;
    uint256 constant PUB_30_X = 11305888819315516681809910142216793634266060612572651244936251151769357729518;
    uint256 constant PUB_30_Y = 21663532365454477472734187879613826529709431243207856687476146792631883055649;
    uint256 constant PUB_31_X = 2427120957837998820095519203584924755363015679214800495407940242801450478811;
    uint256 constant PUB_31_Y = 8515081601004582216709556257069711327342076304954394515325605225809896732474;
    uint256 constant PUB_32_X = 3885524565183425508832823282064177281656625830638723688008352534186079469422;
    uint256 constant PUB_32_Y = 4783896154624801025537171300407863899661414248128972396481063973551545317202;
    uint256 constant PUB_33_X = 4964040001731642681856273112497350251534264694000621028047795962814826568097;
    uint256 constant PUB_33_Y = 5857820235847385784101128975098315940695759474016052082876711068267174629822;
    uint256 constant PUB_34_X = 7886774265904114255609603274952631316382472150647330271248821585260147354254;
    uint256 constant PUB_34_Y = 20271057631511175001440778054649856177715922012870364750834664212268034091393;
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
    uint256 constant PUB_51_X = 2080838527451313524033611121438958315429279668288628259990574684000707657531;
    uint256 constant PUB_51_Y = 17591591064994421886271808951754747847807161686960330097271589099427748533913;
    uint256 constant PUB_52_X = 14031215668610354144353699317460927905015552296290813712877623321622909604915;
    uint256 constant PUB_52_Y = 13642670919791169062909770629591097018645691070104512853470463034222235129015;
    uint256 constant PUB_53_X = 4498773741983481461459041946924341692523523018565348041186109940248098736430;
    uint256 constant PUB_53_Y = 17072038764238113268717298495955640714391981849414427986187310173455752806170;
    uint256 constant PUB_54_X = 15489202397519042236164853914269539551402876397592766270648415888428591214937;
    uint256 constant PUB_54_Y = 8533123592536004005587516240193623048767036522276525262763905292334929109572;
    uint256 constant PUB_55_X = 188872631646324072105438330404319876334810841754700888590701089377657483227;
    uint256 constant PUB_55_Y = 9783892384854970833908079431065911961481028776688174456451798142669560334115;
    uint256 constant PUB_56_X = 7741826986064660247714252699979252896110842267365586917704616323233116952185;
    uint256 constant PUB_56_Y = 15436988099437842501845061457949525587190094345657556814590712571152438028298;
    uint256 constant PUB_57_X = 17364116243635195927186646400555653559022537201974699939520300390405723058196;
    uint256 constant PUB_57_Y = 2152396938858976531671175526301718607335190788562000807467129495855213118065;
    uint256 constant PUB_58_X = 17187232218532499830100126313171724855856242892743037764047057019545749354136;
    uint256 constant PUB_58_Y = 2712974092305491974647936352179273922944130465791321279720387782808445346264;
    uint256 constant PUB_59_X = 10687790357443069958848778341664928380058719560773368727112737193843384321219;
    uint256 constant PUB_59_Y = 21157608485620187833592004981658548939652789255272234802670624977558710085745;
    uint256 constant PUB_60_X = 1653829754064332292051642291381670188560638113980422866150577617666162571933;
    uint256 constant PUB_60_Y = 9191846457704242592664240702864314758796216139498293644190894596099296728714;
    uint256 constant PUB_61_X = 7917277061513675383156328375765588511178763827283030977824962189373835693958;
    uint256 constant PUB_61_Y = 8801171031892385514946484164314418204604526401640757328209978703250307595042;
    uint256 constant PUB_62_X = 8749794691375368616717020530179153262482311421575802950354791068330434234828;
    uint256 constant PUB_62_Y = 20555792373393343950399054551104521144023037379279543841458752977685934793223;
    uint256 constant PUB_63_X = 16865841470974570332236973246587357354372073892077814073645355219225689358365;
    uint256 constant PUB_63_Y = 13062892135018822133183092790522006377045175935778905106307875184629641474544;
    uint256 constant PUB_64_X = 14127685066169568190486157895964036459873974921512341298685122458114931435980;
    uint256 constant PUB_64_Y = 4303878674131104717474420350197132259781631474080254702021277005812169059391;
    uint256 constant PUB_65_X = 4200374187611074898322787925038305575361228820283209700930511835657970628569;
    uint256 constant PUB_65_Y = 11428218694443139351650732014643622007112447739077980907166918603069081336887;

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
        (uint256 hx, uint256 hy) = PublicInputMSMLib.publicInputMSM_high(input);
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
