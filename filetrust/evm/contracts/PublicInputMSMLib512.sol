// SPDX-License-Identifier: MIT
// Generated from App/VK512/core/zk/gnark-storage-proof/keys/profiles/partition_512b_d26_n16_m4/partition/PartitionStorageProofGnarkVerifier.sol by scripts/generate_split_partition_verifier.py
pragma solidity ^0.8.0;

/// @title Public-input MSM helper — second half (inputs 66–131).
/// @notice Computes sum_i=66..131 PUB_i * scalar_i on BN254 G1.
///         Extracted from the gnark Groth16 verifier so the main verifier
///         contract stays within EIP-170's 24 576-byte deployed-bytecode limit.
///         Every constant and every assembly instruction is byte-for-byte
///         identical to what gnark generated for those 66 inputs.
/// @author Remco Bloemen, whose gnark Groth16 verifier template this is lifted
///         from. Splitting it across contracts to fit EIP-170 moved the
///         boundaries, not the code or the authorship. MIT, as the original.
library PublicInputMSMLib512 {

    error PublicInputNotInField();

    uint256 private constant PRECOMPILE_MUL = 0x07;
    uint256 private constant PRECOMPILE_ADD = 0x06;
    uint256 private constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Verification-key G1 points for public inputs 66–131.
    uint256 private constant PUB_66_X = 15371029224878419902909326799624495227692400777163893356623735095097301163200;
    uint256 private constant PUB_66_Y = 18579076835259204022763667124152790826830261526532588067891761685512433850679;
    uint256 private constant PUB_67_X = 5674404017431613656922620133167380632176140686006717126447531486459305427192;
    uint256 private constant PUB_67_Y = 14810994772807824408540717782884593776899183247807885636692676939092842243257;
    uint256 private constant PUB_68_X = 12351202405832308818014728669981488035183389706043779750500273368635950498272;
    uint256 private constant PUB_68_Y = 14179291563437002922884507752982239192082672556003869584698043673079388739957;
    uint256 private constant PUB_69_X = 86034799505471218720061866654767600755470908744794422769134495866306775122;
    uint256 private constant PUB_69_Y = 10544754124904329831671277583730138705772613808151186860895091273931657759466;
    uint256 private constant PUB_70_X = 8058402202789204504130305149986231851242860986784863975249422238779198285935;
    uint256 private constant PUB_70_Y = 19029207630635056679916553513036309421490275812763564085700140814974883476575;
    uint256 private constant PUB_71_X = 7802281336776783376127684486224837765367218529663190119571585577657557533030;
    uint256 private constant PUB_71_Y = 13785235492818223951227146483208906307554421688101000185321654434103812307932;
    uint256 private constant PUB_72_X = 10896340031012334018903057098917580587541945007995656109452013698142535171256;
    uint256 private constant PUB_72_Y = 2757974815200837673356460766067342681198309924385789120080829548564001911838;
    uint256 private constant PUB_73_X = 20074261439816469378821088697129584783676508916362822973321597173007263803446;
    uint256 private constant PUB_73_Y = 12185817936730964213344968902652971570696680801304313354398374813716166713904;
    uint256 private constant PUB_74_X = 8833117790883450067038927639101441185888495693719780641911997463363114747321;
    uint256 private constant PUB_74_Y = 938541225530796962782579257386485240253265979135913843935113535281978436266;
    uint256 private constant PUB_75_X = 19841655320070952711216528328475715175463236272134103660251211613998384469545;
    uint256 private constant PUB_75_Y = 12061006672891758711702954331600059941769585321071995845962651902640414283815;
    uint256 private constant PUB_76_X = 2908661723826728785852720532894650759315951187257128585584629572794558905252;
    uint256 private constant PUB_76_Y = 13179051979735276519514928881570950313171006283753931481205901768180214326400;
    uint256 private constant PUB_77_X = 8878517236831488745374678849943571827623424584172410232303469770271502319617;
    uint256 private constant PUB_77_Y = 5664290507848253654374534065423529138047056737576759275617862267283582609280;
    uint256 private constant PUB_78_X = 5371066184078409612220942615926628535393878430266575095432867216226948316664;
    uint256 private constant PUB_78_Y = 20315387311474988892140364485134006104907661305272450724934841944675029893098;
    uint256 private constant PUB_79_X = 9013672903652554824430974807619159227293002281283287742942357411342729458433;
    uint256 private constant PUB_79_Y = 6744434595648524693067596614698085898799540142931755567535319376644808749596;
    uint256 private constant PUB_80_X = 19667282038621899058901620227263555328149035102393398353929022576196133238556;
    uint256 private constant PUB_80_Y = 3179473252737420403593439700949965819600708511858112066115131149972047557150;
    uint256 private constant PUB_81_X = 18260957167868732962787376477828716859912597755453634198170605314394161695611;
    uint256 private constant PUB_81_Y = 17340694673008535859921700515697987762914538137711460700127283839825887870143;
    uint256 private constant PUB_82_X = 6730613716022156173179607471212082740458053919811251106349993365630421271183;
    uint256 private constant PUB_82_Y = 217143217714728831276848294901033465854976786341143613589306759598862975597;
    uint256 private constant PUB_83_X = 12191232332745626032714789552978211353289782933599217670209781805297460405716;
    uint256 private constant PUB_83_Y = 21795209063832479908115884007910946743934081248481429657246805245668838266741;
    uint256 private constant PUB_84_X = 15895504714066922040029680815208478941239665447234198008270892332421673153538;
    uint256 private constant PUB_84_Y = 8871825614392982371091994237052094690585605590032053206717704032173321651671;
    uint256 private constant PUB_85_X = 1919408072322464241191419396123992707474486557135937504059860943559826592031;
    uint256 private constant PUB_85_Y = 19638347377839311194635315904481734702321409230312194713149066084571542957753;
    uint256 private constant PUB_86_X = 21573432567336305073474195285843279964832241508577784330495734022035580527139;
    uint256 private constant PUB_86_Y = 15122145064014160512922388611225083243010601058154852411969452691005166810599;
    uint256 private constant PUB_87_X = 13791909310419875546218047514702322849406922069726427730176169741360692271404;
    uint256 private constant PUB_87_Y = 909103811028110264836699597539591751541469547777679946255139083394761705152;
    uint256 private constant PUB_88_X = 21824585425739540520670226478802825096746099250758498141978495999883951469764;
    uint256 private constant PUB_88_Y = 10100099181348298914639224704892503423054861244840374774688019498409317623031;
    uint256 private constant PUB_89_X = 6888733714946511032108193828720130426409959243585704839823221246167828616238;
    uint256 private constant PUB_89_Y = 6933667448489663480355959161479248251080062585192226013925108046430869790866;
    uint256 private constant PUB_90_X = 6332707058020347669000197165186912563080456891424545382090068470180383709975;
    uint256 private constant PUB_90_Y = 14223248002894633576713422275707338541782416543039541862238459271062817747722;
    uint256 private constant PUB_91_X = 4155987249419539281441279807511388113435024758498893232391405211514205649188;
    uint256 private constant PUB_91_Y = 10731590299119075815528484907365892649414019517928042574434035314539044210712;
    uint256 private constant PUB_92_X = 8480061354995131002722110130058469906656211912689379961636285763981294263376;
    uint256 private constant PUB_92_Y = 17478108129908091717560438261920426339467360410957365035516186207951333766283;
    uint256 private constant PUB_93_X = 20249502671054051249047571615474805752195621393837905529680463565946338784777;
    uint256 private constant PUB_93_Y = 19823993960226296099487074920347767079287454095288344634451404189768527737346;
    uint256 private constant PUB_94_X = 7842938414334305381501884293729891010676055802451971462089864233491902120461;
    uint256 private constant PUB_94_Y = 19171513811487449013503673373917089232745288959239170856594446727693464168901;
    uint256 private constant PUB_95_X = 3335616908011544113088587622657646399623886109978800297256056538813067577215;
    uint256 private constant PUB_95_Y = 9066566153942118428068313674131239196545016768406977602967982501217359024105;
    uint256 private constant PUB_96_X = 4717972454754071515032813038016195591261375954331733865916607621719730818141;
    uint256 private constant PUB_96_Y = 2675228850316421109685679911429860227269693544282734156507126505433382282;
    uint256 private constant PUB_97_X = 3863675731557479564186128615524255315691815919290682488288056541111608389748;
    uint256 private constant PUB_97_Y = 6792572853694820402003082629493496746544788430462257957178061708101796720085;
    uint256 private constant PUB_98_X = 492888495136175968120100379276545344001673265760769488217773596994211330583;
    uint256 private constant PUB_98_Y = 19747083408572431334566635645335039945894864827965983633749724723542313677237;
    uint256 private constant PUB_99_X = 21083312839033940876402400476981928815473278346708375352702389796199055034712;
    uint256 private constant PUB_99_Y = 1451887120724984513827110614855617161459422347320967166779943255238722276002;
    uint256 private constant PUB_100_X = 20850748934270071932479693848394542952219997731129839005799466321988817893133;
    uint256 private constant PUB_100_Y = 4306519250586579770917344030879282501799435106838143911008284200956600467914;
    uint256 private constant PUB_101_X = 21114696793949681741723999261890315020485013905323586270140371848702630317003;
    uint256 private constant PUB_101_Y = 20352589029366606182373690094030995969652603759089180434326109526661766674980;
    uint256 private constant PUB_102_X = 5807945868717995679118924611477134119028185813095586313303293466358860920085;
    uint256 private constant PUB_102_Y = 5696511313791964783529013832667894906525563263204813016026482186809381717340;
    uint256 private constant PUB_103_X = 17199826633414705421218324012378365135442589234958423510238318002685505928984;
    uint256 private constant PUB_103_Y = 10328001757379861927413869906548743794800498343802279520365377244896138670401;
    uint256 private constant PUB_104_X = 19688451152862556490480423052428624317131822260008734769423990561431299226123;
    uint256 private constant PUB_104_Y = 3265112495546519273196260199387880419786026327488693270261995243305894854103;
    uint256 private constant PUB_105_X = 13653777581664051181029898370070557379403874117138641271986680114851338303104;
    uint256 private constant PUB_105_Y = 9296231027027631877169309671785467081105287345954520492697125144805361473895;
    uint256 private constant PUB_106_X = 9304057604494486356208642767960719985077917349845246781226730478747747962306;
    uint256 private constant PUB_106_Y = 19538750106157215479670224609279435592791055511842741260446797633850619613931;
    uint256 private constant PUB_107_X = 15765368215674588413336210401046240955393447732471383146389552356158876928541;
    uint256 private constant PUB_107_Y = 19287896375083974266518671919315908605210768888649790199647324304299887265488;
    uint256 private constant PUB_108_X = 21516658445647816178931978194565530838440762417611870086805377917207060819532;
    uint256 private constant PUB_108_Y = 19604096801992027252376470733872515521985856413204599844744934094222043716538;
    uint256 private constant PUB_109_X = 14362619949317261628393532148266955232346651863087223557298295963506493778429;
    uint256 private constant PUB_109_Y = 6182311246145303405595613335020299212113513292514059847630759140361018516950;
    uint256 private constant PUB_110_X = 1157647829333263909159008918720339014365414274919344739420454141614673849894;
    uint256 private constant PUB_110_Y = 13989527400097382638283414651830929319419688645536939836079013378296130466629;
    uint256 private constant PUB_111_X = 1952632501830923519447689372695114583769210187591890850847058419290338001332;
    uint256 private constant PUB_111_Y = 20514702084230817018221908117258439814662513394207628591360167965592979064578;
    uint256 private constant PUB_112_X = 9476415632233609400784450210265143753974702197855083112146913623476992492614;
    uint256 private constant PUB_112_Y = 1185737081775195784423087492027527381045245136287686137170129900429141965365;
    uint256 private constant PUB_113_X = 13086992808677312697823429608530053026413227622744738441032612329835760086978;
    uint256 private constant PUB_113_Y = 14599558772771878981761575149994241668394225412820351307015165112342400568565;
    uint256 private constant PUB_114_X = 18014449263402908472095355230868046822060856911821120362276709668818696887793;
    uint256 private constant PUB_114_Y = 20928495340079702505413311518433270045358740714097989402623049102797279263180;
    uint256 private constant PUB_115_X = 9677154816920574609343233870389633238919034145198290735224135877833419417618;
    uint256 private constant PUB_115_Y = 19402991133391032240106405230827077811531821742706436671930018329446436056343;
    uint256 private constant PUB_116_X = 3265344835079270034405296458515111219603514361664026992515586562060306709662;
    uint256 private constant PUB_116_Y = 12088020989225785099652144955150002202538788062325583568648256290233773322221;
    uint256 private constant PUB_117_X = 12692562193593926433911120553854084784817051503174227320056769804720160474749;
    uint256 private constant PUB_117_Y = 17023352329363148984252300048887684301164390437069554979981846448678744234288;
    uint256 private constant PUB_118_X = 8960884929369425887992501755061572944416147497507410841374215557185387369543;
    uint256 private constant PUB_118_Y = 20882600039229070095040373123063307582053678889106321395532726123339242818001;
    uint256 private constant PUB_119_X = 8164216784392506749856226391719725578058996170640862785850246715533910876459;
    uint256 private constant PUB_119_Y = 13937873151152181902701092476824488633896601638613843853101195116296747501186;
    uint256 private constant PUB_120_X = 5036515427541901521686751542931863924819656971973746213393051468931975123184;
    uint256 private constant PUB_120_Y = 19574506466194572173731720958683353370023244146737656580461600168253901523374;
    uint256 private constant PUB_121_X = 16626190988926477236085113726690953212559978805504608855971115594879959074773;
    uint256 private constant PUB_121_Y = 8100035103697066046409989548490750107051934865341895131785520569127499995594;
    uint256 private constant PUB_122_X = 7292980397049528116233556313382781405844071037781099577917447404774682452203;
    uint256 private constant PUB_122_Y = 2747623595991553660205794491059582165449789593279670033364783884086537813850;
    uint256 private constant PUB_123_X = 679189461675125830153159502369952873256864299168407254980589861002070999969;
    uint256 private constant PUB_123_Y = 5514054710070769415022777510218769865274810662910317544335602609934704376870;
    uint256 private constant PUB_124_X = 1303415721561380084362334983452989313308679997342961375691273147166700352719;
    uint256 private constant PUB_124_Y = 107786550558901823276499376858712185042263274345181590906418318339428078033;
    uint256 private constant PUB_125_X = 21853708711369611407477551477470220099490717104354596308373752997433791575562;
    uint256 private constant PUB_125_Y = 2039255841163054905371746921121311728681859183153134304421022119846982649773;
    uint256 private constant PUB_126_X = 12699563162612086034334333897873212433750376266097021909722584953304660176758;
    uint256 private constant PUB_126_Y = 2329724578732710887127385691385376316201005019896629576591801721234269394228;
    uint256 private constant PUB_127_X = 7477715470257828757284364035930358773145072549552497924630619386950380117679;
    uint256 private constant PUB_127_Y = 8015079898897237728975135117581760483917619732670998724304967237553070420539;
    uint256 private constant PUB_128_X = 6947506425302429430562268914266456531831022104665432546008211023001431133881;
    uint256 private constant PUB_128_Y = 16512157319997956209780023962264865404004751846241565521419233754848849965576;
    uint256 private constant PUB_129_X = 21801291153116271501902478474191275302736808045053176679125986093108581665090;
    uint256 private constant PUB_129_Y = 3123324883821018388501315748525169240470657856352881582384320355148363086429;
    uint256 private constant PUB_130_X = 15717582130309556193954647494798603043947585057657808849828042964322074334145;
    uint256 private constant PUB_130_Y = 17792688493582214759439478927620244012826481498665487580152426890078303269284;
    uint256 private constant PUB_131_X = 16074096987002663066699667037797232720162941243313760154145507640618377633906;
    uint256 private constant PUB_131_Y = 10760887736775131969139982143244430685178571169216957914048152220069170430683;

    /// @notice Compute sum_i=66..131 PUB_i * input[i] on BN254 G1.
    /// @dev Starts with the identity (0, 0); the caller adds the result to the
    ///      first-half MSM using ecAdd to get the full public-input combination.
    /// @param input The full 132-element public input array from the original calldata.
    function publicInputMSM_high(uint256[132] calldata input)
        external view returns (uint256 x, uint256 y)
    {
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let g := add(f, 0x40)
            let s
            mstore(f, 0)
            mstore(add(f, 0x20), 0)
            mstore(g, PUB_66_X)
            mstore(add(g, 0x20), PUB_66_Y)
            s :=  calldataload(add(input, 2112))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_67_X)
            mstore(add(g, 0x20), PUB_67_Y)
            s :=  calldataload(add(input, 2144))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_68_X)
            mstore(add(g, 0x20), PUB_68_Y)
            s :=  calldataload(add(input, 2176))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_69_X)
            mstore(add(g, 0x20), PUB_69_Y)
            s :=  calldataload(add(input, 2208))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_70_X)
            mstore(add(g, 0x20), PUB_70_Y)
            s :=  calldataload(add(input, 2240))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_71_X)
            mstore(add(g, 0x20), PUB_71_Y)
            s :=  calldataload(add(input, 2272))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_72_X)
            mstore(add(g, 0x20), PUB_72_Y)
            s :=  calldataload(add(input, 2304))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_73_X)
            mstore(add(g, 0x20), PUB_73_Y)
            s :=  calldataload(add(input, 2336))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_74_X)
            mstore(add(g, 0x20), PUB_74_Y)
            s :=  calldataload(add(input, 2368))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_75_X)
            mstore(add(g, 0x20), PUB_75_Y)
            s :=  calldataload(add(input, 2400))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_76_X)
            mstore(add(g, 0x20), PUB_76_Y)
            s :=  calldataload(add(input, 2432))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_77_X)
            mstore(add(g, 0x20), PUB_77_Y)
            s :=  calldataload(add(input, 2464))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_78_X)
            mstore(add(g, 0x20), PUB_78_Y)
            s :=  calldataload(add(input, 2496))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_79_X)
            mstore(add(g, 0x20), PUB_79_Y)
            s :=  calldataload(add(input, 2528))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_80_X)
            mstore(add(g, 0x20), PUB_80_Y)
            s :=  calldataload(add(input, 2560))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_81_X)
            mstore(add(g, 0x20), PUB_81_Y)
            s :=  calldataload(add(input, 2592))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_82_X)
            mstore(add(g, 0x20), PUB_82_Y)
            s :=  calldataload(add(input, 2624))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_83_X)
            mstore(add(g, 0x20), PUB_83_Y)
            s :=  calldataload(add(input, 2656))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_84_X)
            mstore(add(g, 0x20), PUB_84_Y)
            s :=  calldataload(add(input, 2688))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_85_X)
            mstore(add(g, 0x20), PUB_85_Y)
            s :=  calldataload(add(input, 2720))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_86_X)
            mstore(add(g, 0x20), PUB_86_Y)
            s :=  calldataload(add(input, 2752))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_87_X)
            mstore(add(g, 0x20), PUB_87_Y)
            s :=  calldataload(add(input, 2784))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_88_X)
            mstore(add(g, 0x20), PUB_88_Y)
            s :=  calldataload(add(input, 2816))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_89_X)
            mstore(add(g, 0x20), PUB_89_Y)
            s :=  calldataload(add(input, 2848))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_90_X)
            mstore(add(g, 0x20), PUB_90_Y)
            s :=  calldataload(add(input, 2880))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_91_X)
            mstore(add(g, 0x20), PUB_91_Y)
            s :=  calldataload(add(input, 2912))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_92_X)
            mstore(add(g, 0x20), PUB_92_Y)
            s :=  calldataload(add(input, 2944))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_93_X)
            mstore(add(g, 0x20), PUB_93_Y)
            s :=  calldataload(add(input, 2976))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_94_X)
            mstore(add(g, 0x20), PUB_94_Y)
            s :=  calldataload(add(input, 3008))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_95_X)
            mstore(add(g, 0x20), PUB_95_Y)
            s :=  calldataload(add(input, 3040))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_96_X)
            mstore(add(g, 0x20), PUB_96_Y)
            s :=  calldataload(add(input, 3072))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_97_X)
            mstore(add(g, 0x20), PUB_97_Y)
            s :=  calldataload(add(input, 3104))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_98_X)
            mstore(add(g, 0x20), PUB_98_Y)
            s :=  calldataload(add(input, 3136))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_99_X)
            mstore(add(g, 0x20), PUB_99_Y)
            s :=  calldataload(add(input, 3168))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_100_X)
            mstore(add(g, 0x20), PUB_100_Y)
            s :=  calldataload(add(input, 3200))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_101_X)
            mstore(add(g, 0x20), PUB_101_Y)
            s :=  calldataload(add(input, 3232))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_102_X)
            mstore(add(g, 0x20), PUB_102_Y)
            s :=  calldataload(add(input, 3264))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_103_X)
            mstore(add(g, 0x20), PUB_103_Y)
            s :=  calldataload(add(input, 3296))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_104_X)
            mstore(add(g, 0x20), PUB_104_Y)
            s :=  calldataload(add(input, 3328))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_105_X)
            mstore(add(g, 0x20), PUB_105_Y)
            s :=  calldataload(add(input, 3360))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_106_X)
            mstore(add(g, 0x20), PUB_106_Y)
            s :=  calldataload(add(input, 3392))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_107_X)
            mstore(add(g, 0x20), PUB_107_Y)
            s :=  calldataload(add(input, 3424))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_108_X)
            mstore(add(g, 0x20), PUB_108_Y)
            s :=  calldataload(add(input, 3456))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_109_X)
            mstore(add(g, 0x20), PUB_109_Y)
            s :=  calldataload(add(input, 3488))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_110_X)
            mstore(add(g, 0x20), PUB_110_Y)
            s :=  calldataload(add(input, 3520))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_111_X)
            mstore(add(g, 0x20), PUB_111_Y)
            s :=  calldataload(add(input, 3552))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_112_X)
            mstore(add(g, 0x20), PUB_112_Y)
            s :=  calldataload(add(input, 3584))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_113_X)
            mstore(add(g, 0x20), PUB_113_Y)
            s :=  calldataload(add(input, 3616))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_114_X)
            mstore(add(g, 0x20), PUB_114_Y)
            s :=  calldataload(add(input, 3648))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_115_X)
            mstore(add(g, 0x20), PUB_115_Y)
            s :=  calldataload(add(input, 3680))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_116_X)
            mstore(add(g, 0x20), PUB_116_Y)
            s :=  calldataload(add(input, 3712))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_117_X)
            mstore(add(g, 0x20), PUB_117_Y)
            s :=  calldataload(add(input, 3744))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_118_X)
            mstore(add(g, 0x20), PUB_118_Y)
            s :=  calldataload(add(input, 3776))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_119_X)
            mstore(add(g, 0x20), PUB_119_Y)
            s :=  calldataload(add(input, 3808))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_120_X)
            mstore(add(g, 0x20), PUB_120_Y)
            s :=  calldataload(add(input, 3840))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_121_X)
            mstore(add(g, 0x20), PUB_121_Y)
            s :=  calldataload(add(input, 3872))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_122_X)
            mstore(add(g, 0x20), PUB_122_Y)
            s :=  calldataload(add(input, 3904))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_123_X)
            mstore(add(g, 0x20), PUB_123_Y)
            s :=  calldataload(add(input, 3936))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_124_X)
            mstore(add(g, 0x20), PUB_124_Y)
            s :=  calldataload(add(input, 3968))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_125_X)
            mstore(add(g, 0x20), PUB_125_Y)
            s :=  calldataload(add(input, 4000))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_126_X)
            mstore(add(g, 0x20), PUB_126_Y)
            s :=  calldataload(add(input, 4032))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_127_X)
            mstore(add(g, 0x20), PUB_127_Y)
            s :=  calldataload(add(input, 4064))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_128_X)
            mstore(add(g, 0x20), PUB_128_Y)
            s :=  calldataload(add(input, 4096))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_129_X)
            mstore(add(g, 0x20), PUB_129_Y)
            s :=  calldataload(add(input, 4128))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_130_X)
            mstore(add(g, 0x20), PUB_130_Y)
            s :=  calldataload(add(input, 4160))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_131_X)
            mstore(add(g, 0x20), PUB_131_Y)
            s :=  calldataload(add(input, 4192))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))

            x := mload(f)
            y := mload(add(f, 0x20))
        }
        if (!success) {
            revert PublicInputNotInField();
        }
    }
}
