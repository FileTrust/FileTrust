// SPDX-License-Identifier: MIT
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
library PublicInputMSMLib {

    error PublicInputNotInField();

    uint256 private constant PRECOMPILE_MUL = 0x07;
    uint256 private constant PRECOMPILE_ADD = 0x06;
    uint256 private constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Verification-key G1 points for public inputs 66–131.
    uint256 private constant PUB_66_X = 11439777719823460514800688136491992334536249086991634833605187809225243964625;
    uint256 private constant PUB_66_Y = 20024015132805824468104101726496182706067174056077763921795998605832175387327;
    uint256 private constant PUB_67_X = 3545844882263520615536818800105287246460313563670063902169608374510050014674;
    uint256 private constant PUB_67_Y = 15154697462575117704954401374375458021257351126312754314561676878315604031133;
    uint256 private constant PUB_68_X = 6584744601532818432972616293689188312566102065259456406251639747162251126795;
    uint256 private constant PUB_68_Y = 9223359044503563684762678846471103067226561780671394135511567629553533253707;
    uint256 private constant PUB_69_X = 2450419912690118757567287661785813815839803719906939396533759261829336028169;
    uint256 private constant PUB_69_Y = 18414769563104235060708941327113770324729101010048313159119421320563023944854;
    uint256 private constant PUB_70_X = 9966123348111387317977716363606288713835957540065661931639218468823434152888;
    uint256 private constant PUB_70_Y = 21636726902894949854785555730979325607567108650578603430314135148929373957639;
    uint256 private constant PUB_71_X = 5196506331235349954177648874546072304060262789859934964691666484286222440834;
    uint256 private constant PUB_71_Y = 2412595966991384750961032335957813632438207273206155495032359243299313323666;
    uint256 private constant PUB_72_X = 5984317440417269924596510535326011460497711629253629068528998908478565431159;
    uint256 private constant PUB_72_Y = 9061222936947580743846909558928595316368892750536077006702715249538715284684;
    uint256 private constant PUB_73_X = 18839518839961029423525582957965229995000602900358497504845847718274362591644;
    uint256 private constant PUB_73_Y = 20438556264518224476820068656954322070103641625197732682834128570373927512722;
    uint256 private constant PUB_74_X = 11374920948662556036342019259663657003845253867358427250694667788532672956444;
    uint256 private constant PUB_74_Y = 17682877368560974929372768936297892604730336002794109718125230364586149051792;
    uint256 private constant PUB_75_X = 6133641865602925741517704116600233003093220790034930818660114385593747604763;
    uint256 private constant PUB_75_Y = 15157696714175944900368041275591265500264043171082151393655128950210679170139;
    uint256 private constant PUB_76_X = 20056099087001085416729357101470199270307158979116097210247994972747937613279;
    uint256 private constant PUB_76_Y = 15950040471152740248225981242034515056763849168037771614746085922266158129145;
    uint256 private constant PUB_77_X = 15966222926995967832377509873133239332008035694166472257837772708984054476185;
    uint256 private constant PUB_77_Y = 18300573638904247539337609719248011333645749293377436155901012645318271920141;
    uint256 private constant PUB_78_X = 18292505352719217717913975200105628341701265850444962692243361534030697236637;
    uint256 private constant PUB_78_Y = 10444213210827867145509821006498237097649697126303605664912596212413737583290;
    uint256 private constant PUB_79_X = 12762563044850463622817594371665288088228501080275281896850515046531323017205;
    uint256 private constant PUB_79_Y = 13426013480790741374025156320838112185516953384799893907832721140791978288439;
    uint256 private constant PUB_80_X = 12677764002563574311649588974145694317109420796024148237854142735674385244452;
    uint256 private constant PUB_80_Y = 34433968416372438963912552273585139763557661473198948907065817752780058385;
    uint256 private constant PUB_81_X = 13250212123495644716687716728723382167514671646090568845635517101390002874291;
    uint256 private constant PUB_81_Y = 11799237706875279596517302645904449153679972806304952620615660059307340539908;
    uint256 private constant PUB_82_X = 21578282659775948401804634677027879762596994877222374709851521289007502763458;
    uint256 private constant PUB_82_Y = 4628398106561061117244371999274688561306997904084073569524297238057956294915;
    uint256 private constant PUB_83_X = 17133969351345548350924717116132256973078684667625163658925078897172268524583;
    uint256 private constant PUB_83_Y = 10540035357000404473027438856223908494633933288521550219840872786050773578029;
    uint256 private constant PUB_84_X = 5346224951553579481969589277503548941621531706060232847924747788220359828890;
    uint256 private constant PUB_84_Y = 6026792879248315068570772216758865343883360188538098078483779021811387051831;
    uint256 private constant PUB_85_X = 14234963068021796350269576815501998492179550470024791774716974307963489860463;
    uint256 private constant PUB_85_Y = 14280671610847041069956933399304277091808212552104879636529648177772620387384;
    uint256 private constant PUB_86_X = 12563284067704470439776057242646790789187701902656028406994681847491399315081;
    uint256 private constant PUB_86_Y = 17010192425991181065038282162253662755967521093995972371040794412349618413615;
    uint256 private constant PUB_87_X = 18289242258011480323672941905434470131062171322127182015895096695051948587330;
    uint256 private constant PUB_87_Y = 10896140600568045387349065574167576564008938738801083802254966409936333316514;
    uint256 private constant PUB_88_X = 15902820322411081825777741666693209446517686483604584570107593459256146249693;
    uint256 private constant PUB_88_Y = 17355164080922217285400340813974179578611612768383488478526651254460001865000;
    uint256 private constant PUB_89_X = 19613662340391783945101064067771954347798740124048689412138745807649213091780;
    uint256 private constant PUB_89_Y = 19033242298740282418875880956619513937261909192471903321552132474345733869872;
    uint256 private constant PUB_90_X = 6134892326967705435419717736463266762686108158638288709377590974672682102051;
    uint256 private constant PUB_90_Y = 11301587004214463746312222700313387044764945077792689882872416915803820921399;
    uint256 private constant PUB_91_X = 19585607227588016811402281751722493093354886587319511755927817393778125670478;
    uint256 private constant PUB_91_Y = 19294992899275291353827549911537172153646123160689134760539823860538747103999;
    uint256 private constant PUB_92_X = 11598157201808227471338216308166859940507796386574703058622562010877312636492;
    uint256 private constant PUB_92_Y = 5382220845702801479401855417530565870708573048496536309388906526309720448278;
    uint256 private constant PUB_93_X = 16137114591415135210234194532154459642926699993070745920065373124398531483789;
    uint256 private constant PUB_93_Y = 17699397888089966025523261976042367157198147773788391724137302358045734142809;
    uint256 private constant PUB_94_X = 17444768789756566383742305024390307663080592745324243609137361975788676066229;
    uint256 private constant PUB_94_Y = 7129833096202414297707697769714174806330086736307880168388018870111230233143;
    uint256 private constant PUB_95_X = 20096511735456378136014691955852590747247290839964868028907080389191498703693;
    uint256 private constant PUB_95_Y = 3093639770368764972934892276044411601169923022738947442176886272820709430355;
    uint256 private constant PUB_96_X = 1254303821732312178006577115554139911767512407933917635816163412501083302118;
    uint256 private constant PUB_96_Y = 12573756503617625451437482975716262864179663513702455146398297168305076319399;
    uint256 private constant PUB_97_X = 10345293957364200052203095155387835075872971474438484111518903276067390346718;
    uint256 private constant PUB_97_Y = 19936808384659689675357922757146660367497944942177304699072729032401482091149;
    uint256 private constant PUB_98_X = 16501909834141115208999177260491612578076880188684325572861466364285899758624;
    uint256 private constant PUB_98_Y = 2893988084934596537074822869571579550870347061748219369514937451318190662412;
    uint256 private constant PUB_99_X = 15368328934327085615231659464059081427268721585426637913856406630191410827473;
    uint256 private constant PUB_99_Y = 415470186107420493254459416065618574263788652898913908287890975438024305557;
    uint256 private constant PUB_100_X = 20451689308325045661361332852284420099496142319123660433207684061023596375838;
    uint256 private constant PUB_100_Y = 13742543126519768584907340845606998404372530744701697081211622245534576072627;
    uint256 private constant PUB_101_X = 4147836902305785245080002584148263295131341381761376994188754582191634539170;
    uint256 private constant PUB_101_Y = 14693098621069785126962146404650587563262001418061933641918378696754107172127;
    uint256 private constant PUB_102_X = 7492977868850068881790245716657304397839761923457444734215833031683154147956;
    uint256 private constant PUB_102_Y = 3700451969573757109564869704196144794170587453181209763847420730234682802945;
    uint256 private constant PUB_103_X = 3787544412009947848310342576151135846882515455157298601864025205225009005306;
    uint256 private constant PUB_103_Y = 3808074341533809538737748294458858648096853965733530021731319600936619561742;
    uint256 private constant PUB_104_X = 6523717700719020060248471901547134839135268238014899477095216003784224272822;
    uint256 private constant PUB_104_Y = 4029070056435286435426529938834952657586720834601346623489118054023465111202;
    uint256 private constant PUB_105_X = 20695210251051247279992256614209161906619953157517409471520141234489074522533;
    uint256 private constant PUB_105_Y = 3765160069500894282180785336695070674661845540913908367207867981902602874525;
    uint256 private constant PUB_106_X = 17435588583333599561638290794030980046047206191714649416948299063141314875122;
    uint256 private constant PUB_106_Y = 16448842173375176308435221640019861066225817299795052631902636404028362320256;
    uint256 private constant PUB_107_X = 10209404259371139143264162692704781654644145719422990795076938614128584773095;
    uint256 private constant PUB_107_Y = 10518587018925272824015867835975452560791466572240397510990779140929147508445;
    uint256 private constant PUB_108_X = 11508223936514559360298574817599310974646490574591191047792250852829902963456;
    uint256 private constant PUB_108_Y = 12805466912007439609519163164766965435862908898501590324464727370353900487188;
    uint256 private constant PUB_109_X = 2460605842337442179298970371351392665831542270300740884277926468475406930351;
    uint256 private constant PUB_109_Y = 5211369606736372290129768872038182409658190900749083771120994439301670198848;
    uint256 private constant PUB_110_X = 9104464765235149197182805284080155227271304118729223285331218986511462226569;
    uint256 private constant PUB_110_Y = 17719837539672024192158588367310994963093036005538153735458771745485053596825;
    uint256 private constant PUB_111_X = 21452118645415046945530718167634131428014099604860017046094056212655813429601;
    uint256 private constant PUB_111_Y = 17487067137475051627660980744564201653127523679234286982454884278882521638915;
    uint256 private constant PUB_112_X = 8868631333118989172586668509466665635222729164865820201956398426247969962136;
    uint256 private constant PUB_112_Y = 17429506853560562133294243871391217683945107031978716745464071543663680584955;
    uint256 private constant PUB_113_X = 18158641841316317760827527396262577345804481980905487811608702970160390532560;
    uint256 private constant PUB_113_Y = 391787388065233453506505757633917805055787473426786025342596362246789228911;
    uint256 private constant PUB_114_X = 3136844530166570863625254633675136021267363249207774914616239611854536803660;
    uint256 private constant PUB_114_Y = 15154882336847309694456994150561492470247813586466445820567368746336383977922;
    uint256 private constant PUB_115_X = 8096630668297571559862637896739383754700133867493560642310619483689723731870;
    uint256 private constant PUB_115_Y = 9447921439601316205156130998562813593018392947954630104125215401112738131955;
    uint256 private constant PUB_116_X = 2844382101166731546323503246008146921755834928661098585918150106635045814267;
    uint256 private constant PUB_116_Y = 1537718535981713917626306702227441484783318400398503860297170902223284745483;
    uint256 private constant PUB_117_X = 10333093606742732469167688900898780816647224080460718777072124013332906170738;
    uint256 private constant PUB_117_Y = 841454322533642182644482361222754682827998084413558839772440785265324649338;
    uint256 private constant PUB_118_X = 2151519373454844884519672613185568070854585307832058365579621962520624532397;
    uint256 private constant PUB_118_Y = 15430563327890137873409709886946826239192995884705026813313659250785296770920;
    uint256 private constant PUB_119_X = 21017306249613573805378144297312685990285540329493502893221287123965062908435;
    uint256 private constant PUB_119_Y = 15964787462269512668698702562907185606907953649824109114488731204646998059375;
    uint256 private constant PUB_120_X = 7478381375223170612763346629540664483076234104360345528208974505787835319366;
    uint256 private constant PUB_120_Y = 17849369029053841677769613873149035593601459839689504253018798140026446545931;
    uint256 private constant PUB_121_X = 5172632474851263157808604612181942381929798488319346478745285408985899124896;
    uint256 private constant PUB_121_Y = 1496015105455170087622926128514600236273157672309454493283019527520022696000;
    uint256 private constant PUB_122_X = 5838822352713405194361389823225464285832439367632729305651931782134874436258;
    uint256 private constant PUB_122_Y = 11997344670817051874340460182868981600546932728364210641826887102906854443986;
    uint256 private constant PUB_123_X = 11904214568525849126815592572292245205600533696747556023910387570804925548459;
    uint256 private constant PUB_123_Y = 18141591979132946368134375792397026485454653813360703366626356673602213231857;
    uint256 private constant PUB_124_X = 15302338439803909544040722789056540274013234068791362853019942389674727718565;
    uint256 private constant PUB_124_Y = 11487388763598709236113920819838533932069742835876478798914727846735920557980;
    uint256 private constant PUB_125_X = 18869783477129523998765538903096261139497106491054914999735602337308925017203;
    uint256 private constant PUB_125_Y = 19399602393879332740699100276749298286446030845191202336024324219124978786802;
    uint256 private constant PUB_126_X = 696061860325762311873416122694597765691747058965761715383417605959412985633;
    uint256 private constant PUB_126_Y = 16256870882710574891223323415828333000465939288228716803711519759523336830269;
    uint256 private constant PUB_127_X = 13125634574156052100605063380047308660945376666521030200234963531848628320191;
    uint256 private constant PUB_127_Y = 12556680786885437088119832119345183904354200565210091994528863428288219781465;
    uint256 private constant PUB_128_X = 13203131750537987118474821584862545697697228292459059453260144492959618566;
    uint256 private constant PUB_128_Y = 18245519447969249028647005467954054956664292913275277330814231635244061194653;
    uint256 private constant PUB_129_X = 14632990632754597430949508663703095999888920240001970970441742281085531287242;
    uint256 private constant PUB_129_Y = 68459329871104346476276229294693760146576456291229770795842236299117603696;
    uint256 private constant PUB_130_X = 9628066672997043324596395709110245213764407266722949594365073107277925773708;
    uint256 private constant PUB_130_Y = 15418158640793534146921885583985081766535731506748366328306865861643187309865;
    uint256 private constant PUB_131_X = 3800611912569402746173914976936728426967086363963953020701502515650794620341;
    uint256 private constant PUB_131_Y = 19742937927518603178327179880094152030351819409006336806844011543403760558561;

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
