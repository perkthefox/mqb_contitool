"""Factory ZDC calibration templates, section tables, and hardware catalogs for J533 Gateways."""

from __future__ import annotations

import base64
from functools import lru_cache
import zlib

# ZDC #4 (MultiKo / FPA, 4352 B @ 0x1340) section table as compiled into firmware 5463 / 5504 (217 sections).
# The table belongs to the firmware build, not to the dataset tag: 5366 has 207 sections + a CRC entry,
# 5388/5389 have 214, 5463/5504 have 217, and S000..S205 are identical in all of them. From S206 on
# each build differs (5366 keeps a 517-byte zero reserve there), so only S000..S205 may be edited.
FPA_SHARED_SECTIONS = 206
FPA_SEC_OFFS: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 15, 16, 18, 19, 20, 21, 22, 23, 38, 518, 534, 598,
 662, 722, 782, 812, 825, 837, 839, 1229, 1259, 1979, 1980, 1981, 1986, 1991, 1996, 2001, 2006,
 2038, 2042, 2046, 2054, 2058, 2060, 2061, 2062, 2064, 2065, 2066, 2067, 2068, 2069, 2070, 2071,
 2074, 2077, 2087, 2107, 2117, 2132, 2147, 2162, 2177, 2207, 2222, 2237, 2239, 2241, 2254, 2267,
 2273, 2299, 2539, 2569, 2599, 2603, 2633, 2663, 2693, 2723, 2730, 2731, 2738, 2745, 2758, 2784,
 2797, 2798, 2799, 2800, 2802, 2809, 2823, 2830, 2831, 2832, 2833, 2835, 2841, 2847, 2853, 2865,
 2871, 2877, 2883, 2889, 2901, 2907, 2908, 2910, 2912, 2914, 2916, 2918, 2930, 2932, 2934, 2938,
 2940, 2942, 2943, 2944, 2946, 2947, 2950, 2953, 2960, 2974, 2988, 2990, 2992, 3002, 3022, 3032,
 3064, 3096, 3128, 3160, 3224, 3256, 3288, 3292, 3294, 3301, 3308, 3315, 3329, 3333, 3337, 3339,
 3346, 3352, 3353, 3367, 3369, 3370, 3372, 3374, 3376, 3378, 3380, 3392, 3394, 3396, 3400, 3402,
 3404, 3405, 3406, 3408, 3409, 3410, 3412, 3414, 3430, 3462, 3478, 3510, 3542, 3574, 3606, 3670,
 3702, 3734, 3738, 3740, 3747, 3754, 3758, 3772, 3788, 3790, 3792, 3794, 3796, 3798, 3802, 3803,
 3816, 3823, 3827, 3829, 3831, 3863, 3871, 3872, 3873, 3877, 3879, 3881, 3885, 3887, 3889)

FPA_SEC_CNTS: tuple[int, ...] = (1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 15, 480, 16, 16, 16, 30, 30, 30,
 13, 12, 1, 390, 30, 360, 1, 1, 5, 5, 5, 5, 5, 32, 4, 4, 4, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
 3, 3, 10, 10, 10, 15, 15, 15, 15, 15, 15, 15, 1, 1, 13, 13, 6, 13, 240, 30, 30, 1, 30, 30, 30,
 30, 7, 1, 7, 7, 13, 13, 13, 1, 1, 1, 1, 7, 7, 7, 1, 1, 1, 1, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 1,
 2, 2, 2, 2, 2, 12, 2, 2, 2, 2, 1, 1, 1, 1, 1, 3, 3, 7, 7, 7, 1, 1, 10, 10, 10, 32, 32, 32, 32,
 32, 32, 32, 2, 1, 7, 7, 7, 7, 2, 2, 2, 7, 6, 1, 14, 2, 1, 2, 2, 2, 2, 2, 12, 2, 2, 2, 2, 1, 1,
 1, 1, 1, 1, 2, 2, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 2, 1, 7, 7, 4, 7, 16, 2, 2, 2, 2, 2,
 1, 1, 13, 7, 4, 2, 2, 16, 2, 1, 1, 1, 1, 1, 4, 2, 2, 195)

# 39-field bijection between ZDC #6 BE record (332 B) and firmware ROM LE struct (332 B)
BEM_ZDC_FIELDS: tuple[tuple[int, int, int, str, int, str, str], ...] = (
    (0, 9, 305, 'B', 9, 'phase_shift_y', '0.1 deg'),
    (9, 2, 272, 'H', 1, 'i_exc_offset', '1 mA'),
    (11, 1, 317, 'B', 1, 'n_series_diodes', 'count'),
    (12, 1, 295, 'b', 1, 'r_diode_tc', 'tempco'),
    (13, 2, 290, 'H', 1, 'u_diode_tc', '0.01 mV/K'),
    (15, 4, 4, 'I', 1, 'n_fe_ref', '0.6 RPM'),
    (19, 34, 182, 'H', 17, 'i_exc_axis_17', '1 mA'),
    (53, 36, 110, 'H', 18, 'i_exc_axis_18', '1 mA'),
    (89, 1, 294, 'b', 1, 'alpha0_offset', '0.1 deg'),
    (90, 1, 323, 'B', 1, 'alpha0_speed_slope', 'slope'),
    (91, 9, 296, 'B', 9, 'i_ph_axis_9', '1 A'),
    (100, 1, 318, 'B', 1, 'overlap_curr_span', '10 A'),
    (101, 102, 8, 'H', 51, 'l_sync_map', '1 uH'),
    (203, 1, 319, 'B', 1, 'm_gen_max_clamp', '0.5 Nm'),
    (204, 3, 314, 'B', 3, 'n_gen_axis_3', '100 RPM'),
    (207, 28, 244, 'H', 14, 'mech_loss_speed_x', '0.6 RPM'),
    (235, 1, 320, 'B', 1, 'p_gen_max_clamp', '50 W'),
    (236, 28, 216, 'H', 14, 'mech_loss_pwr_y', '1 W'),
    (264, 2, 274, 'H', 1, 'k_fe_loss', '1 W'),
    (266, 4, 0, 'I', 1, 'r_stator_20c', '0.01 mOhm'),
    (270, 2, 276, 'H', 1, 'r_exc_20c', '0.1 mOhm'),
    (272, 2, 278, 'H', 1, 'r_lead_contact', '0.01 mOhm'),
    (274, 2, 292, 'H', 1, 'r_diode_25c', '0.01 mOhm'),
    (276, 2, 280, 'H', 1, 't_cu_max_clamp', 'degC+100'),
    (278, 2, 282, 'H', 1, 't_cu_min_clamp', 'degC+100'),
    (280, 1, 321, 'B', 1, 'u_bplus_drop_fallback', '0.1 V'),
    (281, 1, 322, 'B', 1, 'u_reg_exc_drop', '0.1 V'),
    (282, 2, 284, 'H', 1, 'u_emf_const_offset', '1 mV'),
    (284, 2, 288, 'H', 1, 'psi_fe_ref', '0.1 mWb'),
    (286, 36, 146, 'H', 18, 'psi_rotor_curve_y', '0.1 mWb'),
    (322, 2, 286, 'H', 1, 'u_diode_25c', '1 mV'),
    (324, 1, 324, 'B', 1, 'k_comm_harm', '0.01'),
    (325, 1, 325, 'B', 1, 'n_stator_systems', 'count'),
    (326, 1, 326, 'B', 1, 'overlap_k_high', '0.1'),
    (327, 1, 327, 'B', 1, 'overlap_k_low', '0.1'),
    (328, 1, 328, 'b', 1, 'steinmetz_alpha', 'exp'),
    (329, 1, 329, 'b', 1, 'steinmetz_beta', 'exp'),
    (330, 1, 330, 'B', 1, 'half_pole_pairs', 'p/2'),
    (331, 1, 331, 'B', 1, 'rect_eff_pct', '%'),
)

_TEMPLATE_BLOBS_B85: dict[str, str] = {
    "MKE_86": (
    "c-pfto2J3f$il+N&u_yZpkT0Lp8*&Mfx!a?)>oy1j0{{1j0}tt(~S5TSw&bISeY0Z1_B5g6$43jMFvLp3k@IvV+M"
    "v4VMZ>S6AZ?z4h#%j0_+!9d4zyUF32zlaQXTg3&<z%|KX6+FtSOR#?Zj<meG*WgE56Mg@r+ZfsNU2qI@#|RPz__"
),
    "MKE_84": (
    "c-pftnWn+d$il+N&u_yZpkT0Lp8*&MfWZR>)>oy1j0{{1j0}tt(~S5TSw&bISeY0Z1_B5g6$9PDuE@a1exU&*V9d"
    "afBEiUDbArK`)q#P5i-Y+ED~|vJ1N#LT1_7=pUt<pW1pYr9avDZ9DbpAl7~V1(GI}tkFs86DC@`=wcl6Jl4ggF$7"
    "{&"
),
    "SSA_4C": (
    "c-rk#$x;(h6g}OY&U;BGWDa2pV-g^Q1Zap7hA@=ku+fELm7=1h<;E%}M9V4>9B|tE4etB{haX^Jm49Hla^=3gCx9"
    ";9y5Lp%)Oo|b_uTVd+y!$P>o5UWFdAPL9f<hr)(_*Ctg3I{fuL=ys2#QA{bS%mN63p}qSez-hQMe@;7~xI+D6tc5"
    "H!7aa4c^dj*nn_8FZT75;B&6<Ci0j5-_#w+Kjb>WDZ$~EKJr!h{!Y)73SIm#=5NQ@`%eUu1Saxc<yiqrNtzyrpe+"
    "0VO#1}8ccah8<nguBOx%x8ez?~w6OMOPj6Iw!g_;@kSU^m*&XKLaDZzWVabTFa#C1|(~%ToTLdOMS&|#I7#TNe79"
    "mJrgS9Shq{R}mSwxx{0mWF=@RTMhny4CmP^oGp?UD%9Ev!@^^a~UR1%?KA3pr2MNBg*u=T-EwP|*W)k6cAFJC9IM"
    "3mq!ZNk3#aO(zHFUyMfNs5DMvd%2NF$W1pTr7n6!WPs_doUk4U>rP98JiYP}+6b*FIXp$%vyM1aZ?r{0W`SK&v!Y"
    "x@;i^a&B9sWj)XWAA7B|iP7iL*fs8K_eDVKL{vxQpEZXbIQsv>gri1b@x(m5ubWzs$xn;R3zyKH|{01UIoJ>BJ2c"
    "Bj}|o8a2W-!({j7$QiXtNeQ`=@&jZ2b;zH8g(eC2CXrVfW`)b8c*P8Y$BwwCC>{_(WLPV5si<CYJ5UW<1^wKUyzV"
    "6wiV#Z4zf3g{)GbjB2|?vDPLKnplYFNVA4R%z?6Y$12Yz84a^%@02crJG#1l139MRJ&G!!u4OiR=r2|1H6n-9w#^"
    "Q-&D&0LfH@~oW<ml3|<0sCXT|RgI%GGPHZr-|m=kC3=`|FQizj?cI>Cwf@7p~vfdRQ1JmdYdJRm*4lGcB!c?H$?9"
    "+VsrqsnahXyx81+Z{T1YjDzuCjj!g~&)=PS9dZ"
),
    # factory FPA dataset of a 2019 Tiguan with 4MOTION Active Control (tag OZ00): the knob's input, switches and slots
    "FPA_OZ00_4MOTION_AC": (
    "c-"
    "rlk%}(Pm5Xb)>kCWhpHi|0Pk1i^RBUGro00%Ct&~6XxWiNZ#2iWK00_Q#OJX|Yr;u379Ep3UL1Z}$@^*4%>&cyL};u"
    ")vkf1aHDj-esY(c&QhLW1aEfrHcYANKqe>*e;g=f>?}!wT8Y3%GWVvk$BEhxV|Clrsbfkzp6D;1^oRNMj;?*ocUL#P"
    "m2sA4zhDE|@!*h<{u{OtZ|J1xZ#2bzEGN%0nU(Hr!N9hlG=|XIiU&L_kVO(l(`5wohedd+-"
    "aZB2tR1l=ZFh*%ErZ(#9VlHIepv6?(i{;WAcXv=t|<tb4S3+%H`iG(MWbGt!jE3A?r_>DXU3SI@fC>8t3uem!?yCr8"
    "hz*F4NFQg+VGW7V0C+nv!>r2KnEjYDRtkt-EWY3q1oEce1DBCuuE;bI}P8Ey&}!KG*LXqq@MJO5~847yg%=2QM-"
    "2>Roq9HiNzDVWScI8iQ0#noIQl`|L&XkeSt`ga8khkV6DTj4y}_2*R+Dt5NNSh~f%3MuH)Um%5HY4^6`_Ln5ewsjgy"
    "+WGkD^ZZ)mw)9&~2<05j-50r^I*ZiZmrph2x1m&DCl8k1;QMXY)#x9-"
    ";y00!@0=ojVy$np{(9a}^PB5p6N3#E|6#xNub%+Q5vZ^"
),
    "FPA_JC00_BASE": (
    "c-r%FHZVxxVBlh4WHjPu{KCY*zz)PB3}|2z!zdWWK=D5WFcGO<0E}n|m{`cy%fdmvwcPmSk@CfVrvGrjz)F!{N7E"
    "m*lJRH|jDisa7*PpkNWny8ISwknPz0D6nHU&9euNuG2q2Yz!w?L=QkmHYZ(1T0=gh3K_@r5x@rEWd<%#`2Za_>T1"
    "*`iH7s0NK0joGM`2ep1TzpWNf23j*5AQ5V9{>qIM!Lo(@#%RKkWx2}f>D4QELw4g833dVn*{"
),
    "FPA_PC00_FWD_DCC": (
    "c-rk&y-ve05I&#n#%W7iq6#_y3T?-#LP25$2}XtvFthLgOsu>H6OVv8v+xvbJOFDYCWeM{8bZ^=A(03_Qa;Ct<Ii"
    "WGFL&omj`#L18&C(vx^4Da1F#UF3vu-O`zPnHia{Sr#&kM$&!Ixu*d6)-1m=}E>H)arDYQeSBOIs!LhZ%}2R5Na#"
    "eoa*)jC*U)>Keo3ZO~Pray-vjH#{P?gOqx)c{0jAfmzuF`6M4lGYB}D19q18$4$325lP5Xf~?MPGLV6Ot4(>HRPP"
    "r49HbtuX<)gfkKF+tfZNxMAS9OeyQ_9E33Hd@42zGl-+1K&8^YFAn6#WokLMYvkRD<O3Si^a}||UB&XcP+Nz*zC("
    "^n2x^AemOGW(PXBcr<3cL!XfyHk;=+p^GhFuu;T0vS|32>db!u<9Yh)V=En?=)o1wX<snqV9z<ywk$aLG&zWcd6H"
    "Eq!%98msWY^U%{3(MzyrbWJ8gOwL4lWL*dMt5oimO7v%y!arp0_&JlEn<>ulv_3FpNJfYqcdG~Np%m@yR<Eg?wR("
    "ehaAUI<J8MLnn^`(TcpSx@-8UnTlLq7bs3(0Gr1s~DgUkV@ckPX{Z;XaN5t9EL3;VGj{hImxxk5gy+m#I}WaH`OP"
    "Q3%d_OnR"
),
    "FPA_NC00_AWD_DCC": (
    "c-rlj!EVz)5I|>UcVlP0xRzBB723)~J#Yw7l}bGni3=PMLMVsk%!Lo&5BLTCgg@X1_?k$ZxR}|o6P!ABZD>mod7J"
    "fmch;WW*_m<Py*xer5P=26*&co$00acE51Wj~XRj9i=8be0<1_Hx1>7<jBT6#3Q=%v$<8KK53!a?hg6Y2BkPiiKY"
    "dv%f$B;m(Qy6g>Kme(<F~#hwzP#tU9nA$n^8%+_9K>)Ut<#4h)9{t+cD)1?(FRp9lF|kO3+K--M40o>I(PKtn(Yh"
    ";$rSHHsw-{M=TQv#%BY%D%QL#5CN)DMQ|dK6UAelZp!TfgwUAL{S!(J2xUmVsVH6)uM$g=|?il2qgSci*4$z3+DE"
    "$b_qUG9;q@pz`M-sWaeia!N>&|{-zkkAnTp4x~ZhM+ptW>NygdMG*KUKulMJXBdd0acdWh9?3KNu7V`&V$I4{(?B"
    "gpu$6;M59=Qv@!T@{TUr^EH3b1k*Ap50bidR(VMb1g31)drMZ4BtdnR8AEa*n$<Gg<s4u>FVgO1Yixb24}ET%Z!4"
    "|6QBx_T^sU`*NRjBFmQ?=9=sk55qYKjqHll|IkCMmLZw*UTqtt)AuF%`r^Jcm@sm#mQBipCJ*6}WJ&^n>1?|pH3g"
    "GYQXLh>J{upi#(X?FML9UcF^9_(zeqn+2^p1$}AE+M7l"
),
    "BEM_2222": (
    "c-rlhT}V?=0LTCTbKREv;Hq2JET)AlvsQEs3LLaPp&%P&VLr^FRRmU6FZaPcI4UkBVITBRJ<MKwF*1l%Fbr}@1ep"
    "=|5JFLrQcw>WMLw+4`q<RBq#(HeALqWD|GC`ryN9D`nzqcALje^pGiJ<~F=NJzng2NY@l$a<TE8I(h;p<5Wexx_e"
    "C3#UuZ$MFv<zE^Y=bi%7N#AyUEONJZOm$!+{m9VzTh@ywq`pPyXx^(X+cG)m<mT}a1m|zfB~dM>NgD><2|0|L2hM"
    "`bCJOa?jy;&KRGOE<~}+0%jZt6VkHYOj9$IO8?=@e?sC*SJJnb2%F?~wE`N8;jnJ*lsom?^p4@~3PPm}LjZ&1shX"
    "B^&04~ud{AdSU=`B6baE=j#6)T`7Fdwzpj??Iq+g-{gUgsd+iej-ughZWa6njLol2qv_f?bJ5kLa=3v1oW&E`K%b"
    "y*ZzGE-hR<h1t^3QzUU&ZX%92J0=j~9NO^-FVK%3T)|1SO2a?s;5Iq0(N8a(1YYA2?tFibbQzeI%aR2V1631T2Cz"
    "vsy6}b-+`$vP#sQ9ST-b$2%oEk3MywPm=~De?E=9v+q?5B;AzilPko@uCymOg_pQ*E!7Cg(kY{SvKwa=x`M%HmPt"
    "LecP+3CYoocS9r7h)}%a1oEGa5*E4Gr=Sua7cc{JAULiGdY)kdN*wBG}e3rE;##O"
),
    "BEM_0101": (
    "c-rljYe-XZ7{;IHf1I0JbGj|lRkIsfmSs!2&>$rW>VrvT*gh<x*$wUb!9gu(l}b0d(T56>2r5XDuw`L(QA>hK3i="
    "SzjV@AAL01a2x0N-!5ES`o@54D9IL|q}|KI<84kv45*2q+Sr!;7^F_9h7idM9u6|HD>d->OI4ElXDC%XZaie-Sq1"
    "R#J9e65~qZ87(Ct+6-tEr!c+jiy@jQA?$*qSvw?9g+7FciAd>t`2*2MvL7!*yYx=em{$Ctl&`U@d8)TsOr9{kgs`"
    "xJ6Xc%bh8gS@EA=9@$6SE6%}*791G+;n-e&QF=$1--<sl%4aPN?PMTv9CfmxBnjOY;OSV1Nk(WC6P%yg&CiH+A7T"
    "Ayk2b{>nBrL)nI#n7r1LnqQ)o@`4z3^+XfTa=xFdhZiga%pe2+rX#w(yBcRKrz{%2OUSPZet+3+)MUHqGZ-?hgc3"
    "`ttvYWv9bf|D9(9OC5*(q+}s<10n2{MFbJ#wl2zHZyNCicX1Kb*oQK#7Q$b&jWguFi)l<@4+0Nx1*bm0M_6Y56H9"
    "Blw*rH^u*}3%aU8-U_TwyWU=^?OF+VD!va9|oLyb~nRh_W3bQ?=m_@ji$c8(F2o3TVTK0jhE!{R&oIi5P)3bR~`6"
    "%o(g5uP6AF_#&%<GpwqZ~$BX2g@Oth&kAeYt)!cFN3UPh|RnyO+4i*eq_gYmbJB8N{YOmf&yXb!WtQLom~BrVrP0"
    "&e8TCsth;19jM5X!l`NG;Ml+cTFL4joQ6mkO%Z@C8Pnz{ec#iXkcyeTB`!YsS`!wv@k1be-RVd{pQK<~a6k(htxl"
    "Tqq9*U<4XK(^lIPAAO|B!LLu#86ndZLe{Hv>gDFF)B$+BhvBO~7E7-XiTR{=$;Otmj}vzQm>;FBvcGFJu`H@-%Pr"
    "8Q-#9Y099?tO;j4Ui1C!clK42b>Jt~`u$q"
),
    "ROM_BEM_21": (
    "c-qZad303e9sS+kn;9VcG7u6V1jG;^AVd_EunDGsD3L{D${Gg<5JLcg2u2_T;Xr6X*|b_B;(}$Dy%8*ePz6O)5J3"
    "fsfRX|#pkmS9H*bba0%mgBlb+_D%s=zyn|b%UzkBcZ)`p7MgGE-V7lj_YiDxhh4<Z?j5D5nk7#7wVnMS78)?-+NS"
    "r~?HxDzo@oD=K)sYapJCqysf5Z>S_V=)-55ROYCk|$T>BF^a<<Am*~{h(uiwRfxUtg$U%bKtt56~RTJ^TV4-HyJ5"
    "^kuy>cshEUi*p7oZi=R+kof@r;w5e9Kj=9RrNJH%6kZMvxf+SSJC4s9BlZA3t3Q*rMs79Z_7lZy0+9+~JtyiO0#I"
    "L<|Q^(@_x(xnss>t0^)X60SkSd92Z)ilJY!hiN_JB}lY(i3UdgkzfecLBQMMXq6S4Zx8!zrO~hCvM10}heG0FjQ4"
    "Qsmm#*m~GD8oi9xM!ZIlwY^w{qxMob?biF}bibx)7yX8JyBW(Ir3i7a5@RdiRkJipFX9+>;I}xi7?>YEGxCX=Npi"
    "2aWU(BOK(xmgJjc)N<@(2P0ly$v!wLWE)F6K~C0goB6S-B|a(5QW1(^pJcN-ORnJD{vdAS^CWQ4Dl)xw2LE~8`HB"
    "u|?*`_c5CZCf>VHc$3)sm?H4UBlHdMkJ8`v-En*(N(wwC**bhjzZ~S^TkH;*j!IzHaZ{-$K_2~Cua-`aYmZPli$5"
    "qiB~Y5>S~G0a!}rpiaD4WnG=;(r>?Y=6qz8)<%k5J4F)0~OSn@<@hz^B%P5T{m;P1>q#lE*$VjOrF%nB*-6O;0If"
    "+HQR?KCg%<tFS&85gjqbM{-o)&J2SC{<<3>`Tly;IveOkEn}(m`F;3Y7rEHTq_Y%Qdzep}@$}OjN^3DZX}v#g>U;"
    "eO8AnbQ0q6lYA&~Mk&VVQ0nJrM5=>~KaUZ(gPd1}%K&L49c7}t!6}cSgN!4SyHSEV+FHA6KYrs273k8tN(ecuLk="
    "5DE2=Vu*YA`#JdII0(dLiK;`_W@7Ldza>XQq3xlBkM=yIi}rX)v1C#%iFWn`GiWxWuK%STWajp>0=u;IMyrQ%+a`"
    "SKzx%yA<P_fwI#BaTk`Pub6Fiex>!n1`8E><o-X2CusXwdtov<!$jln>kVSrJeMXC32ki{xAx$2}kfFLbZi<(jMA"
    "J({-@=-;+R2xT(hkPIx=%%Dvf2&lro&+Sf0aS-qk?T)Lzzmq{t<xrK}7&&ln3SAxkUyj;3<nG<1g>A>~)PR_|^vV"
    "%;{ky-rZWpNB^Fc%Zi9rbZl{!ShJ2rt5zJq|sO!`R6=&qqJzlO4w@#bqe9)QK~`Qcg%D9dih#qX--DF;3Ajf8d-u"
    "D#hi0KI5q=vE{fdDb?kkg?ZV-T>LY+RFg~Yb7Z*5<vx!tm*Ga}$m~5pmi|O+Ls<-`54NLztK)0=Kvob7QHm@K!b9"
    "Y_1HCd5Kgj2@i73y(^~sYHRZm(oeIA$B<dE2?=}AnV4fq_Fpc+8mh$gC*%eecKd}h3yUrxy{m@y-7^uW}J*ya|OW"
    "{$hL+!<_f>Fae~oZ+N4qg$Sr_vtpp>O~q;c?Y}Bqv*xPR2RR>Y1t(kWjid4BC;@)|HJtDF!^jmw>WBci%M|Wkp9+"
    "JX44U_$Sq8s)!2`35Y8FzsP}WiA7Lw~S}xc0O#1EY$t{?bpX=&l`K32|oNm8d8*KH<!|=skDzY}yd7CViKT1B`CP"
    "#*-7fUe#1E{&y2*Fu;<yI#BpNVQ}Vh8m+*K<XC)FacUsO`69Jt2M@QBG6{-7Q}>NQu<J?~sGVSjXS<HLjqVhH6cZ"
    "F8!?%ED_|e7D-58`gD=*vPT+WIdYA~emYS)bs6C1a*rIr&dAlK21@KTLLzF_Z`?9@`qXhF2lc+Ub313O)h{hB5o)"
    "-&b#7hGLwVdo$2=*2Wv0xMT*;Q7P>Kc2lxAo^&0e9SZfCQeC(~paEIdgDMsUV^qbt+tCg#ow{;uV+=!Sk-)-BWO*"
    "y)!&c<pgXpsttTeNJ~GQ>VWU(`+5Dc{;g@b=jk*)1%9P8~CO9x8?O^MG>*dYPbB--HB|jvjG;D15h3z_?#{EMVTp"
    "+WQ=4=E0l*FpR!lJDhp(?JSHQg6TE1QI{bzj2tbK^#Qj*uYi98NE5l_BlgA}5vk}FkKlgMu6Q_Z8W`g%umyXoYI#"
    "w%M=fCflPj&TXPqA7vUQ+*Bj^`K7Eu21j&;wn4vd7(tY_4wttr?Hk@;F956X|oOJoDL1eX#(URNMjf&gJB3l8hx1"
    ")kM7R!xmZXMzL(>Cts33P}we`GBe&(hRQNIDGl6>Xgf~wv=c_R?89!EL5CSe_~+8$?nE`+h>@G<8#a2*M6@t+{LJ"
    "`xai)5?Jc8GP@;Kuq&fn(J>E_ZFT&m0KnVgGQI_6d;_!O#clpij$B*VjHq8`9DH~Z`5Z?c82uXBybblj1Z(q#*#c"
    "sBRpJ88*&`ZC+4O>g5|uhLDri+E4>{m*n+e#R@-<spZ~Wdr!4HraTE4wywJPUXFscmrNEz%NYhPkAO>!45x_iX1M"
    "3h>bAuFq*IhDck8+@(K51nfnBq=SF38>6H8E2gPzp8lor9<BQm1cjGHI+JCVX1!)-JKYJYHAw<G>Dv#zls)_VxM%"
    "H8dxT*sTe_ZBdEcBem*P|%(NxGLLdHgatH9dRAoWg=!SE@IAoY!*vg+PnT@=g3Aby=IbThHv7A=8Puu&~49r)JV$"
    "m5<rwSJF|;Dfj(!0dwO4=6EE2l%s4+%h?BJR7#h%<TiGq1@zg5+?QGGmWL5SwRiBGdNMS#igkIsyZ7Alu2I%6eYr"
    "Hx<2H{jo$hnbv}lXV@md}`@De7YExY)4%<BCTq`vrw`h1=}dI(Q6QB3nM$f{Gl*n=(Xg-eNf$isuUi!JoLoELx3%"
    "1l0+xu1?L<qkOMa8Izu?8mnV(l~9YcWH|DV!y509PgTzR4#jb`lTyp{J89l-YIR&9M>}aGT(FVIj3b2uicqEQTU$"
    "v*hbeYlDg`}4&GrOv|%f%1z}PjVv}D*c)j#Ps`vLihu_0%lDJ9;F32$^{+pHJGEq`wFn!@Y`9)eF9aFfcZ{bsvaK"
    "^*6p5DxFs9G*JKbYX*a;R}5E^~9UdUt8#`<%$qW%cS-j*oS>>)YK=Auh1nnbW<{-D9$uzXR!;tJ#^CyJtI*4ctbY"
    "bzilFr}b%^@d>h<zBYj>>_#=W<XNXSef29|vx_WlpcA}SDZdP$L+5k<E=UM}PbQvX_uq;y$mL}wx}nuISk1k!Xbo"
    "3%HF9bCWlgCo4W+3JVGf347w$Cj{P^WSpXZnB@m9n&zqB3&Z{9rT(INfQ`}TFlCi`@Cu^X<&o@X0rS{@fUpKY*_`"
    ";<-pO7%HITKECE<jjuGWQ{z}1RCSB#+OuPI+fW8P2r?te#Tz4l+CCzx@;nyc|Qwz#y5Df8i0HhG12zmAil&|e2<^"
    ";E2>tPGY2G8Fyo_h^YX^JQj<+x+RNzD%Vi?Uqc%=+zBjVZ6jCSo*Rsb#N4D_*T;lA$<L2@yc|uB4t2f_ILOh}oL>"
    "D+I`{)wpI+fwFInR5;c>*{kan$&9tmMh(G#Lz_4>!=JdaK@{|DRl5NU*rf!1d_KT)By-mkV;3bJ{|E5k}pf#0N~E"
    "$2rqY5KQb-FBa=0Ho_6wjd>BNpU@rVFh{zhGSA$Cq^0zhXPG^9k>>6V=h)Q~xK=+V_!yn2)2sOT<&j?A?1`~i{ql"
    "0@8S<HVv!^`vP;yd&Z@;V=VsiO!%J%$<"
),
}

@lru_cache(maxsize=16)
def get_zdc_template_bytes(name: str) -> bytes:
    """Decompress and return an immutable stock ZDC template or ROM table by key."""
    raw_b85 = _TEMPLATE_BLOBS_B85[name]
    return zlib.decompress(base64.b85decode(raw_b85))


@lru_cache(maxsize=1)
def get_rom_bem_records() -> tuple[bytes, ...]:
    """Return the 21 factory 332-byte LE LIN alternator records compiled in J533 firmware."""
    blob = get_zdc_template_bytes("ROM_BEM_21")
    return tuple(blob[i * 332 : (i + 1) * 332] for i in range(21))


# 21 factory LIN 14V alternator models indexed by ROM_REC[0..20]
# Tuple: (rom_idx, default_supplier_id, default_class_id, nominal_amps, rectifier, poles, phases, ru, en)
ROM_BEM_CATALOG: tuple[tuple[int, int, int, int, str, int, int, str, str], ...] = (
    (0, 0x07, 0x12, 110, "PN", 12, 3, "Denso / SEG — 110 А (стандартный)", "Denso / SEG — 110 A (standard)"),
    (1, 0x07, 0x02, 110, "PN", 12, 6, "Denso / SEG — 110 А (6-фазный)", "Denso / SEG — 110 A (6-phase)"),
    (2, 0x00, 0x12, 110, "PN", 12, 3, "Valeo — 110 А (исполнение B)", "Valeo — 110 A (variant B)"),
    (3, 0x00, 0x01, 90, "PN", 12, 3, "Valeo — 90 А", "Valeo — 90 A"),
    (4, 0x01, 0x0D, 150, "MOSFET", 12, 3, "Bosch — 150 А (активный выпрямитель MOSFET)", "Bosch — 150 A (MOSFET)"),
    (5, 0x01, 0x0E, 180, "MOSFET", 12, 6, "Bosch — 180 А (6-фазный MOSFET)", "Bosch — 180 A (6-phase MOSFET)"),
    (6, 0x00, 0x02, 110, "PN", 12, 3, "Valeo — 110 А (базовый)", "Valeo — 110 A (standard)"),
    (7, 0x00, 0x03, 140, "PN", 12, 3, "Valeo — 140 А (базовый)", "Valeo — 140 A (standard)"),
    (8, 0x00, 0x14, 140, "HED", 12, 3, "Valeo — 140 А (высокоэффективный HED)", "Valeo — 140 A (high-efficiency HED)"),
    (9, 0x00, 0x0D, 150, "MOSFET", 16, 3, "Valeo — 150 А (MOSFET)", "Valeo — 150 A (MOSFET)"),
    (10, 0x00, 0x05, 180, "PN", 16, 3, "Valeo — 180 А (стандартный)", "Valeo — 180 A (standard)"),
    (11, 0x00, 0x15, 180, "HED", 16, 3, "Valeo — 180 А (высокоэффективный HED)", "Valeo — 180 A (high-efficiency HED)"),
    (12, 0x00, 0x11, 250, "MOSFET", 16, 3, "Valeo — 250 А (усиленный MOSFET)", "Valeo — 250 A (heavy-duty MOSFET)"),
    (13, 0x01, 0x15, 180, "HED", 12, 3, "Bosch — 180 А (высокоэффективный HED)", "Bosch — 180 A (high-efficiency HED)"),
    (14, 0x01, 0x09, 180, "PN", 12, 3, "Bosch — 180 А (стандартный)", "Bosch — 180 A (standard)"),
    (15, 0x01, 0x12, 110, "PN", 12, 3, "Bosch — 110 А (исполнение B)", "Bosch — 110 A (variant B)"),
    (16, 0x01, 0x02, 110, "PN", 12, 3, "Bosch — 110 А (базовый)", "Bosch — 110 A (standard)"),
    (17, 0x01, 0x14, 140, "HED", 12, 3, "Bosch — 140 А (высокоэффективный HED)", "Bosch — 140 A (high-efficiency HED)"),
    (18, 0x01, 0x13, 140, "PN", 12, 3, "Bosch — 140 А (модернизированный)", "Bosch — 140 A (revised)"),
    (19, 0x01, 0x03, 140, "PN", 12, 3, "Bosch — 140 А (базовый)", "Bosch — 140 A (standard)"),
    (20, 0x01, 0x01, 90, "PN", 12, 3, "Bosch — 90 А", "Bosch — 90 A"),
)

BEM_SUPPLIER_NAMES: dict[int, tuple[str, str]] = {
    0x00: ("Valeo", "Valeo"),
    0x01: ("Bosch", "Bosch"),
    0x02: ("Hitachi / Mitsubishi", "Hitachi / Mitsubishi"),
    0x03: ("Denso / SEG", "Denso / SEG"),
    0x07: ("Не задан", "Unassigned"),
}

FPA_PROFILE_NAMES: dict[int, tuple[str, str]] = {
    0x00: ("Отключён", "Disabled"),
    0x01: ("Comfort (Комфорт)", "Comfort"),
    0x02: ("Normal (Обычный)", "Normal"),
    0x03: ("Sport (Спорт)", "Sport"),
    0x04: ("Offroad (Бездорожье)", "Offroad"),
    0x05: ("Eco (Эко)", "Eco"),
    0x06: ("Race / Cupra (Гонка)", "Race / Cupra"),
    0x07: ("Individual (Индивидуальный)", "Individual"),
    0x08: ("Offroad Individual", "Offroad Individual"),
    0x09: ("Snow / Allroad (Снег)", "Snow / Allroad"),
    0x0A: ("Snow (Снег)", "Snow"),
    0x0B: ("Offroad Individual", "Offroad Individual"),  # Tiguan OZ00: knob position 4, cluster code 0x12
    0x0C: ("GTE / Hybrid (Гибрид)", "GTE / Hybrid"),
    0x14: ("Базовый Normal (без выбора профилей)", "Passive Normal (no FPA)"),
    0x36: ("Шайба 4Motion: Дорога / Снег", "4Motion Rotary: Snow / Onroad"),
    0x3A: ("Шайба 4Motion: Offroad Individual", "4Motion Rotary: Offroad Individual"),
    0x3B: ("Шайба 4Motion: Бездорожье", "4Motion Rotary: Offroad"),
}

# Canonical defaults per Inst0 FPA slot 1..12: (bap_profile_id, fec_code, kombi_icon, s074_flags, name_ru, name_en)
# Note: FeC 0x10001900 unlocks Inst0 slots 9..12; FeC 0x10001A00/1B00 map to Inst1 S153[1..2] below.
FPA_SLOT_DEFAULTS: dict[int, tuple[int, int, int, int, str, str]] = {
    1: (0x01, 0x10001100, 0x01, 0x0001, "Comfort (Комфорт)", "Comfort"),
    2: (0x02, 0x10001200, 0x02, 0x0000, "Normal (Обычный)", "Normal"),
    3: (0x03, 0x10001300, 0x03, 0x0001, "Sport (Спорт)", "Sport"),
    4: (0x04, 0x10001400, 0x04, 0x0005, "Offroad (Бездорожье)", "Offroad"),
    5: (0x05, 0x10001500, 0x05, 0x0001, "Eco (Эко)", "Eco"),
    6: (0x06, 0x10001600, 0x07, 0x0001, "Race / Cupra (Гонка)", "Race / Cupra"),
    7: (0x07, 0x10001700, 0x06, 0x0000, "Individual (Индивидуальный)", "Individual"),
    8: (0x0A, 0x10001800, 0x10, 0x0001, "Snow (Снег)", "Snow"),
    9: (0x0B, 0x10001900, 0x12, 0x0005, "Offroad Individual", "Offroad Individual"),  # as in the Tiguan OZ00
    10: (0x36, 0x00000000, 0x00, 0x0000, "Шайба 4Motion (Снег / Трасса)", "4Motion Rotary (Snow / Onroad)"),
    11: (0x3B, 0x00000000, 0x00, 0x0000, "Шайба 4Motion (Бездорожье)", "4Motion Rotary (Offroad)"),
    12: (0x3A, 0x00000000, 0x06, 0x0005, "Шайба 4Motion (Offroad Индив.)", "4Motion Rotary (Offroad Indiv.)"),
}

# Canonical defaults per Inst1 secondary EV/Hybrid slot 1..2 (S153[1..2]): (bap_profile_id, fec_code, name_ru, name_en)
FPA_INST1_SLOT_DEFAULTS: dict[int, tuple[int, int, str, str]] = {
    1: (0x0B, 0x10001A00, "EV / E-Mode (Электро)", "EV / E-Mode"),
    2: (0x0C, 0x10001B00, "GTE / Hybrid (Гибрид)", "GTE / Hybrid"),
}

FPA_SG_CATALOG: dict[int, tuple[str, str]] = {
    0x01: ("Двигатель (отклик педали газа)", "Engine / Throttle Response"),
    0x02: ("Система Старт-Стоп", "Start-Stop System"),
    0x03: ("Коробка передач DSG / АКПП", "Gearbox DSG / AT"),
    0x04: ("Задний межколёсный дифференциал (EDS)", "Rear Differential Lock (EDS)"),
    0x05: ("Рулевое управление (усилие на руле)", "Power Steering"),
    0x06: ("Прогрессивное / динамическое рулевое", "Progressive / Dynamic Steering"),
    0x07: ("Адаптивная подвеска (DCC)", "Adaptive Chassis (DCC)"),
    0x08: ("Климат-контроль (Climatronic)", "Air Conditioning (Climatronic)"),
    0x09: ("Адаптивный круиз-контроль (ACC)", "Adaptive Cruise Control (ACC)"),
    0x0A: ("Имитатор звука двигателя (Soundaktor)", "Interior Engine Sound (Soundaktor)"),
    0x0B: ("Адаптивное освещение и поворотный свет (AFS)", "Adaptive Front Lighting (AFS)"),
    0x0C: ("Фоновая подсветка салона (Ambiente)", "Ambient Lighting"),
    0x0D: ("Пневмоподвеска", "Air Suspension"),
    0x0E: ("Преднатяжители ремней безопасности", "Seatbelt Pre-Tensioners"),
    0x0F: ("Боковая поддержка сидений", "Seat Bolster Support"),
    0x12: ("Движение накатом КПП (Freilauf)", "Freewheeling / DSG Coasting"),
    0x13: ("Подсказки экономичного вождения (Eco)", "Eco Driving Tips"),
    0x14: ("Внешний генератор звука выхлопа", "Exterior Exhaust Sound"),
    0x15: ("Блокировка переднего дифференциала (VAQ)", "Front Differential Lock (VAQ)"),
    0x16: ("Межосевой дифференциал", "Center Differential Lock"),
    0x17: ("Полный привод 4Motion (муфта Haldex)", "4Motion AWD (Haldex)"),
    0x1A: ("Матричные фары (Matrix LED)", "Matrix LED Headlights"),
    0x1B: ("Задний спойлер", "Rear Spoiler"),
    0x1C: ("Система курсовой устойчивости (ESC)", "Electronic Stability Control (ESC)"),
    0x20: ("Гибридный привод", "Hybrid Drive"),
    0x21: ("Силовой агрегат (ДВС + КПП)", "Powertrain (Engine + Gearbox)"),
    0x22: ("Шасси (группа)", "Chassis (Group)"),
    0x23: ("Заслонка выхлопной системы", "Exhaust Flap"),
    0x24: ("Звук двигателя (салон + выхлоп)", "Engine Sound"),
    0x2A: ("Подвеска Magnetic Ride", "Magnetic Ride Suspension"),
    0x2B: ("Подвеска Sport Select", "Sport Select Suspension"),
    0x2C: ("Ассистент спуска с горы (HDC)", "Hill Descent Control (HDC)"),
    0x2D: ("Ассистент трогания на подъёме (HHC)", "Hill Hold Control (HHC)"),
    0x2E: ("Парковочный ассистент (PDC)", "Park Distance Control (PDC)"),
    0x33: ("Звук электромобиля (e-Sound)", "Electric Vehicle Sound (e-Sound)"),
    0x36: ("Электроусилитель тормозов (eBKV)", "Electric Brake Booster (eBKV)"),
    0x3A: ("Распределение тяги (Torque Splitter)", "Torque Splitter"),
    0x3B: ("Рекуперация энергии", "Energy Recuperation"),
    0x4C: ("Движение накатом (вкл. по умолчанию)", "Freewheeling (Default ON)"),
}

FPA_TARGET_MODE_NAMES: dict[int, tuple[str, str]] = {
    0: ("Не задействован", "Off / Unused"),
    1: ("Comfort (Комфорт)", "Comfort"),
    2: ("Normal (Стандарт)", "Normal"),
    3: ("Sport (Спорт)", "Sport"),
    4: ("Offroad (Бездорожье)", "Offroad"),
    5: ("Eco (Эко)", "Eco"),
    6: ("Race / Cupra (Гонка)", "Race / Cupra"),
    7: ("Individual", "Individual"),
    8: ("Вкл (On)", "On"),
    9: ("Выкл (Off)", "Off"),
    10: ("Snow (Снег)", "Snow"),
}

# Steering-wheel LIN MFL_Tastencode presets (DID 0x1F07 byte 1)
MFL_KEYCODE_PRESETS: tuple[tuple[int, str, str], ...] = (
    (0x19, "Голосовое управление / Микрофон (рекомендуется)", "Voice Control / Mic (recommended)"),
    (0x23, "Кнопка VIEW (смена вида приборки)", "VIEW button (cluster view)"),
    (0x74, "Кнопка меню ассистентов на руле", "Assistants menu button on wheel"),
    (0x2B, "Кнопка обогрева руля", "Steering-wheel heating button"),
    (0x2A, "Кнопка R / Звёздочка (Joker)", "R / Star / Joker button"),
)
