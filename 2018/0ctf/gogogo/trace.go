Entering main.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = fmt.init()
Entering fmt.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = strconv.init()
Entering strconv.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = math.init()
Entering math.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = internal/cpu.init()
Entering internal/cpu.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = init#1()
Entering internal/cpu.init#1 at /usr/local/Cellar/go/1.9.2/libexec/src/internal/cpu/cpu_x86.go:17:6.
.0:
	 t0 = cpuid(0:uint32, 0:uint32)
Entering internal/cpu.cpuid at /usr/local/Cellar/go/1.9.2/libexec/src/internal/cpu/cpu_x86.go:12:6.
	(external)
Leaving internal/cpu.cpuid, resuming internal/cpu.init#1 at /usr/local/Cellar/go/1.9.2/libexec/src/internal/cpu/cpu_x86.go:18:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = extract t0 #3
	 t5 = t1 < 1:uint32
	 if t5 goto 1 else 2
.1:
	 return
Leaving internal/cpu.init#1, resuming internal/cpu.init.
	 jump 2
.2:
	 return
Leaving internal/cpu.init, resuming math.init.
	 t2 = unsafe.init()
Entering unsafe.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 jump 2
.2:
	 return
Leaving unsafe.init, resuming math.init.
	 t3 = &internal/cpu.X86.HasSSE41 [#13]
	 t4 = *t3
	 *useSSE41 = t4
	 t5 = &_gamP[0:int]
	 t6 = &_gamP[1:int]
	 t7 = &_gamP[2:int]
	 t8 = &_gamP[3:int]
	 t9 = &_gamP[4:int]
	 t10 = &_gamP[5:int]
	 t11 = &_gamP[6:int]
	 *t5 = 0.00016012:float64
	 *t6 = 0.00119135:float64
	 *t7 = 0.0104214:float64
	 *t8 = 0.0476368:float64
	 *t9 = 0.207448:float64
	 *t10 = 0.494215:float64
	 *t11 = 1:float64
	 t12 = &_gamQ[0:int]
	 t13 = &_gamQ[1:int]
	 t14 = &_gamQ[2:int]
	 t15 = &_gamQ[3:int]
	 t16 = &_gamQ[4:int]
	 t17 = &_gamQ[5:int]
	 t18 = &_gamQ[6:int]
	 t19 = &_gamQ[7:int]
	 *t12 = -2.31582e-05:float64
	 *t13 = 0.000539606:float64
	 *t14 = -0.00445642:float64
	 *t15 = 0.011814:float64
	 *t16 = 0.0358236:float64
	 *t17 = -0.234592:float64
	 *t18 = 0.0714305:float64
	 *t19 = 1:float64
	 t20 = &_gamS[0:int]
	 t21 = &_gamS[1:int]
	 t22 = &_gamS[2:int]
	 t23 = &_gamS[3:int]
	 t24 = &_gamS[4:int]
	 *t20 = 0.000787311:float64
	 *t21 = -0.00022955:float64
	 *t22 = -0.00268133:float64
	 *t23 = 0.00347222:float64
	 *t24 = 0.0833333:float64
	 t25 = &p0R8[0:int]
	 t26 = &p0R8[1:int]
	 t27 = &p0R8[2:int]
	 t28 = &p0R8[3:int]
	 t29 = &p0R8[4:int]
	 t30 = &p0R8[5:int]
	 *t25 = 0:float64
	 *t26 = -0.0703125:float64
	 *t27 = -8.08167:float64
	 *t28 = -257.063:float64
	 *t29 = -2485.22:float64
	 *t30 = -5253.04:float64
	 t31 = &p0S8[0:int]
	 t32 = &p0S8[1:int]
	 t33 = &p0S8[2:int]
	 t34 = &p0S8[3:int]
	 t35 = &p0S8[4:int]
	 *t31 = 116.534:float64
	 *t32 = 3833.74:float64
	 *t33 = 40597.9:float64
	 *t34 = 116753:float64
	 *t35 = 47627.7:float64
	 t36 = &p0R5[0:int]
	 t37 = &p0R5[1:int]
	 t38 = &p0R5[2:int]
	 t39 = &p0R5[3:int]
	 t40 = &p0R5[4:int]
	 t41 = &p0R5[5:int]
	 *t36 = -1.14125e-11:float64
	 *t37 = -0.0703125:float64
	 *t38 = -4.15961:float64
	 *t39 = -67.6748:float64
	 *t40 = -331.231:float64
	 *t41 = -346.433:float64
	 t42 = &p0S5[0:int]
	 t43 = &p0S5[1:int]
	 t44 = &p0S5[2:int]
	 t45 = &p0S5[3:int]
	 t46 = &p0S5[4:int]
	 *t42 = 60.7539:float64
	 *t43 = 1051.25:float64
	 *t44 = 5978.97:float64
	 *t45 = 9625.45:float64
	 *t46 = 2406.06:float64
	 t47 = &p0R3[0:int]
	 t48 = &p0R3[1:int]
	 t49 = &p0R3[2:int]
	 t50 = &p0R3[3:int]
	 t51 = &p0R3[4:int]
	 t52 = &p0R3[5:int]
	 *t47 = -2.54705e-09:float64
	 *t48 = -0.070312:float64
	 *t49 = -2.40903:float64
	 *t50 = -21.966:float64
	 *t51 = -58.0792:float64
	 *t52 = -31.4479:float64
	 t53 = &p0S3[0:int]
	 t54 = &p0S3[1:int]
	 t55 = &p0S3[2:int]
	 t56 = &p0S3[3:int]
	 t57 = &p0S3[4:int]
	 *t53 = 35.856:float64
	 *t54 = 361.514:float64
	 *t55 = 1193.61:float64
	 *t56 = 1128:float64
	 *t57 = 173.581:float64
	 t58 = &p0R2[0:int]
	 t59 = &p0R2[1:int]
	 t60 = &p0R2[2:int]
	 t61 = &p0R2[3:int]
	 t62 = &p0R2[4:int]
	 t63 = &p0R2[5:int]
	 *t58 = -8.87534e-08:float64
	 *t59 = -0.0703031:float64
	 *t60 = -1.45074:float64
	 *t61 = -7.6357:float64
	 *t62 = -11.1932:float64
	 *t63 = -3.23365:float64
	 t64 = &p0S2[0:int]
	 t65 = &p0S2[1:int]
	 t66 = &p0S2[2:int]
	 t67 = &p0S2[3:int]
	 t68 = &p0S2[4:int]
	 *t64 = 22.2203:float64
	 *t65 = 136.207:float64
	 *t66 = 270.47:float64
	 *t67 = 153.875:float64
	 *t68 = 14.6576:float64
	 t69 = &q0R8[0:int]
	 t70 = &q0R8[1:int]
	 t71 = &q0R8[2:int]
	 t72 = &q0R8[3:int]
	 t73 = &q0R8[4:int]
	 t74 = &q0R8[5:int]
	 *t69 = 0:float64
	 *t70 = 0.0732422:float64
	 *t71 = 11.7682:float64
	 *t72 = 557.673:float64
	 *t73 = 8859.2:float64
	 *t74 = 37014.6:float64
	 t75 = &q0S8[0:int]
	 t76 = &q0S8[1:int]
	 t77 = &q0S8[2:int]
	 t78 = &q0S8[3:int]
	 t79 = &q0S8[4:int]
	 t80 = &q0S8[5:int]
	 *t75 = 163.776:float64
	 *t76 = 8098.34:float64
	 *t77 = 142538:float64
	 *t78 = 803309:float64
	 *t79 = 840502:float64
	 *t80 = -343899:float64
	 t81 = &q0R5[0:int]
	 t82 = &q0R5[1:int]
	 t83 = &q0R5[2:int]
	 t84 = &q0R5[3:int]
	 t85 = &q0R5[4:int]
	 t86 = &q0R5[5:int]
	 *t81 = 1.84086e-11:float64
	 *t82 = 0.0732422:float64
	 *t83 = 5.83564:float64
	 *t84 = 135.112:float64
	 *t85 = 1027.24:float64
	 *t86 = 1989.98:float64
	 t87 = &q0S5[0:int]
	 t88 = &q0S5[1:int]
	 t89 = &q0S5[2:int]
	 t90 = &q0S5[3:int]
	 t91 = &q0S5[4:int]
	 t92 = &q0S5[5:int]
	 *t87 = 82.7766:float64
	 *t88 = 2077.81:float64
	 *t89 = 18847.3:float64
	 *t90 = 56751.1:float64
	 *t91 = 35976.8:float64
	 *t92 = -5354.34:float64
	 t93 = &q0R3[0:int]
	 t94 = &q0R3[1:int]
	 t95 = &q0R3[2:int]
	 t96 = &q0R3[3:int]
	 t97 = &q0R3[4:int]
	 t98 = &q0R3[5:int]
	 *t93 = 4.37741e-09:float64
	 *t94 = 0.0732411:float64
	 *t95 = 3.34423:float64
	 *t96 = 42.6218:float64
	 *t97 = 170.808:float64
	 *t98 = 166.734:float64
	 t99 = &q0S3[0:int]
	 t100 = &q0S3[1:int]
	 t101 = &q0S3[2:int]
	 t102 = &q0S3[3:int]
	 t103 = &q0S3[4:int]
	 t104 = &q0S3[5:int]
	 *t99 = 48.7589:float64
	 *t100 = 709.689:float64
	 *t101 = 3704.15:float64
	 *t102 = 6460.43:float64
	 *t103 = 2516.33:float64
	 *t104 = -149.247:float64
	 t105 = &q0R2[0:int]
	 t106 = &q0R2[1:int]
	 t107 = &q0R2[2:int]
	 t108 = &q0R2[3:int]
	 t109 = &q0R2[4:int]
	 t110 = &q0R2[5:int]
	 *t105 = 1.50444e-07:float64
	 *t106 = 0.0732234:float64
	 *t107 = 1.99819:float64
	 *t108 = 14.4956:float64
	 *t109 = 31.6662:float64
	 *t110 = 16.2527:float64
	 t111 = &q0S2[0:int]
	 t112 = &q0S2[1:int]
	 t113 = &q0S2[2:int]
	 t114 = &q0S2[3:int]
	 t115 = &q0S2[4:int]
	 t116 = &q0S2[5:int]
	 *t111 = 30.3656:float64
	 *t112 = 269.348:float64
	 *t113 = 844.784:float64
	 *t114 = 882.936:float64
	 *t115 = 212.666:float64
	 *t116 = -5.31095:float64
	 t117 = &p1R8[0:int]
	 t118 = &p1R8[1:int]
	 t119 = &p1R8[2:int]
	 t120 = &p1R8[3:int]
	 t121 = &p1R8[4:int]
	 t122 = &p1R8[5:int]
	 *t117 = 0:float64
	 *t118 = 0.117187:float64
	 *t119 = 13.2395:float64
	 *t120 = 412.052:float64
	 *t121 = 3874.75:float64
	 *t122 = 7914.48:float64
	 t123 = &p1S8[0:int]
	 t124 = &p1S8[1:int]
	 t125 = &p1S8[2:int]
	 t126 = &p1S8[3:int]
	 t127 = &p1S8[4:int]
	 *t123 = 114.207:float64
	 *t124 = 3650.93:float64
	 *t125 = 36956.2:float64
	 *t126 = 97602.8:float64
	 *t127 = 30804.3:float64
	 t128 = &p1R5[0:int]
	 t129 = &p1R5[1:int]
	 t130 = &p1R5[2:int]
	 t131 = &p1R5[3:int]
	 t132 = &p1R5[4:int]
	 t133 = &p1R5[5:int]
	 *t128 = 1.31991e-11:float64
	 *t129 = 0.117187:float64
	 *t130 = 6.80275:float64
	 *t131 = 108.308:float64
	 *t132 = 517.636:float64
	 *t133 = 528.715:float64
	 t134 = &p1S5[0:int]
	 t135 = &p1S5[1:int]
	 t136 = &p1S5[2:int]
	 t137 = &p1S5[3:int]
	 t138 = &p1S5[4:int]
	 *t134 = 59.2806:float64
	 *t135 = 991.401:float64
	 *t136 = 5353.27:float64
	 *t137 = 7844.69:float64
	 *t138 = 1504.05:float64
	 t139 = &p1R3[0:int]
	 t140 = &p1R3[1:int]
	 t141 = &p1R3[2:int]
	 t142 = &p1R3[3:int]
	 t143 = &p1R3[4:int]
	 t144 = &p1R3[5:int]
	 *t139 = 3.02504e-09:float64
	 *t140 = 0.117187:float64
	 *t141 = 3.93298:float64
	 *t142 = 35.1194:float64
	 *t143 = 91.055:float64
	 *t144 = 48.5591:float64
	 t145 = &p1S3[0:int]
	 t146 = &p1S3[1:int]
	 t147 = &p1S3[2:int]
	 t148 = &p1S3[3:int]
	 t149 = &p1S3[4:int]
	 *t145 = 34.7913:float64
	 *t146 = 336.762:float64
	 *t147 = 1046.87:float64
	 *t148 = 890.811:float64
	 *t149 = 103.788:float64
	 t150 = &p1R2[0:int]
	 t151 = &p1R2[1:int]
	 t152 = &p1R2[2:int]
	 t153 = &p1R2[3:int]
	 t154 = &p1R2[4:int]
	 t155 = &p1R2[5:int]
	 *t150 = 1.07711e-07:float64
	 *t151 = 0.117176:float64
	 *t152 = 2.36851:float64
	 *t153 = 12.2426:float64
	 *t154 = 17.694:float64
	 *t155 = 5.07352:float64
	 t156 = &p1S2[0:int]
	 t157 = &p1S2[1:int]
	 t158 = &p1S2[2:int]
	 t159 = &p1S2[3:int]
	 t160 = &p1S2[4:int]
	 *t156 = 21.4365:float64
	 *t157 = 125.29:float64
	 *t158 = 232.276:float64
	 *t159 = 117.679:float64
	 *t160 = 8.36464:float64
	 t161 = &q1R8[0:int]
	 t162 = &q1R8[1:int]
	 t163 = &q1R8[2:int]
	 t164 = &q1R8[3:int]
	 t165 = &q1R8[4:int]
	 t166 = &q1R8[5:int]
	 *t161 = 0:float64
	 *t162 = -0.102539:float64
	 *t163 = -16.2718:float64
	 *t164 = -759.602:float64
	 *t165 = -11849.8:float64
	 *t166 = -48438.5:float64
	 t167 = &q1S8[0:int]
	 t168 = &q1S8[1:int]
	 t169 = &q1S8[2:int]
	 t170 = &q1S8[3:int]
	 t171 = &q1S8[4:int]
	 t172 = &q1S8[5:int]
	 *t167 = 161.395:float64
	 *t168 = 7825.39:float64
	 *t169 = 133875:float64
	 *t170 = 719658:float64
	 *t171 = 666601:float64
	 *t172 = -294490:float64
	 t173 = &q1R5[0:int]
	 t174 = &q1R5[1:int]
	 t175 = &q1R5[2:int]
	 t176 = &q1R5[3:int]
	 t177 = &q1R5[4:int]
	 t178 = &q1R5[5:int]
	 *t173 = -2.0898e-11:float64
	 *t174 = -0.102539:float64
	 *t175 = -8.05645:float64
	 *t176 = -183.67:float64
	 *t177 = -1373.19:float64
	 *t178 = -2612.44:float64
	 t179 = &q1S5[0:int]
	 t180 = &q1S5[1:int]
	 t181 = &q1S5[2:int]
	 t182 = &q1S5[3:int]
	 t183 = &q1S5[4:int]
	 t184 = &q1S5[5:int]
	 *t179 = 81.2766:float64
	 *t180 = 1991.8:float64
	 *t181 = 17468.5:float64
	 *t182 = 49851.4:float64
	 *t183 = 27948.1:float64
	 *t184 = -4719.18:float64
	 t185 = &q1R3[0:int]
	 t186 = &q1R3[1:int]
	 t187 = &q1R3[2:int]
	 t188 = &q1R3[3:int]
	 t189 = &q1R3[4:int]
	 t190 = &q1R3[5:int]
	 *t185 = -5.07831e-09:float64
	 *t186 = -0.102538:float64
	 *t187 = -4.61012:float64
	 *t188 = -57.8472:float64
	 *t189 = -228.245:float64
	 *t190 = -219.21:float64
	 t191 = &q1S3[0:int]
	 t192 = &q1S3[1:int]
	 t193 = &q1S3[2:int]
	 t194 = &q1S3[3:int]
	 t195 = &q1S3[4:int]
	 t196 = &q1S3[5:int]
	 *t191 = 47.6652:float64
	 *t192 = 673.865:float64
	 *t193 = 3380.15:float64
	 *t194 = 5547.73:float64
	 *t195 = 1903.12:float64
	 *t196 = -135.201:float64
	 t197 = &q1R2[0:int]
	 t198 = &q1R2[1:int]
	 t199 = &q1R2[2:int]
	 t200 = &q1R2[3:int]
	 t201 = &q1R2[4:int]
	 t202 = &q1R2[5:int]
	 *t197 = -1.78382e-07:float64
	 *t198 = -0.102517:float64
	 *t199 = -2.75221:float64
	 *t200 = -19.6636:float64
	 *t201 = -42.3253:float64
	 *t202 = -21.3719:float64
	 t203 = &q1S2[0:int]
	 t204 = &q1S2[1:int]
	 t205 = &q1S2[2:int]
	 t206 = &q1S2[3:int]
	 t207 = &q1S2[4:int]
	 t208 = &q1S2[5:int]
	 *t203 = 29.5334:float64
	 *t204 = 252.982:float64
	 *t205 = 757.503:float64
	 *t206 = 739.393:float64
	 *t207 = 155.949:float64
	 *t208 = -4.9595:float64
	 t209 = &_lgamA[0:int]
	 t210 = &_lgamA[1:int]
	 t211 = &_lgamA[2:int]
	 t212 = &_lgamA[3:int]
	 t213 = &_lgamA[4:int]
	 t214 = &_lgamA[5:int]
	 t215 = &_lgamA[6:int]
	 t216 = &_lgamA[7:int]
	 t217 = &_lgamA[8:int]
	 t218 = &_lgamA[9:int]
	 t219 = &_lgamA[10:int]
	 t220 = &_lgamA[11:int]
	 *t209 = 0.0772157:float64
	 *t210 = 0.322467:float64
	 *t211 = 0.0673523:float64
	 *t212 = 0.0205808:float64
	 *t213 = 0.00738555:float64
	 *t214 = 0.00289051:float64
	 *t215 = 0.00119271:float64
	 *t216 = 0.00051007:float64
	 *t217 = 0.000220863:float64
	 *t218 = 0.000108012:float64
	 *t219 = 2.52145e-05:float64
	 *t220 = 4.48641e-05:float64
	 t221 = &_lgamR[0:int]
	 t222 = &_lgamR[1:int]
	 t223 = &_lgamR[2:int]
	 t224 = &_lgamR[3:int]
	 t225 = &_lgamR[4:int]
	 t226 = &_lgamR[5:int]
	 t227 = &_lgamR[6:int]
	 *t221 = 1:float64
	 *t222 = 1.39201:float64
	 *t223 = 0.721936:float64
	 *t224 = 0.171934:float64
	 *t225 = 0.0186459:float64
	 *t226 = 0.000777942:float64
	 *t227 = 7.32668e-06:float64
	 t228 = &_lgamS[0:int]
	 t229 = &_lgamS[1:int]
	 t230 = &_lgamS[2:int]
	 t231 = &_lgamS[3:int]
	 t232 = &_lgamS[4:int]
	 t233 = &_lgamS[5:int]
	 t234 = &_lgamS[6:int]
	 *t228 = -0.0772157:float64
	 *t229 = 0.214982:float64
	 *t230 = 0.325779:float64
	 *t231 = 0.14635:float64
	 *t232 = 0.0266423:float64
	 *t233 = 0.00184028:float64
	 *t234 = 3.19475e-05:float64
	 t235 = &_lgamT[0:int]
	 t236 = &_lgamT[1:int]
	 t237 = &_lgamT[2:int]
	 t238 = &_lgamT[3:int]
	 t239 = &_lgamT[4:int]
	 t240 = &_lgamT[5:int]
	 t241 = &_lgamT[6:int]
	 t242 = &_lgamT[7:int]
	 t243 = &_lgamT[8:int]
	 t244 = &_lgamT[9:int]
	 t245 = &_lgamT[10:int]
	 t246 = &_lgamT[11:int]
	 t247 = &_lgamT[12:int]
	 t248 = &_lgamT[13:int]
	 t249 = &_lgamT[14:int]
	 *t235 = 0.483836:float64
	 *t236 = -0.147588:float64
	 *t237 = 0.0646249:float64
	 *t238 = -0.0327885:float64
	 *t239 = 0.0179707:float64
	 *t240 = -0.0103142:float64
	 *t241 = 0.00610054:float64
	 *t242 = -0.00368452:float64
	 *t243 = 0.00225965:float64
	 *t244 = -0.00140346:float64
	 *t245 = 0.000881082:float64
	 *t246 = -0.000538595:float64
	 *t247 = 0.000315632:float64
	 *t248 = -0.000312754:float64
	 *t249 = 0.000335529:float64
	 t250 = &_lgamU[0:int]
	 t251 = &_lgamU[1:int]
	 t252 = &_lgamU[2:int]
	 t253 = &_lgamU[3:int]
	 t254 = &_lgamU[4:int]
	 t255 = &_lgamU[5:int]
	 *t250 = -0.0772157:float64
	 *t251 = 0.632827:float64
	 *t252 = 1.45492:float64
	 *t253 = 0.977718:float64
	 *t254 = 0.228964:float64
	 *t255 = 0.0133811:float64
	 t256 = &_lgamV[0:int]
	 t257 = &_lgamV[1:int]
	 t258 = &_lgamV[2:int]
	 t259 = &_lgamV[3:int]
	 t260 = &_lgamV[4:int]
	 t261 = &_lgamV[5:int]
	 *t256 = 1:float64
	 *t257 = 2.45598:float64
	 *t258 = 2.12849:float64
	 *t259 = 0.769285:float64
	 *t260 = 0.104223:float64
	 *t261 = 0.00321709:float64
	 t262 = &_lgamW[0:int]
	 t263 = &_lgamW[1:int]
	 t264 = &_lgamW[2:int]
	 t265 = &_lgamW[3:int]
	 t266 = &_lgamW[4:int]
	 t267 = &_lgamW[5:int]
	 t268 = &_lgamW[6:int]
	 *t262 = 0.418939:float64
	 *t263 = 0.0833333:float64
	 *t264 = -0.00277778:float64
	 *t265 = 0.000793651:float64
	 *t266 = -0.000595188:float64
	 *t267 = 0.00083634:float64
	 *t268 = -0.00163093:float64
	 t269 = &pow10tab[0:int]
	 t270 = &pow10tab[1:int]
	 t271 = &pow10tab[2:int]
	 t272 = &pow10tab[3:int]
	 t273 = &pow10tab[4:int]
	 t274 = &pow10tab[5:int]
	 t275 = &pow10tab[6:int]
	 t276 = &pow10tab[7:int]
	 t277 = &pow10tab[8:int]
	 t278 = &pow10tab[9:int]
	 t279 = &pow10tab[10:int]
	 t280 = &pow10tab[11:int]
	 t281 = &pow10tab[12:int]
	 t282 = &pow10tab[13:int]
	 t283 = &pow10tab[14:int]
	 t284 = &pow10tab[15:int]
	 t285 = &pow10tab[16:int]
	 t286 = &pow10tab[17:int]
	 t287 = &pow10tab[18:int]
	 t288 = &pow10tab[19:int]
	 t289 = &pow10tab[20:int]
	 t290 = &pow10tab[21:int]
	 t291 = &pow10tab[22:int]
	 t292 = &pow10tab[23:int]
	 t293 = &pow10tab[24:int]
	 t294 = &pow10tab[25:int]
	 t295 = &pow10tab[26:int]
	 t296 = &pow10tab[27:int]
	 t297 = &pow10tab[28:int]
	 t298 = &pow10tab[29:int]
	 t299 = &pow10tab[30:int]
	 t300 = &pow10tab[31:int]
	 *t269 = 1:float64
	 *t270 = 10:float64
	 *t271 = 100:float64
	 *t272 = 1000:float64
	 *t273 = 10000:float64
	 *t274 = 100000:float64
	 *t275 = 1e+06:float64
	 *t276 = 1e+07:float64
	 *t277 = 1e+08:float64
	 *t278 = 1e+09:float64
	 *t279 = 1e+10:float64
	 *t280 = 1e+11:float64
	 *t281 = 1e+12:float64
	 *t282 = 1e+13:float64
	 *t283 = 1e+14:float64
	 *t284 = 1e+15:float64
	 *t285 = 1e+16:float64
	 *t286 = 1e+17:float64
	 *t287 = 1e+18:float64
	 *t288 = 1e+19:float64
	 *t289 = 1e+20:float64
	 *t290 = 1e+21:float64
	 *t291 = 1e+22:float64
	 *t292 = 1e+23:float64
	 *t293 = 1e+24:float64
	 *t294 = 1e+25:float64
	 *t295 = 1e+26:float64
	 *t296 = 1e+27:float64
	 *t297 = 1e+28:float64
	 *t298 = 1e+29:float64
	 *t299 = 1e+30:float64
	 *t300 = 1e+31:float64
	 t301 = &pow10postab32[0:int]
	 t302 = &pow10postab32[1:int]
	 t303 = &pow10postab32[2:int]
	 t304 = &pow10postab32[3:int]
	 t305 = &pow10postab32[4:int]
	 t306 = &pow10postab32[5:int]
	 t307 = &pow10postab32[6:int]
	 t308 = &pow10postab32[7:int]
	 t309 = &pow10postab32[8:int]
	 t310 = &pow10postab32[9:int]
	 *t301 = 1:float64
	 *t302 = 1e+32:float64
	 *t303 = 1e+64:float64
	 *t304 = 1e+96:float64
	 *t305 = 1e+128:float64
	 *t306 = 1e+160:float64
	 *t307 = 1e+192:float64
	 *t308 = 1e+224:float64
	 *t309 = 1e+256:float64
	 *t310 = 1e+288:float64
	 t311 = &pow10negtab32[0:int]
	 t312 = &pow10negtab32[1:int]
	 t313 = &pow10negtab32[2:int]
	 t314 = &pow10negtab32[3:int]
	 t315 = &pow10negtab32[4:int]
	 t316 = &pow10negtab32[5:int]
	 t317 = &pow10negtab32[6:int]
	 t318 = &pow10negtab32[7:int]
	 t319 = &pow10negtab32[8:int]
	 t320 = &pow10negtab32[9:int]
	 t321 = &pow10negtab32[10:int]
	 *t311 = 1:float64
	 *t312 = 1e-32:float64
	 *t313 = 1e-64:float64
	 *t314 = 1e-96:float64
	 *t315 = 1e-128:float64
	 *t316 = 1e-160:float64
	 *t317 = 1e-192:float64
	 *t318 = 1e-224:float64
	 *t319 = 1e-256:float64
	 *t320 = 1e-288:float64
	 *t321 = 9.99989e-321:float64
	 t322 = &_sin[0:int]
	 t323 = &_sin[1:int]
	 t324 = &_sin[2:int]
	 t325 = &_sin[3:int]
	 t326 = &_sin[4:int]
	 t327 = &_sin[5:int]
	 *t322 = 1.58962e-10:float64
	 *t323 = -2.50507e-08:float64
	 *t324 = 2.75573e-06:float64
	 *t325 = -0.000198413:float64
	 *t326 = 0.00833333:float64
	 *t327 = -0.166667:float64
	 t328 = &_cos[0:int]
	 t329 = &_cos[1:int]
	 t330 = &_cos[2:int]
	 t331 = &_cos[3:int]
	 t332 = &_cos[4:int]
	 t333 = &_cos[5:int]
	 *t328 = -1.13585e-11:float64
	 *t329 = 2.08757e-09:float64
	 *t330 = -2.75573e-07:float64
	 *t331 = 2.48016e-05:float64
	 *t332 = -0.00138889:float64
	 *t333 = 0.0416667:float64
	 t334 = &_tanP[0:int]
	 t335 = &_tanP[1:int]
	 t336 = &_tanP[2:int]
	 *t334 = -13093.7:float64
	 *t335 = 1.15352e+06:float64
	 *t336 = -1.79565e+07:float64
	 t337 = &_tanQ[0:int]
	 t338 = &_tanQ[1:int]
	 t339 = &_tanQ[2:int]
	 t340 = &_tanQ[3:int]
	 t341 = &_tanQ[4:int]
	 *t337 = 1:float64
	 *t338 = 13681.3:float64
	 *t339 = -1.32089e+06:float64
	 *t340 = 2.50084e+07:float64
	 *t341 = -5.38696e+07:float64
	 t342 = &tanhP[0:int]
	 t343 = &tanhP[1:int]
	 t344 = &tanhP[2:int]
	 *t342 = -0.964399:float64
	 *t343 = -99.2877:float64
	 *t344 = -1614.69:float64
	 t345 = &tanhQ[0:int]
	 t346 = &tanhQ[1:int]
	 t347 = &tanhQ[2:int]
	 *t345 = 112.812:float64
	 *t346 = 2235.49:float64
	 *t347 = 4844.06:float64
	 jump 2
.2:
	 return
Leaving math.init, resuming strconv.init.
	 t2 = errors.init()
Entering errors.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 jump 2
.2:
	 return
Leaving errors.init, resuming strconv.init.
	 t3 = unicode/utf8.init()
Entering unicode/utf8.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = &first[0:int]
	 t2 = &first[1:int]
	 t3 = &first[2:int]
	 t4 = &first[3:int]
	 t5 = &first[4:int]
	 t6 = &first[5:int]
	 t7 = &first[6:int]
	 t8 = &first[7:int]
	 t9 = &first[8:int]
	 t10 = &first[9:int]
	 t11 = &first[10:int]
	 t12 = &first[11:int]
	 t13 = &first[12:int]
	 t14 = &first[13:int]
	 t15 = &first[14:int]
	 t16 = &first[15:int]
	 t17 = &first[16:int]
	 t18 = &first[17:int]
	 t19 = &first[18:int]
	 t20 = &first[19:int]
	 t21 = &first[20:int]
	 t22 = &first[21:int]
	 t23 = &first[22:int]
	 t24 = &first[23:int]
	 t25 = &first[24:int]
	 t26 = &first[25:int]
	 t27 = &first[26:int]
	 t28 = &first[27:int]
	 t29 = &first[28:int]
	 t30 = &first[29:int]
	 t31 = &first[30:int]
	 t32 = &first[31:int]
	 t33 = &first[32:int]
	 t34 = &first[33:int]
	 t35 = &first[34:int]
	 t36 = &first[35:int]
	 t37 = &first[36:int]
	 t38 = &first[37:int]
	 t39 = &first[38:int]
	 t40 = &first[39:int]
	 t41 = &first[40:int]
	 t42 = &first[41:int]
	 t43 = &first[42:int]
	 t44 = &first[43:int]
	 t45 = &first[44:int]
	 t46 = &first[45:int]
	 t47 = &first[46:int]
	 t48 = &first[47:int]
	 t49 = &first[48:int]
	 t50 = &first[49:int]
	 t51 = &first[50:int]
	 t52 = &first[51:int]
	 t53 = &first[52:int]
	 t54 = &first[53:int]
	 t55 = &first[54:int]
	 t56 = &first[55:int]
	 t57 = &first[56:int]
	 t58 = &first[57:int]
	 t59 = &first[58:int]
	 t60 = &first[59:int]
	 t61 = &first[60:int]
	 t62 = &first[61:int]
	 t63 = &first[62:int]
	 t64 = &first[63:int]
	 t65 = &first[64:int]
	 t66 = &first[65:int]
	 t67 = &first[66:int]
	 t68 = &first[67:int]
	 t69 = &first[68:int]
	 t70 = &first[69:int]
	 t71 = &first[70:int]
	 t72 = &first[71:int]
	 t73 = &first[72:int]
	 t74 = &first[73:int]
	 t75 = &first[74:int]
	 t76 = &first[75:int]
	 t77 = &first[76:int]
	 t78 = &first[77:int]
	 t79 = &first[78:int]
	 t80 = &first[79:int]
	 t81 = &first[80:int]
	 t82 = &first[81:int]
	 t83 = &first[82:int]
	 t84 = &first[83:int]
	 t85 = &first[84:int]
	 t86 = &first[85:int]
	 t87 = &first[86:int]
	 t88 = &first[87:int]
	 t89 = &first[88:int]
	 t90 = &first[89:int]
	 t91 = &first[90:int]
	 t92 = &first[91:int]
	 t93 = &first[92:int]
	 t94 = &first[93:int]
	 t95 = &first[94:int]
	 t96 = &first[95:int]
	 t97 = &first[96:int]
	 t98 = &first[97:int]
	 t99 = &first[98:int]
	 t100 = &first[99:int]
	 t101 = &first[100:int]
	 t102 = &first[101:int]
	 t103 = &first[102:int]
	 t104 = &first[103:int]
	 t105 = &first[104:int]
	 t106 = &first[105:int]
	 t107 = &first[106:int]
	 t108 = &first[107:int]
	 t109 = &first[108:int]
	 t110 = &first[109:int]
	 t111 = &first[110:int]
	 t112 = &first[111:int]
	 t113 = &first[112:int]
	 t114 = &first[113:int]
	 t115 = &first[114:int]
	 t116 = &first[115:int]
	 t117 = &first[116:int]
	 t118 = &first[117:int]
	 t119 = &first[118:int]
	 t120 = &first[119:int]
	 t121 = &first[120:int]
	 t122 = &first[121:int]
	 t123 = &first[122:int]
	 t124 = &first[123:int]
	 t125 = &first[124:int]
	 t126 = &first[125:int]
	 t127 = &first[126:int]
	 t128 = &first[127:int]
	 t129 = &first[128:int]
	 t130 = &first[129:int]
	 t131 = &first[130:int]
	 t132 = &first[131:int]
	 t133 = &first[132:int]
	 t134 = &first[133:int]
	 t135 = &first[134:int]
	 t136 = &first[135:int]
	 t137 = &first[136:int]
	 t138 = &first[137:int]
	 t139 = &first[138:int]
	 t140 = &first[139:int]
	 t141 = &first[140:int]
	 t142 = &first[141:int]
	 t143 = &first[142:int]
	 t144 = &first[143:int]
	 t145 = &first[144:int]
	 t146 = &first[145:int]
	 t147 = &first[146:int]
	 t148 = &first[147:int]
	 t149 = &first[148:int]
	 t150 = &first[149:int]
	 t151 = &first[150:int]
	 t152 = &first[151:int]
	 t153 = &first[152:int]
	 t154 = &first[153:int]
	 t155 = &first[154:int]
	 t156 = &first[155:int]
	 t157 = &first[156:int]
	 t158 = &first[157:int]
	 t159 = &first[158:int]
	 t160 = &first[159:int]
	 t161 = &first[160:int]
	 t162 = &first[161:int]
	 t163 = &first[162:int]
	 t164 = &first[163:int]
	 t165 = &first[164:int]
	 t166 = &first[165:int]
	 t167 = &first[166:int]
	 t168 = &first[167:int]
	 t169 = &first[168:int]
	 t170 = &first[169:int]
	 t171 = &first[170:int]
	 t172 = &first[171:int]
	 t173 = &first[172:int]
	 t174 = &first[173:int]
	 t175 = &first[174:int]
	 t176 = &first[175:int]
	 t177 = &first[176:int]
	 t178 = &first[177:int]
	 t179 = &first[178:int]
	 t180 = &first[179:int]
	 t181 = &first[180:int]
	 t182 = &first[181:int]
	 t183 = &first[182:int]
	 t184 = &first[183:int]
	 t185 = &first[184:int]
	 t186 = &first[185:int]
	 t187 = &first[186:int]
	 t188 = &first[187:int]
	 t189 = &first[188:int]
	 t190 = &first[189:int]
	 t191 = &first[190:int]
	 t192 = &first[191:int]
	 t193 = &first[192:int]
	 t194 = &first[193:int]
	 t195 = &first[194:int]
	 t196 = &first[195:int]
	 t197 = &first[196:int]
	 t198 = &first[197:int]
	 t199 = &first[198:int]
	 t200 = &first[199:int]
	 t201 = &first[200:int]
	 t202 = &first[201:int]
	 t203 = &first[202:int]
	 t204 = &first[203:int]
	 t205 = &first[204:int]
	 t206 = &first[205:int]
	 t207 = &first[206:int]
	 t208 = &first[207:int]
	 t209 = &first[208:int]
	 t210 = &first[209:int]
	 t211 = &first[210:int]
	 t212 = &first[211:int]
	 t213 = &first[212:int]
	 t214 = &first[213:int]
	 t215 = &first[214:int]
	 t216 = &first[215:int]
	 t217 = &first[216:int]
	 t218 = &first[217:int]
	 t219 = &first[218:int]
	 t220 = &first[219:int]
	 t221 = &first[220:int]
	 t222 = &first[221:int]
	 t223 = &first[222:int]
	 t224 = &first[223:int]
	 t225 = &first[224:int]
	 t226 = &first[225:int]
	 t227 = &first[226:int]
	 t228 = &first[227:int]
	 t229 = &first[228:int]
	 t230 = &first[229:int]
	 t231 = &first[230:int]
	 t232 = &first[231:int]
	 t233 = &first[232:int]
	 t234 = &first[233:int]
	 t235 = &first[234:int]
	 t236 = &first[235:int]
	 t237 = &first[236:int]
	 t238 = &first[237:int]
	 t239 = &first[238:int]
	 t240 = &first[239:int]
	 t241 = &first[240:int]
	 t242 = &first[241:int]
	 t243 = &first[242:int]
	 t244 = &first[243:int]
	 t245 = &first[244:int]
	 t246 = &first[245:int]
	 t247 = &first[246:int]
	 t248 = &first[247:int]
	 t249 = &first[248:int]
	 t250 = &first[249:int]
	 t251 = &first[250:int]
	 t252 = &first[251:int]
	 t253 = &first[252:int]
	 t254 = &first[253:int]
	 t255 = &first[254:int]
	 t256 = &first[255:int]
	 *t1 = 240:uint8
	 *t2 = 240:uint8
	 *t3 = 240:uint8
	 *t4 = 240:uint8
	 *t5 = 240:uint8
	 *t6 = 240:uint8
	 *t7 = 240:uint8
	 *t8 = 240:uint8
	 *t9 = 240:uint8
	 *t10 = 240:uint8
	 *t11 = 240:uint8
	 *t12 = 240:uint8
	 *t13 = 240:uint8
	 *t14 = 240:uint8
	 *t15 = 240:uint8
	 *t16 = 240:uint8
	 *t17 = 240:uint8
	 *t18 = 240:uint8
	 *t19 = 240:uint8
	 *t20 = 240:uint8
	 *t21 = 240:uint8
	 *t22 = 240:uint8
	 *t23 = 240:uint8
	 *t24 = 240:uint8
	 *t25 = 240:uint8
	 *t26 = 240:uint8
	 *t27 = 240:uint8
	 *t28 = 240:uint8
	 *t29 = 240:uint8
	 *t30 = 240:uint8
	 *t31 = 240:uint8
	 *t32 = 240:uint8
	 *t33 = 240:uint8
	 *t34 = 240:uint8
	 *t35 = 240:uint8
	 *t36 = 240:uint8
	 *t37 = 240:uint8
	 *t38 = 240:uint8
	 *t39 = 240:uint8
	 *t40 = 240:uint8
	 *t41 = 240:uint8
	 *t42 = 240:uint8
	 *t43 = 240:uint8
	 *t44 = 240:uint8
	 *t45 = 240:uint8
	 *t46 = 240:uint8
	 *t47 = 240:uint8
	 *t48 = 240:uint8
	 *t49 = 240:uint8
	 *t50 = 240:uint8
	 *t51 = 240:uint8
	 *t52 = 240:uint8
	 *t53 = 240:uint8
	 *t54 = 240:uint8
	 *t55 = 240:uint8
	 *t56 = 240:uint8
	 *t57 = 240:uint8
	 *t58 = 240:uint8
	 *t59 = 240:uint8
	 *t60 = 240:uint8
	 *t61 = 240:uint8
	 *t62 = 240:uint8
	 *t63 = 240:uint8
	 *t64 = 240:uint8
	 *t65 = 240:uint8
	 *t66 = 240:uint8
	 *t67 = 240:uint8
	 *t68 = 240:uint8
	 *t69 = 240:uint8
	 *t70 = 240:uint8
	 *t71 = 240:uint8
	 *t72 = 240:uint8
	 *t73 = 240:uint8
	 *t74 = 240:uint8
	 *t75 = 240:uint8
	 *t76 = 240:uint8
	 *t77 = 240:uint8
	 *t78 = 240:uint8
	 *t79 = 240:uint8
	 *t80 = 240:uint8
	 *t81 = 240:uint8
	 *t82 = 240:uint8
	 *t83 = 240:uint8
	 *t84 = 240:uint8
	 *t85 = 240:uint8
	 *t86 = 240:uint8
	 *t87 = 240:uint8
	 *t88 = 240:uint8
	 *t89 = 240:uint8
	 *t90 = 240:uint8
	 *t91 = 240:uint8
	 *t92 = 240:uint8
	 *t93 = 240:uint8
	 *t94 = 240:uint8
	 *t95 = 240:uint8
	 *t96 = 240:uint8
	 *t97 = 240:uint8
	 *t98 = 240:uint8
	 *t99 = 240:uint8
	 *t100 = 240:uint8
	 *t101 = 240:uint8
	 *t102 = 240:uint8
	 *t103 = 240:uint8
	 *t104 = 240:uint8
	 *t105 = 240:uint8
	 *t106 = 240:uint8
	 *t107 = 240:uint8
	 *t108 = 240:uint8
	 *t109 = 240:uint8
	 *t110 = 240:uint8
	 *t111 = 240:uint8
	 *t112 = 240:uint8
	 *t113 = 240:uint8
	 *t114 = 240:uint8
	 *t115 = 240:uint8
	 *t116 = 240:uint8
	 *t117 = 240:uint8
	 *t118 = 240:uint8
	 *t119 = 240:uint8
	 *t120 = 240:uint8
	 *t121 = 240:uint8
	 *t122 = 240:uint8
	 *t123 = 240:uint8
	 *t124 = 240:uint8
	 *t125 = 240:uint8
	 *t126 = 240:uint8
	 *t127 = 240:uint8
	 *t128 = 240:uint8
	 *t129 = 241:uint8
	 *t130 = 241:uint8
	 *t131 = 241:uint8
	 *t132 = 241:uint8
	 *t133 = 241:uint8
	 *t134 = 241:uint8
	 *t135 = 241:uint8
	 *t136 = 241:uint8
	 *t137 = 241:uint8
	 *t138 = 241:uint8
	 *t139 = 241:uint8
	 *t140 = 241:uint8
	 *t141 = 241:uint8
	 *t142 = 241:uint8
	 *t143 = 241:uint8
	 *t144 = 241:uint8
	 *t145 = 241:uint8
	 *t146 = 241:uint8
	 *t147 = 241:uint8
	 *t148 = 241:uint8
	 *t149 = 241:uint8
	 *t150 = 241:uint8
	 *t151 = 241:uint8
	 *t152 = 241:uint8
	 *t153 = 241:uint8
	 *t154 = 241:uint8
	 *t155 = 241:uint8
	 *t156 = 241:uint8
	 *t157 = 241:uint8
	 *t158 = 241:uint8
	 *t159 = 241:uint8
	 *t160 = 241:uint8
	 *t161 = 241:uint8
	 *t162 = 241:uint8
	 *t163 = 241:uint8
	 *t164 = 241:uint8
	 *t165 = 241:uint8
	 *t166 = 241:uint8
	 *t167 = 241:uint8
	 *t168 = 241:uint8
	 *t169 = 241:uint8
	 *t170 = 241:uint8
	 *t171 = 241:uint8
	 *t172 = 241:uint8
	 *t173 = 241:uint8
	 *t174 = 241:uint8
	 *t175 = 241:uint8
	 *t176 = 241:uint8
	 *t177 = 241:uint8
	 *t178 = 241:uint8
	 *t179 = 241:uint8
	 *t180 = 241:uint8
	 *t181 = 241:uint8
	 *t182 = 241:uint8
	 *t183 = 241:uint8
	 *t184 = 241:uint8
	 *t185 = 241:uint8
	 *t186 = 241:uint8
	 *t187 = 241:uint8
	 *t188 = 241:uint8
	 *t189 = 241:uint8
	 *t190 = 241:uint8
	 *t191 = 241:uint8
	 *t192 = 241:uint8
	 *t193 = 241:uint8
	 *t194 = 241:uint8
	 *t195 = 2:uint8
	 *t196 = 2:uint8
	 *t197 = 2:uint8
	 *t198 = 2:uint8
	 *t199 = 2:uint8
	 *t200 = 2:uint8
	 *t201 = 2:uint8
	 *t202 = 2:uint8
	 *t203 = 2:uint8
	 *t204 = 2:uint8
	 *t205 = 2:uint8
	 *t206 = 2:uint8
	 *t207 = 2:uint8
	 *t208 = 2:uint8
	 *t209 = 2:uint8
	 *t210 = 2:uint8
	 *t211 = 2:uint8
	 *t212 = 2:uint8
	 *t213 = 2:uint8
	 *t214 = 2:uint8
	 *t215 = 2:uint8
	 *t216 = 2:uint8
	 *t217 = 2:uint8
	 *t218 = 2:uint8
	 *t219 = 2:uint8
	 *t220 = 2:uint8
	 *t221 = 2:uint8
	 *t222 = 2:uint8
	 *t223 = 2:uint8
	 *t224 = 2:uint8
	 *t225 = 19:uint8
	 *t226 = 3:uint8
	 *t227 = 3:uint8
	 *t228 = 3:uint8
	 *t229 = 3:uint8
	 *t230 = 3:uint8
	 *t231 = 3:uint8
	 *t232 = 3:uint8
	 *t233 = 3:uint8
	 *t234 = 3:uint8
	 *t235 = 3:uint8
	 *t236 = 3:uint8
	 *t237 = 3:uint8
	 *t238 = 35:uint8
	 *t239 = 3:uint8
	 *t240 = 3:uint8
	 *t241 = 52:uint8
	 *t242 = 4:uint8
	 *t243 = 4:uint8
	 *t244 = 4:uint8
	 *t245 = 68:uint8
	 *t246 = 241:uint8
	 *t247 = 241:uint8
	 *t248 = 241:uint8
	 *t249 = 241:uint8
	 *t250 = 241:uint8
	 *t251 = 241:uint8
	 *t252 = 241:uint8
	 *t253 = 241:uint8
	 *t254 = 241:uint8
	 *t255 = 241:uint8
	 *t256 = 241:uint8
	 t257 = &acceptRanges[0:int]
	 t258 = &t257.lo [#0]
	 t259 = &t257.hi [#1]
	 t260 = &acceptRanges[1:int]
	 t261 = &t260.lo [#0]
	 t262 = &t260.hi [#1]
	 t263 = &acceptRanges[2:int]
	 t264 = &t263.lo [#0]
	 t265 = &t263.hi [#1]
	 t266 = &acceptRanges[3:int]
	 t267 = &t266.lo [#0]
	 t268 = &t266.hi [#1]
	 t269 = &acceptRanges[4:int]
	 t270 = &t269.lo [#0]
	 t271 = &t269.hi [#1]
	 *t258 = 128:uint8
	 *t259 = 191:uint8
	 *t261 = 160:uint8
	 *t262 = 191:uint8
	 *t264 = 128:uint8
	 *t265 = 159:uint8
	 *t267 = 144:uint8
	 *t268 = 191:uint8
	 *t270 = 128:uint8
	 *t271 = 143:uint8
	 jump 2
.2:
	 return
Leaving unicode/utf8.init, resuming strconv.init.
	 *optimize = true:bool
	 t4 = new [9]int (slicelit)
	 t5 = &t4[0:int]
	 *t5 = 1:int
	 t6 = &t4[1:int]
	 *t6 = 3:int
	 t7 = &t4[2:int]
	 *t7 = 6:int
	 t8 = &t4[3:int]
	 *t8 = 9:int
	 t9 = &t4[4:int]
	 *t9 = 13:int
	 t10 = &t4[5:int]
	 *t10 = 16:int
	 t11 = &t4[6:int]
	 *t11 = 19:int
	 t12 = &t4[7:int]
	 *t12 = 23:int
	 t13 = &t4[8:int]
	 *t13 = 26:int
	 t14 = slice t4[:]
	 *powtab = t14
	 t15 = new [23]float64 (slicelit)
	 t16 = &t15[0:int]
	 *t16 = 1:float64
	 t17 = &t15[1:int]
	 *t17 = 10:float64
	 t18 = &t15[2:int]
	 *t18 = 100:float64
	 t19 = &t15[3:int]
	 *t19 = 1000:float64
	 t20 = &t15[4:int]
	 *t20 = 10000:float64
	 t21 = &t15[5:int]
	 *t21 = 100000:float64
	 t22 = &t15[6:int]
	 *t22 = 1e+06:float64
	 t23 = &t15[7:int]
	 *t23 = 1e+07:float64
	 t24 = &t15[8:int]
	 *t24 = 1e+08:float64
	 t25 = &t15[9:int]
	 *t25 = 1e+09:float64
	 t26 = &t15[10:int]
	 *t26 = 1e+10:float64
	 t27 = &t15[11:int]
	 *t27 = 1e+11:float64
	 t28 = &t15[12:int]
	 *t28 = 1e+12:float64
	 t29 = &t15[13:int]
	 *t29 = 1e+13:float64
	 t30 = &t15[14:int]
	 *t30 = 1e+14:float64
	 t31 = &t15[15:int]
	 *t31 = 1e+15:float64
	 t32 = &t15[16:int]
	 *t32 = 1e+16:float64
	 t33 = &t15[17:int]
	 *t33 = 1e+17:float64
	 t34 = &t15[18:int]
	 *t34 = 1e+18:float64
	 t35 = &t15[19:int]
	 *t35 = 1e+19:float64
	 t36 = &t15[20:int]
	 *t36 = 1e+20:float64
	 t37 = &t15[21:int]
	 *t37 = 1e+21:float64
	 t38 = &t15[22:int]
	 *t38 = 1e+22:float64
	 t39 = slice t15[:]
	 *float64pow10 = t39
	 t40 = new [11]float32 (slicelit)
	 t41 = &t40[0:int]
	 *t41 = 1:float32
	 t42 = &t40[1:int]
	 *t42 = 10:float32
	 t43 = &t40[2:int]
	 *t43 = 100:float32
	 t44 = &t40[3:int]
	 *t44 = 1000:float32
	 t45 = &t40[4:int]
	 *t45 = 10000:float32
	 t46 = &t40[5:int]
	 *t46 = 100000:float32
	 t47 = &t40[6:int]
	 *t47 = 1e+06:float32
	 t48 = &t40[7:int]
	 *t48 = 1e+07:float32
	 t49 = &t40[8:int]
	 *t49 = 1e+08:float32
	 t50 = &t40[9:int]
	 *t50 = 1e+09:float32
	 t51 = &t40[10:int]
	 *t51 = 1e+10:float32
	 t52 = slice t40[:]
	 *float32pow10 = t52
	 t53 = errors.New("value out of range":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming strconv.init at /usr/local/Cellar/go/1.9.2/libexec/src/strconv/atoi.go:10:26.
	 *ErrRange = t53
	 t54 = errors.New("invalid syntax":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming strconv.init at /usr/local/Cellar/go/1.9.2/libexec/src/strconv/atoi.go:13:27.
	 *ErrSyntax = t54
	 t55 = new [61]leftCheat (slicelit)
	 t56 = &t55[0:int]
	 t57 = &t56.delta [#0]
	 t58 = &t56.cutoff [#1]
	 *t57 = 0:int
	 *t58 = "":string
	 t59 = &t55[1:int]
	 t60 = &t59.delta [#0]
	 t61 = &t59.cutoff [#1]
	 *t60 = 1:int
	 *t61 = "5":string
	 t62 = &t55[2:int]
	 t63 = &t62.delta [#0]
	 t64 = &t62.cutoff [#1]
	 *t63 = 1:int
	 *t64 = "25":string
	 t65 = &t55[3:int]
	 t66 = &t65.delta [#0]
	 t67 = &t65.cutoff [#1]
	 *t66 = 1:int
	 *t67 = "125":string
	 t68 = &t55[4:int]
	 t69 = &t68.delta [#0]
	 t70 = &t68.cutoff [#1]
	 *t69 = 2:int
	 *t70 = "625":string
	 t71 = &t55[5:int]
	 t72 = &t71.delta [#0]
	 t73 = &t71.cutoff [#1]
	 *t72 = 2:int
	 *t73 = "3125":string
	 t74 = &t55[6:int]
	 t75 = &t74.delta [#0]
	 t76 = &t74.cutoff [#1]
	 *t75 = 2:int
	 *t76 = "15625":string
	 t77 = &t55[7:int]
	 t78 = &t77.delta [#0]
	 t79 = &t77.cutoff [#1]
	 *t78 = 3:int
	 *t79 = "78125":string
	 t80 = &t55[8:int]
	 t81 = &t80.delta [#0]
	 t82 = &t80.cutoff [#1]
	 *t81 = 3:int
	 *t82 = "390625":string
	 t83 = &t55[9:int]
	 t84 = &t83.delta [#0]
	 t85 = &t83.cutoff [#1]
	 *t84 = 3:int
	 *t85 = "1953125":string
	 t86 = &t55[10:int]
	 t87 = &t86.delta [#0]
	 t88 = &t86.cutoff [#1]
	 *t87 = 4:int
	 *t88 = "9765625":string
	 t89 = &t55[11:int]
	 t90 = &t89.delta [#0]
	 t91 = &t89.cutoff [#1]
	 *t90 = 4:int
	 *t91 = "48828125":string
	 t92 = &t55[12:int]
	 t93 = &t92.delta [#0]
	 t94 = &t92.cutoff [#1]
	 *t93 = 4:int
	 *t94 = "244140625":string
	 t95 = &t55[13:int]
	 t96 = &t95.delta [#0]
	 t97 = &t95.cutoff [#1]
	 *t96 = 4:int
	 *t97 = "1220703125":string
	 t98 = &t55[14:int]
	 t99 = &t98.delta [#0]
	 t100 = &t98.cutoff [#1]
	 *t99 = 5:int
	 *t100 = "6103515625":string
	 t101 = &t55[15:int]
	 t102 = &t101.delta [#0]
	 t103 = &t101.cutoff [#1]
	 *t102 = 5:int
	 *t103 = "30517578125":string
	 t104 = &t55[16:int]
	 t105 = &t104.delta [#0]
	 t106 = &t104.cutoff [#1]
	 *t105 = 5:int
	 *t106 = "152587890625":string
	 t107 = &t55[17:int]
	 t108 = &t107.delta [#0]
	 t109 = &t107.cutoff [#1]
	 *t108 = 6:int
	 *t109 = "762939453125":string
	 t110 = &t55[18:int]
	 t111 = &t110.delta [#0]
	 t112 = &t110.cutoff [#1]
	 *t111 = 6:int
	 *t112 = "3814697265625":string
	 t113 = &t55[19:int]
	 t114 = &t113.delta [#0]
	 t115 = &t113.cutoff [#1]
	 *t114 = 6:int
	 *t115 = "19073486328125":string
	 t116 = &t55[20:int]
	 t117 = &t116.delta [#0]
	 t118 = &t116.cutoff [#1]
	 *t117 = 7:int
	 *t118 = "95367431640625":string
	 t119 = &t55[21:int]
	 t120 = &t119.delta [#0]
	 t121 = &t119.cutoff [#1]
	 *t120 = 7:int
	 *t121 = "476837158203125":string
	 t122 = &t55[22:int]
	 t123 = &t122.delta [#0]
	 t124 = &t122.cutoff [#1]
	 *t123 = 7:int
	 *t124 = "2384185791015625":string
	 t125 = &t55[23:int]
	 t126 = &t125.delta [#0]
	 t127 = &t125.cutoff [#1]
	 *t126 = 7:int
	 *t127 = "11920928955078125":string
	 t128 = &t55[24:int]
	 t129 = &t128.delta [#0]
	 t130 = &t128.cutoff [#1]
	 *t129 = 8:int
	 *t130 = "59604644775390625":string
	 t131 = &t55[25:int]
	 t132 = &t131.delta [#0]
	 t133 = &t131.cutoff [#1]
	 *t132 = 8:int
	 *t133 = "298023223876953125":string
	 t134 = &t55[26:int]
	 t135 = &t134.delta [#0]
	 t136 = &t134.cutoff [#1]
	 *t135 = 8:int
	 *t136 = "1490116119384765625":string
	 t137 = &t55[27:int]
	 t138 = &t137.delta [#0]
	 t139 = &t137.cutoff [#1]
	 *t138 = 9:int
	 *t139 = "7450580596923828125":string
	 t140 = &t55[28:int]
	 t141 = &t140.delta [#0]
	 t142 = &t140.cutoff [#1]
	 *t141 = 9:int
	 *t142 = "37252902984619140625":string
	 t143 = &t55[29:int]
	 t144 = &t143.delta [#0]
	 t145 = &t143.cutoff [#1]
	 *t144 = 9:int
	 *t145 = "18626451492309570...":string
	 t146 = &t55[30:int]
	 t147 = &t146.delta [#0]
	 t148 = &t146.cutoff [#1]
	 *t147 = 10:int
	 *t148 = "93132257461547851...":string
	 t149 = &t55[31:int]
	 t150 = &t149.delta [#0]
	 t151 = &t149.cutoff [#1]
	 *t150 = 10:int
	 *t151 = "46566128730773925...":string
	 t152 = &t55[32:int]
	 t153 = &t152.delta [#0]
	 t154 = &t152.cutoff [#1]
	 *t153 = 10:int
	 *t154 = "23283064365386962...":string
	 t155 = &t55[33:int]
	 t156 = &t155.delta [#0]
	 t157 = &t155.cutoff [#1]
	 *t156 = 10:int
	 *t157 = "11641532182693481...":string
	 t158 = &t55[34:int]
	 t159 = &t158.delta [#0]
	 t160 = &t158.cutoff [#1]
	 *t159 = 11:int
	 *t160 = "58207660913467407...":string
	 t161 = &t55[35:int]
	 t162 = &t161.delta [#0]
	 t163 = &t161.cutoff [#1]
	 *t162 = 11:int
	 *t163 = "29103830456733703...":string
	 t164 = &t55[36:int]
	 t165 = &t164.delta [#0]
	 t166 = &t164.cutoff [#1]
	 *t165 = 11:int
	 *t166 = "14551915228366851...":string
	 t167 = &t55[37:int]
	 t168 = &t167.delta [#0]
	 t169 = &t167.cutoff [#1]
	 *t168 = 12:int
	 *t169 = "72759576141834259...":string
	 t170 = &t55[38:int]
	 t171 = &t170.delta [#0]
	 t172 = &t170.cutoff [#1]
	 *t171 = 12:int
	 *t172 = "36379788070917129...":string
	 t173 = &t55[39:int]
	 t174 = &t173.delta [#0]
	 t175 = &t173.cutoff [#1]
	 *t174 = 12:int
	 *t175 = "18189894035458564...":string
	 t176 = &t55[40:int]
	 t177 = &t176.delta [#0]
	 t178 = &t176.cutoff [#1]
	 *t177 = 13:int
	 *t178 = "90949470177292823...":string
	 t179 = &t55[41:int]
	 t180 = &t179.delta [#0]
	 t181 = &t179.cutoff [#1]
	 *t180 = 13:int
	 *t181 = "45474735088646411...":string
	 t182 = &t55[42:int]
	 t183 = &t182.delta [#0]
	 t184 = &t182.cutoff [#1]
	 *t183 = 13:int
	 *t184 = "22737367544323205...":string
	 t185 = &t55[43:int]
	 t186 = &t185.delta [#0]
	 t187 = &t185.cutoff [#1]
	 *t186 = 13:int
	 *t187 = "11368683772161602...":string
	 t188 = &t55[44:int]
	 t189 = &t188.delta [#0]
	 t190 = &t188.cutoff [#1]
	 *t189 = 14:int
	 *t190 = "56843418860808014...":string
	 t191 = &t55[45:int]
	 t192 = &t191.delta [#0]
	 t193 = &t191.cutoff [#1]
	 *t192 = 14:int
	 *t193 = "28421709430404007...":string
	 t194 = &t55[46:int]
	 t195 = &t194.delta [#0]
	 t196 = &t194.cutoff [#1]
	 *t195 = 14:int
	 *t196 = "14210854715202003...":string
	 t197 = &t55[47:int]
	 t198 = &t197.delta [#0]
	 t199 = &t197.cutoff [#1]
	 *t198 = 15:int
	 *t199 = "71054273576010018...":string
	 t200 = &t55[48:int]
	 t201 = &t200.delta [#0]
	 t202 = &t200.cutoff [#1]
	 *t201 = 15:int
	 *t202 = "35527136788005009...":string
	 t203 = &t55[49:int]
	 t204 = &t203.delta [#0]
	 t205 = &t203.cutoff [#1]
	 *t204 = 15:int
	 *t205 = "17763568394002504...":string
	 t206 = &t55[50:int]
	 t207 = &t206.delta [#0]
	 t208 = &t206.cutoff [#1]
	 *t207 = 16:int
	 *t208 = "88817841970012523...":string
	 t209 = &t55[51:int]
	 t210 = &t209.delta [#0]
	 t211 = &t209.cutoff [#1]
	 *t210 = 16:int
	 *t211 = "44408920985006261...":string
	 t212 = &t55[52:int]
	 t213 = &t212.delta [#0]
	 t214 = &t212.cutoff [#1]
	 *t213 = 16:int
	 *t214 = "22204460492503130...":string
	 t215 = &t55[53:int]
	 t216 = &t215.delta [#0]
	 t217 = &t215.cutoff [#1]
	 *t216 = 16:int
	 *t217 = "11102230246251565...":string
	 t218 = &t55[54:int]
	 t219 = &t218.delta [#0]
	 t220 = &t218.cutoff [#1]
	 *t219 = 17:int
	 *t220 = "55511151231257827...":string
	 t221 = &t55[55:int]
	 t222 = &t221.delta [#0]
	 t223 = &t221.cutoff [#1]
	 *t222 = 17:int
	 *t223 = "27755575615628913...":string
	 t224 = &t55[56:int]
	 t225 = &t224.delta [#0]
	 t226 = &t224.cutoff [#1]
	 *t225 = 17:int
	 *t226 = "13877787807814456...":string
	 t227 = &t55[57:int]
	 t228 = &t227.delta [#0]
	 t229 = &t227.cutoff [#1]
	 *t228 = 18:int
	 *t229 = "69388939039072283...":string
	 t230 = &t55[58:int]
	 t231 = &t230.delta [#0]
	 t232 = &t230.cutoff [#1]
	 *t231 = 18:int
	 *t232 = "34694469519536141...":string
	 t233 = &t55[59:int]
	 t234 = &t233.delta [#0]
	 t235 = &t233.cutoff [#1]
	 *t234 = 18:int
	 *t235 = "17347234759768070...":string
	 t236 = &t55[60:int]
	 t237 = &t236.delta [#0]
	 t238 = &t236.cutoff [#1]
	 *t237 = 19:int
	 *t238 = "86736173798840354...":string
	 t239 = slice t55[:]
	 *leftcheats = t239
	 t240 = &smallPowersOfTen[0:int]
	 t241 = &t240.mant [#0]
	 t242 = &t240.exp [#1]
	 t243 = &t240.neg [#2]
	 t244 = &smallPowersOfTen[1:int]
	 t245 = &t244.mant [#0]
	 t246 = &t244.exp [#1]
	 t247 = &t244.neg [#2]
	 t248 = &smallPowersOfTen[2:int]
	 t249 = &t248.mant [#0]
	 t250 = &t248.exp [#1]
	 t251 = &t248.neg [#2]
	 t252 = &smallPowersOfTen[3:int]
	 t253 = &t252.mant [#0]
	 t254 = &t252.exp [#1]
	 t255 = &t252.neg [#2]
	 t256 = &smallPowersOfTen[4:int]
	 t257 = &t256.mant [#0]
	 t258 = &t256.exp [#1]
	 t259 = &t256.neg [#2]
	 t260 = &smallPowersOfTen[5:int]
	 t261 = &t260.mant [#0]
	 t262 = &t260.exp [#1]
	 t263 = &t260.neg [#2]
	 t264 = &smallPowersOfTen[6:int]
	 t265 = &t264.mant [#0]
	 t266 = &t264.exp [#1]
	 t267 = &t264.neg [#2]
	 t268 = &smallPowersOfTen[7:int]
	 t269 = &t268.mant [#0]
	 t270 = &t268.exp [#1]
	 t271 = &t268.neg [#2]
	 *t241 = 9223372036854775808:uint64
	 *t242 = -63:int
	 *t243 = false:bool
	 *t245 = 11529215046068469760:uint64
	 *t246 = -60:int
	 *t247 = false:bool
	 *t249 = 14411518807585587200:uint64
	 *t250 = -57:int
	 *t251 = false:bool
	 *t253 = 18014398509481984000:uint64
	 *t254 = -54:int
	 *t255 = false:bool
	 *t257 = 11258999068426240000:uint64
	 *t258 = -50:int
	 *t259 = false:bool
	 *t261 = 14073748835532800000:uint64
	 *t262 = -47:int
	 *t263 = false:bool
	 *t265 = 17592186044416000000:uint64
	 *t266 = -44:int
	 *t267 = false:bool
	 *t269 = 10995116277760000000:uint64
	 *t270 = -40:int
	 *t271 = false:bool
	 t272 = &powersOfTen[0:int]
	 t273 = &t272.mant [#0]
	 t274 = &t272.exp [#1]
	 t275 = &t272.neg [#2]
	 t276 = &powersOfTen[1:int]
	 t277 = &t276.mant [#0]
	 t278 = &t276.exp [#1]
	 t279 = &t276.neg [#2]
	 t280 = &powersOfTen[2:int]
	 t281 = &t280.mant [#0]
	 t282 = &t280.exp [#1]
	 t283 = &t280.neg [#2]
	 t284 = &powersOfTen[3:int]
	 t285 = &t284.mant [#0]
	 t286 = &t284.exp [#1]
	 t287 = &t284.neg [#2]
	 t288 = &powersOfTen[4:int]
	 t289 = &t288.mant [#0]
	 t290 = &t288.exp [#1]
	 t291 = &t288.neg [#2]
	 t292 = &powersOfTen[5:int]
	 t293 = &t292.mant [#0]
	 t294 = &t292.exp [#1]
	 t295 = &t292.neg [#2]
	 t296 = &powersOfTen[6:int]
	 t297 = &t296.mant [#0]
	 t298 = &t296.exp [#1]
	 t299 = &t296.neg [#2]
	 t300 = &powersOfTen[7:int]
	 t301 = &t300.mant [#0]
	 t302 = &t300.exp [#1]
	 t303 = &t300.neg [#2]
	 t304 = &powersOfTen[8:int]
	 t305 = &t304.mant [#0]
	 t306 = &t304.exp [#1]
	 t307 = &t304.neg [#2]
	 t308 = &powersOfTen[9:int]
	 t309 = &t308.mant [#0]
	 t310 = &t308.exp [#1]
	 t311 = &t308.neg [#2]
	 t312 = &powersOfTen[10:int]
	 t313 = &t312.mant [#0]
	 t314 = &t312.exp [#1]
	 t315 = &t312.neg [#2]
	 t316 = &powersOfTen[11:int]
	 t317 = &t316.mant [#0]
	 t318 = &t316.exp [#1]
	 t319 = &t316.neg [#2]
	 t320 = &powersOfTen[12:int]
	 t321 = &t320.mant [#0]
	 t322 = &t320.exp [#1]
	 t323 = &t320.neg [#2]
	 t324 = &powersOfTen[13:int]
	 t325 = &t324.mant [#0]
	 t326 = &t324.exp [#1]
	 t327 = &t324.neg [#2]
	 t328 = &powersOfTen[14:int]
	 t329 = &t328.mant [#0]
	 t330 = &t328.exp [#1]
	 t331 = &t328.neg [#2]
	 t332 = &powersOfTen[15:int]
	 t333 = &t332.mant [#0]
	 t334 = &t332.exp [#1]
	 t335 = &t332.neg [#2]
	 t336 = &powersOfTen[16:int]
	 t337 = &t336.mant [#0]
	 t338 = &t336.exp [#1]
	 t339 = &t336.neg [#2]
	 t340 = &powersOfTen[17:int]
	 t341 = &t340.mant [#0]
	 t342 = &t340.exp [#1]
	 t343 = &t340.neg [#2]
	 t344 = &powersOfTen[18:int]
	 t345 = &t344.mant [#0]
	 t346 = &t344.exp [#1]
	 t347 = &t344.neg [#2]
	 t348 = &powersOfTen[19:int]
	 t349 = &t348.mant [#0]
	 t350 = &t348.exp [#1]
	 t351 = &t348.neg [#2]
	 t352 = &powersOfTen[20:int]
	 t353 = &t352.mant [#0]
	 t354 = &t352.exp [#1]
	 t355 = &t352.neg [#2]
	 t356 = &powersOfTen[21:int]
	 t357 = &t356.mant [#0]
	 t358 = &t356.exp [#1]
	 t359 = &t356.neg [#2]
	 t360 = &powersOfTen[22:int]
	 t361 = &t360.mant [#0]
	 t362 = &t360.exp [#1]
	 t363 = &t360.neg [#2]
	 t364 = &powersOfTen[23:int]
	 t365 = &t364.mant [#0]
	 t366 = &t364.exp [#1]
	 t367 = &t364.neg [#2]
	 t368 = &powersOfTen[24:int]
	 t369 = &t368.mant [#0]
	 t370 = &t368.exp [#1]
	 t371 = &t368.neg [#2]
	 t372 = &powersOfTen[25:int]
	 t373 = &t372.mant [#0]
	 t374 = &t372.exp [#1]
	 t375 = &t372.neg [#2]
	 t376 = &powersOfTen[26:int]
	 t377 = &t376.mant [#0]
	 t378 = &t376.exp [#1]
	 t379 = &t376.neg [#2]
	 t380 = &powersOfTen[27:int]
	 t381 = &t380.mant [#0]
	 t382 = &t380.exp [#1]
	 t383 = &t380.neg [#2]
	 t384 = &powersOfTen[28:int]
	 t385 = &t384.mant [#0]
	 t386 = &t384.exp [#1]
	 t387 = &t384.neg [#2]
	 t388 = &powersOfTen[29:int]
	 t389 = &t388.mant [#0]
	 t390 = &t388.exp [#1]
	 t391 = &t388.neg [#2]
	 t392 = &powersOfTen[30:int]
	 t393 = &t392.mant [#0]
	 t394 = &t392.exp [#1]
	 t395 = &t392.neg [#2]
	 t396 = &powersOfTen[31:int]
	 t397 = &t396.mant [#0]
	 t398 = &t396.exp [#1]
	 t399 = &t396.neg [#2]
	 t400 = &powersOfTen[32:int]
	 t401 = &t400.mant [#0]
	 t402 = &t400.exp [#1]
	 t403 = &t400.neg [#2]
	 t404 = &powersOfTen[33:int]
	 t405 = &t404.mant [#0]
	 t406 = &t404.exp [#1]
	 t407 = &t404.neg [#2]
	 t408 = &powersOfTen[34:int]
	 t409 = &t408.mant [#0]
	 t410 = &t408.exp [#1]
	 t411 = &t408.neg [#2]
	 t412 = &powersOfTen[35:int]
	 t413 = &t412.mant [#0]
	 t414 = &t412.exp [#1]
	 t415 = &t412.neg [#2]
	 t416 = &powersOfTen[36:int]
	 t417 = &t416.mant [#0]
	 t418 = &t416.exp [#1]
	 t419 = &t416.neg [#2]
	 t420 = &powersOfTen[37:int]
	 t421 = &t420.mant [#0]
	 t422 = &t420.exp [#1]
	 t423 = &t420.neg [#2]
	 t424 = &powersOfTen[38:int]
	 t425 = &t424.mant [#0]
	 t426 = &t424.exp [#1]
	 t427 = &t424.neg [#2]
	 t428 = &powersOfTen[39:int]
	 t429 = &t428.mant [#0]
	 t430 = &t428.exp [#1]
	 t431 = &t428.neg [#2]
	 t432 = &powersOfTen[40:int]
	 t433 = &t432.mant [#0]
	 t434 = &t432.exp [#1]
	 t435 = &t432.neg [#2]
	 t436 = &powersOfTen[41:int]
	 t437 = &t436.mant [#0]
	 t438 = &t436.exp [#1]
	 t439 = &t436.neg [#2]
	 t440 = &powersOfTen[42:int]
	 t441 = &t440.mant [#0]
	 t442 = &t440.exp [#1]
	 t443 = &t440.neg [#2]
	 t444 = &powersOfTen[43:int]
	 t445 = &t444.mant [#0]
	 t446 = &t444.exp [#1]
	 t447 = &t444.neg [#2]
	 t448 = &powersOfTen[44:int]
	 t449 = &t448.mant [#0]
	 t450 = &t448.exp [#1]
	 t451 = &t448.neg [#2]
	 t452 = &powersOfTen[45:int]
	 t453 = &t452.mant [#0]
	 t454 = &t452.exp [#1]
	 t455 = &t452.neg [#2]
	 t456 = &powersOfTen[46:int]
	 t457 = &t456.mant [#0]
	 t458 = &t456.exp [#1]
	 t459 = &t456.neg [#2]
	 t460 = &powersOfTen[47:int]
	 t461 = &t460.mant [#0]
	 t462 = &t460.exp [#1]
	 t463 = &t460.neg [#2]
	 t464 = &powersOfTen[48:int]
	 t465 = &t464.mant [#0]
	 t466 = &t464.exp [#1]
	 t467 = &t464.neg [#2]
	 t468 = &powersOfTen[49:int]
	 t469 = &t468.mant [#0]
	 t470 = &t468.exp [#1]
	 t471 = &t468.neg [#2]
	 t472 = &powersOfTen[50:int]
	 t473 = &t472.mant [#0]
	 t474 = &t472.exp [#1]
	 t475 = &t472.neg [#2]
	 t476 = &powersOfTen[51:int]
	 t477 = &t476.mant [#0]
	 t478 = &t476.exp [#1]
	 t479 = &t476.neg [#2]
	 t480 = &powersOfTen[52:int]
	 t481 = &t480.mant [#0]
	 t482 = &t480.exp [#1]
	 t483 = &t480.neg [#2]
	 t484 = &powersOfTen[53:int]
	 t485 = &t484.mant [#0]
	 t486 = &t484.exp [#1]
	 t487 = &t484.neg [#2]
	 t488 = &powersOfTen[54:int]
	 t489 = &t488.mant [#0]
	 t490 = &t488.exp [#1]
	 t491 = &t488.neg [#2]
	 t492 = &powersOfTen[55:int]
	 t493 = &t492.mant [#0]
	 t494 = &t492.exp [#1]
	 t495 = &t492.neg [#2]
	 t496 = &powersOfTen[56:int]
	 t497 = &t496.mant [#0]
	 t498 = &t496.exp [#1]
	 t499 = &t496.neg [#2]
	 t500 = &powersOfTen[57:int]
	 t501 = &t500.mant [#0]
	 t502 = &t500.exp [#1]
	 t503 = &t500.neg [#2]
	 t504 = &powersOfTen[58:int]
	 t505 = &t504.mant [#0]
	 t506 = &t504.exp [#1]
	 t507 = &t504.neg [#2]
	 t508 = &powersOfTen[59:int]
	 t509 = &t508.mant [#0]
	 t510 = &t508.exp [#1]
	 t511 = &t508.neg [#2]
	 t512 = &powersOfTen[60:int]
	 t513 = &t512.mant [#0]
	 t514 = &t512.exp [#1]
	 t515 = &t512.neg [#2]
	 t516 = &powersOfTen[61:int]
	 t517 = &t516.mant [#0]
	 t518 = &t516.exp [#1]
	 t519 = &t516.neg [#2]
	 t520 = &powersOfTen[62:int]
	 t521 = &t520.mant [#0]
	 t522 = &t520.exp [#1]
	 t523 = &t520.neg [#2]
	 t524 = &powersOfTen[63:int]
	 t525 = &t524.mant [#0]
	 t526 = &t524.exp [#1]
	 t527 = &t524.neg [#2]
	 t528 = &powersOfTen[64:int]
	 t529 = &t528.mant [#0]
	 t530 = &t528.exp [#1]
	 t531 = &t528.neg [#2]
	 t532 = &powersOfTen[65:int]
	 t533 = &t532.mant [#0]
	 t534 = &t532.exp [#1]
	 t535 = &t532.neg [#2]
	 t536 = &powersOfTen[66:int]
	 t537 = &t536.mant [#0]
	 t538 = &t536.exp [#1]
	 t539 = &t536.neg [#2]
	 t540 = &powersOfTen[67:int]
	 t541 = &t540.mant [#0]
	 t542 = &t540.exp [#1]
	 t543 = &t540.neg [#2]
	 t544 = &powersOfTen[68:int]
	 t545 = &t544.mant [#0]
	 t546 = &t544.exp [#1]
	 t547 = &t544.neg [#2]
	 t548 = &powersOfTen[69:int]
	 t549 = &t548.mant [#0]
	 t550 = &t548.exp [#1]
	 t551 = &t548.neg [#2]
	 t552 = &powersOfTen[70:int]
	 t553 = &t552.mant [#0]
	 t554 = &t552.exp [#1]
	 t555 = &t552.neg [#2]
	 t556 = &powersOfTen[71:int]
	 t557 = &t556.mant [#0]
	 t558 = &t556.exp [#1]
	 t559 = &t556.neg [#2]
	 t560 = &powersOfTen[72:int]
	 t561 = &t560.mant [#0]
	 t562 = &t560.exp [#1]
	 t563 = &t560.neg [#2]
	 t564 = &powersOfTen[73:int]
	 t565 = &t564.mant [#0]
	 t566 = &t564.exp [#1]
	 t567 = &t564.neg [#2]
	 t568 = &powersOfTen[74:int]
	 t569 = &t568.mant [#0]
	 t570 = &t568.exp [#1]
	 t571 = &t568.neg [#2]
	 t572 = &powersOfTen[75:int]
	 t573 = &t572.mant [#0]
	 t574 = &t572.exp [#1]
	 t575 = &t572.neg [#2]
	 t576 = &powersOfTen[76:int]
	 t577 = &t576.mant [#0]
	 t578 = &t576.exp [#1]
	 t579 = &t576.neg [#2]
	 t580 = &powersOfTen[77:int]
	 t581 = &t580.mant [#0]
	 t582 = &t580.exp [#1]
	 t583 = &t580.neg [#2]
	 t584 = &powersOfTen[78:int]
	 t585 = &t584.mant [#0]
	 t586 = &t584.exp [#1]
	 t587 = &t584.neg [#2]
	 t588 = &powersOfTen[79:int]
	 t589 = &t588.mant [#0]
	 t590 = &t588.exp [#1]
	 t591 = &t588.neg [#2]
	 t592 = &powersOfTen[80:int]
	 t593 = &t592.mant [#0]
	 t594 = &t592.exp [#1]
	 t595 = &t592.neg [#2]
	 t596 = &powersOfTen[81:int]
	 t597 = &t596.mant [#0]
	 t598 = &t596.exp [#1]
	 t599 = &t596.neg [#2]
	 t600 = &powersOfTen[82:int]
	 t601 = &t600.mant [#0]
	 t602 = &t600.exp [#1]
	 t603 = &t600.neg [#2]
	 t604 = &powersOfTen[83:int]
	 t605 = &t604.mant [#0]
	 t606 = &t604.exp [#1]
	 t607 = &t604.neg [#2]
	 t608 = &powersOfTen[84:int]
	 t609 = &t608.mant [#0]
	 t610 = &t608.exp [#1]
	 t611 = &t608.neg [#2]
	 t612 = &powersOfTen[85:int]
	 t613 = &t612.mant [#0]
	 t614 = &t612.exp [#1]
	 t615 = &t612.neg [#2]
	 t616 = &powersOfTen[86:int]
	 t617 = &t616.mant [#0]
	 t618 = &t616.exp [#1]
	 t619 = &t616.neg [#2]
	 *t273 = 18054884314459144840:uint64
	 *t274 = -1220:int
	 *t275 = false:bool
	 *t277 = 13451937075301367670:uint64
	 *t278 = -1193:int
	 *t279 = false:bool
	 *t281 = 10022474136428063862:uint64
	 *t282 = -1166:int
	 *t283 = false:bool
	 *t285 = 14934650266808366570:uint64
	 *t286 = -1140:int
	 *t287 = false:bool
	 *t289 = 11127181549972568877:uint64
	 *t290 = -1113:int
	 *t291 = false:bool
	 *t293 = 16580792590934885855:uint64
	 *t294 = -1087:int
	 *t295 = false:bool
	 *t297 = 12353653155963782858:uint64
	 *t298 = -1060:int
	 *t299 = false:bool
	 *t301 = 18408377700990114895:uint64
	 *t302 = -1034:int
	 *t303 = false:bool
	 *t305 = 13715310171984221708:uint64
	 *t306 = -1007:int
	 *t307 = false:bool
	 *t309 = 10218702384817765436:uint64
	 *t310 = -980:int
	 *t311 = false:bool
	 *t313 = 15227053142812498563:uint64
	 *t314 = -954:int
	 *t315 = false:bool
	 *t317 = 11345038669416679861:uint64
	 *t318 = -927:int
	 *t319 = false:bool
	 *t321 = 16905424996341287883:uint64
	 *t322 = -901:int
	 *t323 = false:bool
	 *t325 = 12595523146049147757:uint64
	 *t326 = -874:int
	 *t327 = false:bool
	 *t329 = 9384396036005875287:uint64
	 *t330 = -847:int
	 *t331 = false:bool
	 *t333 = 13983839803942852151:uint64
	 *t334 = -821:int
	 *t335 = false:bool
	 *t337 = 10418772551374772303:uint64
	 *t338 = -794:int
	 *t339 = false:bool
	 *t341 = 15525180923007089351:uint64
	 *t342 = -768:int
	 *t343 = false:bool
	 *t345 = 11567161174868858868:uint64
	 *t346 = -741:int
	 *t347 = false:bool
	 *t349 = 17236413322193710309:uint64
	 *t350 = -715:int
	 *t351 = false:bool
	 *t353 = 12842128665889583758:uint64
	 *t354 = -688:int
	 *t355 = false:bool
	 *t357 = 9568131466127621947:uint64
	 *t358 = -661:int
	 *t359 = false:bool
	 *t361 = 14257626930069360058:uint64
	 *t362 = -635:int
	 *t363 = false:bool
	 *t365 = 10622759856335341974:uint64
	 *t366 = -608:int
	 *t367 = false:bool
	 *t369 = 15829145694278690180:uint64
	 *t370 = -582:int
	 *t371 = false:bool
	 *t373 = 11793632577567316726:uint64
	 *t374 = -555:int
	 *t375 = false:bool
	 *t377 = 17573882009934360870:uint64
	 *t378 = -529:int
	 *t379 = false:bool
	 *t381 = 13093562431584567480:uint64
	 *t382 = -502:int
	 *t383 = false:bool
	 *t385 = 9755464219737475723:uint64
	 *t386 = -475:int
	 *t387 = false:bool
	 *t389 = 14536774485912137811:uint64
	 *t390 = -449:int
	 *t391 = false:bool
	 *t393 = 10830740992659433045:uint64
	 *t394 = -422:int
	 *t395 = false:bool
	 *t397 = 16139061738043178685:uint64
	 *t398 = -396:int
	 *t399 = false:bool
	 *t401 = 12024538023802026127:uint64
	 *t402 = -369:int
	 *t403 = false:bool
	 *t405 = 17917957937422433684:uint64
	 *t406 = -343:int
	 *t407 = false:bool
	 *t409 = 13349918974505688015:uint64
	 *t410 = -316:int
	 *t411 = false:bool
	 *t413 = 9946464728195732843:uint64
	 *t414 = -289:int
	 *t415 = false:bool
	 *t417 = 14821387422376473014:uint64
	 *t418 = -263:int
	 *t419 = false:bool
	 *t421 = 11042794154864902060:uint64
	 *t422 = -236:int
	 *t423 = false:bool
	 *t425 = 16455045573212060422:uint64
	 *t426 = -210:int
	 *t427 = false:bool
	 *t429 = 12259964326927110867:uint64
	 *t430 = -183:int
	 *t431 = false:bool
	 *t433 = 18268770466636286478:uint64
	 *t434 = -157:int
	 *t435 = false:bool
	 *t437 = 13611294676837538539:uint64
	 *t438 = -130:int
	 *t439 = false:bool
	 *t441 = 10141204801825835212:uint64
	 *t442 = -103:int
	 *t443 = false:bool
	 *t445 = 15111572745182864684:uint64
	 *t446 = -77:int
	 *t447 = false:bool
	 *t449 = 11258999068426240000:uint64
	 *t450 = -50:int
	 *t451 = false:bool
	 *t453 = 16777216000000000000:uint64
	 *t454 = -24:int
	 *t455 = false:bool
	 *t457 = 12500000000000000000:uint64
	 *t458 = 3:int
	 *t459 = false:bool
	 *t461 = 9313225746154785156:uint64
	 *t462 = 30:int
	 *t463 = false:bool
	 *t465 = 13877787807814456755:uint64
	 *t466 = 56:int
	 *t467 = false:bool
	 *t469 = 10339757656912845936:uint64
	 *t470 = 83:int
	 *t471 = false:bool
	 *t473 = 15407439555097886824:uint64
	 *t474 = 109:int
	 *t475 = false:bool
	 *t477 = 11479437019748901445:uint64
	 *t478 = 136:int
	 *t479 = false:bool
	 *t481 = 17105694144590052135:uint64
	 *t482 = 162:int
	 *t483 = false:bool
	 *t485 = 12744735289059618216:uint64
	 *t486 = 189:int
	 *t487 = false:bool
	 *t489 = 9495567745759798747:uint64
	 *t490 = 216:int
	 *t491 = false:bool
	 *t493 = 14149498560666738074:uint64
	 *t494 = 242:int
	 *t495 = false:bool
	 *t497 = 10542197943230523224:uint64
	 *t498 = 269:int
	 *t499 = false:bool
	 *t501 = 15709099088952724970:uint64
	 *t502 = 295:int
	 *t503 = false:bool
	 *t505 = 11704190886730495818:uint64
	 *t506 = 322:int
	 *t507 = false:bool
	 *t509 = 17440603504673385349:uint64
	 *t510 = 348:int
	 *t511 = false:bool
	 *t513 = 12994262207056124023:uint64
	 *t514 = 375:int
	 *t515 = false:bool
	 *t517 = 9681479787123295682:uint64
	 *t518 = 402:int
	 *t519 = false:bool
	 *t521 = 14426529090290212157:uint64
	 *t522 = 428:int
	 *t523 = false:bool
	 *t525 = 10748601772107342003:uint64
	 *t526 = 455:int
	 *t527 = false:bool
	 *t529 = 16016664761464807395:uint64
	 *t530 = 481:int
	 *t531 = false:bool
	 *t533 = 11933345169920330789:uint64
	 *t534 = 508:int
	 *t535 = false:bool
	 *t537 = 17782069995880619868:uint64
	 *t538 = 534:int
	 *t539 = false:bool
	 *t541 = 13248674568444952270:uint64
	 *t542 = 561:int
	 *t543 = false:bool
	 *t545 = 9871031767461413346:uint64
	 *t546 = 588:int
	 *t547 = false:bool
	 *t549 = 14708983551653345445:uint64
	 *t550 = 614:int
	 *t551 = false:bool
	 *t553 = 10959046745042015199:uint64
	 *t554 = 641:int
	 *t555 = false:bool
	 *t557 = 16330252207878254650:uint64
	 *t558 = 667:int
	 *t559 = false:bool
	 *t561 = 12166986024289022870:uint64
	 *t562 = 694:int
	 *t563 = false:bool
	 *t565 = 18130221999122236476:uint64
	 *t566 = 720:int
	 *t567 = false:bool
	 *t569 = 13508068024458167312:uint64
	 *t570 = 747:int
	 *t571 = false:bool
	 *t573 = 10064294952495520794:uint64
	 *t574 = 774:int
	 *t575 = false:bool
	 *t577 = 14996968138956309548:uint64
	 *t578 = 800:int
	 *t579 = false:bool
	 *t581 = 11173611982879273257:uint64
	 *t582 = 827:int
	 *t583 = false:bool
	 *t585 = 16649979327439178909:uint64
	 *t586 = 853:int
	 *t587 = false:bool
	 *t589 = 12405201291620119593:uint64
	 *t590 = 880:int
	 *t591 = false:bool
	 *t593 = 9242595204427927429:uint64
	 *t594 = 907:int
	 *t595 = false:bool
	 *t597 = 13772540099066387757:uint64
	 *t598 = 933:int
	 *t599 = false:bool
	 *t601 = 10261342003245940623:uint64
	 *t602 = 960:int
	 *t603 = false:bool
	 *t605 = 15290591125556738113:uint64
	 *t606 = 986:int
	 *t607 = false:bool
	 *t609 = 11392378155556871081:uint64
	 *t610 = 1013:int
	 *t611 = false:bool
	 *t613 = 16975966327722178521:uint64
	 *t614 = 1039:int
	 *t615 = false:bool
	 *t617 = 12648080533535911531:uint64
	 *t618 = 1066:int
	 *t619 = false:bool
	 t620 = &uint64pow10[0:int]
	 t621 = &uint64pow10[1:int]
	 t622 = &uint64pow10[2:int]
	 t623 = &uint64pow10[3:int]
	 t624 = &uint64pow10[4:int]
	 t625 = &uint64pow10[5:int]
	 t626 = &uint64pow10[6:int]
	 t627 = &uint64pow10[7:int]
	 t628 = &uint64pow10[8:int]
	 t629 = &uint64pow10[9:int]
	 t630 = &uint64pow10[10:int]
	 t631 = &uint64pow10[11:int]
	 t632 = &uint64pow10[12:int]
	 t633 = &uint64pow10[13:int]
	 t634 = &uint64pow10[14:int]
	 t635 = &uint64pow10[15:int]
	 t636 = &uint64pow10[16:int]
	 t637 = &uint64pow10[17:int]
	 t638 = &uint64pow10[18:int]
	 t639 = &uint64pow10[19:int]
	 *t620 = 1:uint64
	 *t621 = 10:uint64
	 *t622 = 100:uint64
	 *t623 = 1000:uint64
	 *t624 = 10000:uint64
	 *t625 = 100000:uint64
	 *t626 = 1000000:uint64
	 *t627 = 10000000:uint64
	 *t628 = 100000000:uint64
	 *t629 = 1000000000:uint64
	 *t630 = 10000000000:uint64
	 *t631 = 100000000000:uint64
	 *t632 = 1000000000000:uint64
	 *t633 = 10000000000000:uint64
	 *t634 = 100000000000000:uint64
	 *t635 = 1000000000000000:uint64
	 *t636 = 10000000000000000:uint64
	 *t637 = 100000000000000000:uint64
	 *t638 = 1000000000000000000:uint64
	 *t639 = 10000000000000000000:uint64
	 t640 = &float32info.mantbits [#0]
	 t641 = &float32info.expbits [#1]
	 t642 = &float32info.bias [#2]
	 *t640 = 23:uint
	 *t641 = 8:uint
	 *t642 = -127:int
	 t643 = &float64info.mantbits [#0]
	 t644 = &float64info.expbits [#1]
	 t645 = &float64info.bias [#2]
	 *t643 = 52:uint
	 *t644 = 11:uint
	 *t645 = -1023:int
	 t646 = new [462]uint16 (slicelit)
	 t647 = &t646[0:int]
	 *t647 = 32:uint16
	 t648 = &t646[1:int]
	 *t648 = 126:uint16
	 t649 = &t646[2:int]
	 *t649 = 161:uint16
	 t650 = &t646[3:int]
	 *t650 = 887:uint16
	 t651 = &t646[4:int]
	 *t651 = 890:uint16
	 t652 = &t646[5:int]
	 *t652 = 895:uint16
	 t653 = &t646[6:int]
	 *t653 = 900:uint16
	 t654 = &t646[7:int]
	 *t654 = 1366:uint16
	 t655 = &t646[8:int]
	 *t655 = 1369:uint16
	 t656 = &t646[9:int]
	 *t656 = 1418:uint16
	 t657 = &t646[10:int]
	 *t657 = 1421:uint16
	 t658 = &t646[11:int]
	 *t658 = 1479:uint16
	 t659 = &t646[12:int]
	 *t659 = 1488:uint16
	 t660 = &t646[13:int]
	 *t660 = 1514:uint16
	 t661 = &t646[14:int]
	 *t661 = 1520:uint16
	 t662 = &t646[15:int]
	 *t662 = 1524:uint16
	 t663 = &t646[16:int]
	 *t663 = 1542:uint16
	 t664 = &t646[17:int]
	 *t664 = 1563:uint16
	 t665 = &t646[18:int]
	 *t665 = 1566:uint16
	 t666 = &t646[19:int]
	 *t666 = 1805:uint16
	 t667 = &t646[20:int]
	 *t667 = 1808:uint16
	 t668 = &t646[21:int]
	 *t668 = 1866:uint16
	 t669 = &t646[22:int]
	 *t669 = 1869:uint16
	 t670 = &t646[23:int]
	 *t670 = 1969:uint16
	 t671 = &t646[24:int]
	 *t671 = 1984:uint16
	 t672 = &t646[25:int]
	 *t672 = 2042:uint16
	 t673 = &t646[26:int]
	 *t673 = 2048:uint16
	 t674 = &t646[27:int]
	 *t674 = 2093:uint16
	 t675 = &t646[28:int]
	 *t675 = 2096:uint16
	 t676 = &t646[29:int]
	 *t676 = 2139:uint16
	 t677 = &t646[30:int]
	 *t677 = 2142:uint16
	 t678 = &t646[31:int]
	 *t678 = 2142:uint16
	 t679 = &t646[32:int]
	 *t679 = 2208:uint16
	 t680 = &t646[33:int]
	 *t680 = 2237:uint16
	 t681 = &t646[34:int]
	 *t681 = 2260:uint16
	 t682 = &t646[35:int]
	 *t682 = 2444:uint16
	 t683 = &t646[36:int]
	 *t683 = 2447:uint16
	 t684 = &t646[37:int]
	 *t684 = 2448:uint16
	 t685 = &t646[38:int]
	 *t685 = 2451:uint16
	 t686 = &t646[39:int]
	 *t686 = 2482:uint16
	 t687 = &t646[40:int]
	 *t687 = 2486:uint16
	 t688 = &t646[41:int]
	 *t688 = 2489:uint16
	 t689 = &t646[42:int]
	 *t689 = 2492:uint16
	 t690 = &t646[43:int]
	 *t690 = 2500:uint16
	 t691 = &t646[44:int]
	 *t691 = 2503:uint16
	 t692 = &t646[45:int]
	 *t692 = 2504:uint16
	 t693 = &t646[46:int]
	 *t693 = 2507:uint16
	 t694 = &t646[47:int]
	 *t694 = 2510:uint16
	 t695 = &t646[48:int]
	 *t695 = 2519:uint16
	 t696 = &t646[49:int]
	 *t696 = 2519:uint16
	 t697 = &t646[50:int]
	 *t697 = 2524:uint16
	 t698 = &t646[51:int]
	 *t698 = 2531:uint16
	 t699 = &t646[52:int]
	 *t699 = 2534:uint16
	 t700 = &t646[53:int]
	 *t700 = 2555:uint16
	 t701 = &t646[54:int]
	 *t701 = 2561:uint16
	 t702 = &t646[55:int]
	 *t702 = 2570:uint16
	 t703 = &t646[56:int]
	 *t703 = 2575:uint16
	 t704 = &t646[57:int]
	 *t704 = 2576:uint16
	 t705 = &t646[58:int]
	 *t705 = 2579:uint16
	 t706 = &t646[59:int]
	 *t706 = 2617:uint16
	 t707 = &t646[60:int]
	 *t707 = 2620:uint16
	 t708 = &t646[61:int]
	 *t708 = 2626:uint16
	 t709 = &t646[62:int]
	 *t709 = 2631:uint16
	 t710 = &t646[63:int]
	 *t710 = 2632:uint16
	 t711 = &t646[64:int]
	 *t711 = 2635:uint16
	 t712 = &t646[65:int]
	 *t712 = 2637:uint16
	 t713 = &t646[66:int]
	 *t713 = 2641:uint16
	 t714 = &t646[67:int]
	 *t714 = 2641:uint16
	 t715 = &t646[68:int]
	 *t715 = 2649:uint16
	 t716 = &t646[69:int]
	 *t716 = 2654:uint16
	 t717 = &t646[70:int]
	 *t717 = 2662:uint16
	 t718 = &t646[71:int]
	 *t718 = 2677:uint16
	 t719 = &t646[72:int]
	 *t719 = 2689:uint16
	 t720 = &t646[73:int]
	 *t720 = 2745:uint16
	 t721 = &t646[74:int]
	 *t721 = 2748:uint16
	 t722 = &t646[75:int]
	 *t722 = 2765:uint16
	 t723 = &t646[76:int]
	 *t723 = 2768:uint16
	 t724 = &t646[77:int]
	 *t724 = 2768:uint16
	 t725 = &t646[78:int]
	 *t725 = 2784:uint16
	 t726 = &t646[79:int]
	 *t726 = 2787:uint16
	 t727 = &t646[80:int]
	 *t727 = 2790:uint16
	 t728 = &t646[81:int]
	 *t728 = 2801:uint16
	 t729 = &t646[82:int]
	 *t729 = 2809:uint16
	 t730 = &t646[83:int]
	 *t730 = 2809:uint16
	 t731 = &t646[84:int]
	 *t731 = 2817:uint16
	 t732 = &t646[85:int]
	 *t732 = 2828:uint16
	 t733 = &t646[86:int]
	 *t733 = 2831:uint16
	 t734 = &t646[87:int]
	 *t734 = 2832:uint16
	 t735 = &t646[88:int]
	 *t735 = 2835:uint16
	 t736 = &t646[89:int]
	 *t736 = 2873:uint16
	 t737 = &t646[90:int]
	 *t737 = 2876:uint16
	 t738 = &t646[91:int]
	 *t738 = 2884:uint16
	 t739 = &t646[92:int]
	 *t739 = 2887:uint16
	 t740 = &t646[93:int]
	 *t740 = 2888:uint16
	 t741 = &t646[94:int]
	 *t741 = 2891:uint16
	 t742 = &t646[95:int]
	 *t742 = 2893:uint16
	 t743 = &t646[96:int]
	 *t743 = 2902:uint16
	 t744 = &t646[97:int]
	 *t744 = 2903:uint16
	 t745 = &t646[98:int]
	 *t745 = 2908:uint16
	 t746 = &t646[99:int]
	 *t746 = 2915:uint16
	 t747 = &t646[100:int]
	 *t747 = 2918:uint16
	 t748 = &t646[101:int]
	 *t748 = 2935:uint16
	 t749 = &t646[102:int]
	 *t749 = 2946:uint16
	 t750 = &t646[103:int]
	 *t750 = 2954:uint16
	 t751 = &t646[104:int]
	 *t751 = 2958:uint16
	 t752 = &t646[105:int]
	 *t752 = 2965:uint16
	 t753 = &t646[106:int]
	 *t753 = 2969:uint16
	 t754 = &t646[107:int]
	 *t754 = 2975:uint16
	 t755 = &t646[108:int]
	 *t755 = 2979:uint16
	 t756 = &t646[109:int]
	 *t756 = 2980:uint16
	 t757 = &t646[110:int]
	 *t757 = 2984:uint16
	 t758 = &t646[111:int]
	 *t758 = 2986:uint16
	 t759 = &t646[112:int]
	 *t759 = 2990:uint16
	 t760 = &t646[113:int]
	 *t760 = 3001:uint16
	 t761 = &t646[114:int]
	 *t761 = 3006:uint16
	 t762 = &t646[115:int]
	 *t762 = 3010:uint16
	 t763 = &t646[116:int]
	 *t763 = 3014:uint16
	 t764 = &t646[117:int]
	 *t764 = 3021:uint16
	 t765 = &t646[118:int]
	 *t765 = 3024:uint16
	 t766 = &t646[119:int]
	 *t766 = 3024:uint16
	 t767 = &t646[120:int]
	 *t767 = 3031:uint16
	 t768 = &t646[121:int]
	 *t768 = 3031:uint16
	 t769 = &t646[122:int]
	 *t769 = 3046:uint16
	 t770 = &t646[123:int]
	 *t770 = 3066:uint16
	 t771 = &t646[124:int]
	 *t771 = 3072:uint16
	 t772 = &t646[125:int]
	 *t772 = 3129:uint16
	 t773 = &t646[126:int]
	 *t773 = 3133:uint16
	 t774 = &t646[127:int]
	 *t774 = 3149:uint16
	 t775 = &t646[128:int]
	 *t775 = 3157:uint16
	 t776 = &t646[129:int]
	 *t776 = 3162:uint16
	 t777 = &t646[130:int]
	 *t777 = 3168:uint16
	 t778 = &t646[131:int]
	 *t778 = 3171:uint16
	 t779 = &t646[132:int]
	 *t779 = 3174:uint16
	 t780 = &t646[133:int]
	 *t780 = 3183:uint16
	 t781 = &t646[134:int]
	 *t781 = 3192:uint16
	 t782 = &t646[135:int]
	 *t782 = 3257:uint16
	 t783 = &t646[136:int]
	 *t783 = 3260:uint16
	 t784 = &t646[137:int]
	 *t784 = 3277:uint16
	 t785 = &t646[138:int]
	 *t785 = 3285:uint16
	 t786 = &t646[139:int]
	 *t786 = 3286:uint16
	 t787 = &t646[140:int]
	 *t787 = 3294:uint16
	 t788 = &t646[141:int]
	 *t788 = 3299:uint16
	 t789 = &t646[142:int]
	 *t789 = 3302:uint16
	 t790 = &t646[143:int]
	 *t790 = 3314:uint16
	 t791 = &t646[144:int]
	 *t791 = 3329:uint16
	 t792 = &t646[145:int]
	 *t792 = 3386:uint16
	 t793 = &t646[146:int]
	 *t793 = 3389:uint16
	 t794 = &t646[147:int]
	 *t794 = 3407:uint16
	 t795 = &t646[148:int]
	 *t795 = 3412:uint16
	 t796 = &t646[149:int]
	 *t796 = 3427:uint16
	 t797 = &t646[150:int]
	 *t797 = 3430:uint16
	 t798 = &t646[151:int]
	 *t798 = 3455:uint16
	 t799 = &t646[152:int]
	 *t799 = 3458:uint16
	 t800 = &t646[153:int]
	 *t800 = 3478:uint16
	 t801 = &t646[154:int]
	 *t801 = 3482:uint16
	 t802 = &t646[155:int]
	 *t802 = 3517:uint16
	 t803 = &t646[156:int]
	 *t803 = 3520:uint16
	 t804 = &t646[157:int]
	 *t804 = 3526:uint16
	 t805 = &t646[158:int]
	 *t805 = 3530:uint16
	 t806 = &t646[159:int]
	 *t806 = 3530:uint16
	 t807 = &t646[160:int]
	 *t807 = 3535:uint16
	 t808 = &t646[161:int]
	 *t808 = 3551:uint16
	 t809 = &t646[162:int]
	 *t809 = 3558:uint16
	 t810 = &t646[163:int]
	 *t810 = 3567:uint16
	 t811 = &t646[164:int]
	 *t811 = 3570:uint16
	 t812 = &t646[165:int]
	 *t812 = 3572:uint16
	 t813 = &t646[166:int]
	 *t813 = 3585:uint16
	 t814 = &t646[167:int]
	 *t814 = 3642:uint16
	 t815 = &t646[168:int]
	 *t815 = 3647:uint16
	 t816 = &t646[169:int]
	 *t816 = 3675:uint16
	 t817 = &t646[170:int]
	 *t817 = 3713:uint16
	 t818 = &t646[171:int]
	 *t818 = 3716:uint16
	 t819 = &t646[172:int]
	 *t819 = 3719:uint16
	 t820 = &t646[173:int]
	 *t820 = 3722:uint16
	 t821 = &t646[174:int]
	 *t821 = 3725:uint16
	 t822 = &t646[175:int]
	 *t822 = 3725:uint16
	 t823 = &t646[176:int]
	 *t823 = 3732:uint16
	 t824 = &t646[177:int]
	 *t824 = 3751:uint16
	 t825 = &t646[178:int]
	 *t825 = 3754:uint16
	 t826 = &t646[179:int]
	 *t826 = 3773:uint16
	 t827 = &t646[180:int]
	 *t827 = 3776:uint16
	 t828 = &t646[181:int]
	 *t828 = 3789:uint16
	 t829 = &t646[182:int]
	 *t829 = 3792:uint16
	 t830 = &t646[183:int]
	 *t830 = 3801:uint16
	 t831 = &t646[184:int]
	 *t831 = 3804:uint16
	 t832 = &t646[185:int]
	 *t832 = 3807:uint16
	 t833 = &t646[186:int]
	 *t833 = 3840:uint16
	 t834 = &t646[187:int]
	 *t834 = 3948:uint16
	 t835 = &t646[188:int]
	 *t835 = 3953:uint16
	 t836 = &t646[189:int]
	 *t836 = 4058:uint16
	 t837 = &t646[190:int]
	 *t837 = 4096:uint16
	 t838 = &t646[191:int]
	 *t838 = 4295:uint16
	 t839 = &t646[192:int]
	 *t839 = 4301:uint16
	 t840 = &t646[193:int]
	 *t840 = 4301:uint16
	 t841 = &t646[194:int]
	 *t841 = 4304:uint16
	 t842 = &t646[195:int]
	 *t842 = 4685:uint16
	 t843 = &t646[196:int]
	 *t843 = 4688:uint16
	 t844 = &t646[197:int]
	 *t844 = 4701:uint16
	 t845 = &t646[198:int]
	 *t845 = 4704:uint16
	 t846 = &t646[199:int]
	 *t846 = 4749:uint16
	 t847 = &t646[200:int]
	 *t847 = 4752:uint16
	 t848 = &t646[201:int]
	 *t848 = 4789:uint16
	 t849 = &t646[202:int]
	 *t849 = 4792:uint16
	 t850 = &t646[203:int]
	 *t850 = 4805:uint16
	 t851 = &t646[204:int]
	 *t851 = 4808:uint16
	 t852 = &t646[205:int]
	 *t852 = 4885:uint16
	 t853 = &t646[206:int]
	 *t853 = 4888:uint16
	 t854 = &t646[207:int]
	 *t854 = 4954:uint16
	 t855 = &t646[208:int]
	 *t855 = 4957:uint16
	 t856 = &t646[209:int]
	 *t856 = 4988:uint16
	 t857 = &t646[210:int]
	 *t857 = 4992:uint16
	 t858 = &t646[211:int]
	 *t858 = 5017:uint16
	 t859 = &t646[212:int]
	 *t859 = 5024:uint16
	 t860 = &t646[213:int]
	 *t860 = 5109:uint16
	 t861 = &t646[214:int]
	 *t861 = 5112:uint16
	 t862 = &t646[215:int]
	 *t862 = 5117:uint16
	 t863 = &t646[216:int]
	 *t863 = 5120:uint16
	 t864 = &t646[217:int]
	 *t864 = 5788:uint16
	 t865 = &t646[218:int]
	 *t865 = 5792:uint16
	 t866 = &t646[219:int]
	 *t866 = 5880:uint16
	 t867 = &t646[220:int]
	 *t867 = 5888:uint16
	 t868 = &t646[221:int]
	 *t868 = 5908:uint16
	 t869 = &t646[222:int]
	 *t869 = 5920:uint16
	 t870 = &t646[223:int]
	 *t870 = 5942:uint16
	 t871 = &t646[224:int]
	 *t871 = 5952:uint16
	 t872 = &t646[225:int]
	 *t872 = 5971:uint16
	 t873 = &t646[226:int]
	 *t873 = 5984:uint16
	 t874 = &t646[227:int]
	 *t874 = 6003:uint16
	 t875 = &t646[228:int]
	 *t875 = 6016:uint16
	 t876 = &t646[229:int]
	 *t876 = 6109:uint16
	 t877 = &t646[230:int]
	 *t877 = 6112:uint16
	 t878 = &t646[231:int]
	 *t878 = 6121:uint16
	 t879 = &t646[232:int]
	 *t879 = 6128:uint16
	 t880 = &t646[233:int]
	 *t880 = 6137:uint16
	 t881 = &t646[234:int]
	 *t881 = 6144:uint16
	 t882 = &t646[235:int]
	 *t882 = 6157:uint16
	 t883 = &t646[236:int]
	 *t883 = 6160:uint16
	 t884 = &t646[237:int]
	 *t884 = 6169:uint16
	 t885 = &t646[238:int]
	 *t885 = 6176:uint16
	 t886 = &t646[239:int]
	 *t886 = 6263:uint16
	 t887 = &t646[240:int]
	 *t887 = 6272:uint16
	 t888 = &t646[241:int]
	 *t888 = 6314:uint16
	 t889 = &t646[242:int]
	 *t889 = 6320:uint16
	 t890 = &t646[243:int]
	 *t890 = 6389:uint16
	 t891 = &t646[244:int]
	 *t891 = 6400:uint16
	 t892 = &t646[245:int]
	 *t892 = 6443:uint16
	 t893 = &t646[246:int]
	 *t893 = 6448:uint16
	 t894 = &t646[247:int]
	 *t894 = 6459:uint16
	 t895 = &t646[248:int]
	 *t895 = 6464:uint16
	 t896 = &t646[249:int]
	 *t896 = 6464:uint16
	 t897 = &t646[250:int]
	 *t897 = 6468:uint16
	 t898 = &t646[251:int]
	 *t898 = 6509:uint16
	 t899 = &t646[252:int]
	 *t899 = 6512:uint16
	 t900 = &t646[253:int]
	 *t900 = 6516:uint16
	 t901 = &t646[254:int]
	 *t901 = 6528:uint16
	 t902 = &t646[255:int]
	 *t902 = 6571:uint16
	 t903 = &t646[256:int]
	 *t903 = 6576:uint16
	 t904 = &t646[257:int]
	 *t904 = 6601:uint16
	 t905 = &t646[258:int]
	 *t905 = 6608:uint16
	 t906 = &t646[259:int]
	 *t906 = 6618:uint16
	 t907 = &t646[260:int]
	 *t907 = 6622:uint16
	 t908 = &t646[261:int]
	 *t908 = 6683:uint16
	 t909 = &t646[262:int]
	 *t909 = 6686:uint16
	 t910 = &t646[263:int]
	 *t910 = 6780:uint16
	 t911 = &t646[264:int]
	 *t911 = 6783:uint16
	 t912 = &t646[265:int]
	 *t912 = 6793:uint16
	 t913 = &t646[266:int]
	 *t913 = 6800:uint16
	 t914 = &t646[267:int]
	 *t914 = 6809:uint16
	 t915 = &t646[268:int]
	 *t915 = 6816:uint16
	 t916 = &t646[269:int]
	 *t916 = 6829:uint16
	 t917 = &t646[270:int]
	 *t917 = 6832:uint16
	 t918 = &t646[271:int]
	 *t918 = 6846:uint16
	 t919 = &t646[272:int]
	 *t919 = 6912:uint16
	 t920 = &t646[273:int]
	 *t920 = 6987:uint16
	 t921 = &t646[274:int]
	 *t921 = 6992:uint16
	 t922 = &t646[275:int]
	 *t922 = 7036:uint16
	 t923 = &t646[276:int]
	 *t923 = 7040:uint16
	 t924 = &t646[277:int]
	 *t924 = 7155:uint16
	 t925 = &t646[278:int]
	 *t925 = 7164:uint16
	 t926 = &t646[279:int]
	 *t926 = 7223:uint16
	 t927 = &t646[280:int]
	 *t927 = 7227:uint16
	 t928 = &t646[281:int]
	 *t928 = 7241:uint16
	 t929 = &t646[282:int]
	 *t929 = 7245:uint16
	 t930 = &t646[283:int]
	 *t930 = 7304:uint16
	 t931 = &t646[284:int]
	 *t931 = 7360:uint16
	 t932 = &t646[285:int]
	 *t932 = 7367:uint16
	 t933 = &t646[286:int]
	 *t933 = 7376:uint16
	 t934 = &t646[287:int]
	 *t934 = 7417:uint16
	 t935 = &t646[288:int]
	 *t935 = 7424:uint16
	 t936 = &t646[289:int]
	 *t936 = 7669:uint16
	 t937 = &t646[290:int]
	 *t937 = 7675:uint16
	 t938 = &t646[291:int]
	 *t938 = 7957:uint16
	 t939 = &t646[292:int]
	 *t939 = 7960:uint16
	 t940 = &t646[293:int]
	 *t940 = 7965:uint16
	 t941 = &t646[294:int]
	 *t941 = 7968:uint16
	 t942 = &t646[295:int]
	 *t942 = 8005:uint16
	 t943 = &t646[296:int]
	 *t943 = 8008:uint16
	 t944 = &t646[297:int]
	 *t944 = 8013:uint16
	 t945 = &t646[298:int]
	 *t945 = 8016:uint16
	 t946 = &t646[299:int]
	 *t946 = 8061:uint16
	 t947 = &t646[300:int]
	 *t947 = 8064:uint16
	 t948 = &t646[301:int]
	 *t948 = 8147:uint16
	 t949 = &t646[302:int]
	 *t949 = 8150:uint16
	 t950 = &t646[303:int]
	 *t950 = 8175:uint16
	 t951 = &t646[304:int]
	 *t951 = 8178:uint16
	 t952 = &t646[305:int]
	 *t952 = 8190:uint16
	 t953 = &t646[306:int]
	 *t953 = 8208:uint16
	 t954 = &t646[307:int]
	 *t954 = 8231:uint16
	 t955 = &t646[308:int]
	 *t955 = 8240:uint16
	 t956 = &t646[309:int]
	 *t956 = 8286:uint16
	 t957 = &t646[310:int]
	 *t957 = 8304:uint16
	 t958 = &t646[311:int]
	 *t958 = 8305:uint16
	 t959 = &t646[312:int]
	 *t959 = 8308:uint16
	 t960 = &t646[313:int]
	 *t960 = 8348:uint16
	 t961 = &t646[314:int]
	 *t961 = 8352:uint16
	 t962 = &t646[315:int]
	 *t962 = 8382:uint16
	 t963 = &t646[316:int]
	 *t963 = 8400:uint16
	 t964 = &t646[317:int]
	 *t964 = 8432:uint16
	 t965 = &t646[318:int]
	 *t965 = 8448:uint16
	 t966 = &t646[319:int]
	 *t966 = 8587:uint16
	 t967 = &t646[320:int]
	 *t967 = 8592:uint16
	 t968 = &t646[321:int]
	 *t968 = 9254:uint16
	 t969 = &t646[322:int]
	 *t969 = 9280:uint16
	 t970 = &t646[323:int]
	 *t970 = 9290:uint16
	 t971 = &t646[324:int]
	 *t971 = 9312:uint16
	 t972 = &t646[325:int]
	 *t972 = 11123:uint16
	 t973 = &t646[326:int]
	 *t973 = 11126:uint16
	 t974 = &t646[327:int]
	 *t974 = 11157:uint16
	 t975 = &t646[328:int]
	 *t975 = 11160:uint16
	 t976 = &t646[329:int]
	 *t976 = 11193:uint16
	 t977 = &t646[330:int]
	 *t977 = 11197:uint16
	 t978 = &t646[331:int]
	 *t978 = 11217:uint16
	 t979 = &t646[332:int]
	 *t979 = 11244:uint16
	 t980 = &t646[333:int]
	 *t980 = 11247:uint16
	 t981 = &t646[334:int]
	 *t981 = 11264:uint16
	 t982 = &t646[335:int]
	 *t982 = 11507:uint16
	 t983 = &t646[336:int]
	 *t983 = 11513:uint16
	 t984 = &t646[337:int]
	 *t984 = 11559:uint16
	 t985 = &t646[338:int]
	 *t985 = 11565:uint16
	 t986 = &t646[339:int]
	 *t986 = 11565:uint16
	 t987 = &t646[340:int]
	 *t987 = 11568:uint16
	 t988 = &t646[341:int]
	 *t988 = 11623:uint16
	 t989 = &t646[342:int]
	 *t989 = 11631:uint16
	 t990 = &t646[343:int]
	 *t990 = 11632:uint16
	 t991 = &t646[344:int]
	 *t991 = 11647:uint16
	 t992 = &t646[345:int]
	 *t992 = 11670:uint16
	 t993 = &t646[346:int]
	 *t993 = 11680:uint16
	 t994 = &t646[347:int]
	 *t994 = 11844:uint16
	 t995 = &t646[348:int]
	 *t995 = 11904:uint16
	 t996 = &t646[349:int]
	 *t996 = 12019:uint16
	 t997 = &t646[350:int]
	 *t997 = 12032:uint16
	 t998 = &t646[351:int]
	 *t998 = 12245:uint16
	 t999 = &t646[352:int]
	 *t999 = 12272:uint16
	 t1000 = &t646[353:int]
	 *t1000 = 12283:uint16
	 t1001 = &t646[354:int]
	 *t1001 = 12289:uint16
	 t1002 = &t646[355:int]
	 *t1002 = 12438:uint16
	 t1003 = &t646[356:int]
	 *t1003 = 12441:uint16
	 t1004 = &t646[357:int]
	 *t1004 = 12543:uint16
	 t1005 = &t646[358:int]
	 *t1005 = 12549:uint16
	 t1006 = &t646[359:int]
	 *t1006 = 12589:uint16
	 t1007 = &t646[360:int]
	 *t1007 = 12593:uint16
	 t1008 = &t646[361:int]
	 *t1008 = 12730:uint16
	 t1009 = &t646[362:int]
	 *t1009 = 12736:uint16
	 t1010 = &t646[363:int]
	 *t1010 = 12771:uint16
	 t1011 = &t646[364:int]
	 *t1011 = 12784:uint16
	 t1012 = &t646[365:int]
	 *t1012 = 19893:uint16
	 t1013 = &t646[366:int]
	 *t1013 = 19904:uint16
	 t1014 = &t646[367:int]
	 *t1014 = 40917:uint16
	 t1015 = &t646[368:int]
	 *t1015 = 40960:uint16
	 t1016 = &t646[369:int]
	 *t1016 = 42124:uint16
	 t1017 = &t646[370:int]
	 *t1017 = 42128:uint16
	 t1018 = &t646[371:int]
	 *t1018 = 42182:uint16
	 t1019 = &t646[372:int]
	 *t1019 = 42192:uint16
	 t1020 = &t646[373:int]
	 *t1020 = 42539:uint16
	 t1021 = &t646[374:int]
	 *t1021 = 42560:uint16
	 t1022 = &t646[375:int]
	 *t1022 = 42743:uint16
	 t1023 = &t646[376:int]
	 *t1023 = 42752:uint16
	 t1024 = &t646[377:int]
	 *t1024 = 42935:uint16
	 t1025 = &t646[378:int]
	 *t1025 = 42999:uint16
	 t1026 = &t646[379:int]
	 *t1026 = 43051:uint16
	 t1027 = &t646[380:int]
	 *t1027 = 43056:uint16
	 t1028 = &t646[381:int]
	 *t1028 = 43065:uint16
	 t1029 = &t646[382:int]
	 *t1029 = 43072:uint16
	 t1030 = &t646[383:int]
	 *t1030 = 43127:uint16
	 t1031 = &t646[384:int]
	 *t1031 = 43136:uint16
	 t1032 = &t646[385:int]
	 *t1032 = 43205:uint16
	 t1033 = &t646[386:int]
	 *t1033 = 43214:uint16
	 t1034 = &t646[387:int]
	 *t1034 = 43225:uint16
	 t1035 = &t646[388:int]
	 *t1035 = 43232:uint16
	 t1036 = &t646[389:int]
	 *t1036 = 43261:uint16
	 t1037 = &t646[390:int]
	 *t1037 = 43264:uint16
	 t1038 = &t646[391:int]
	 *t1038 = 43347:uint16
	 t1039 = &t646[392:int]
	 *t1039 = 43359:uint16
	 t1040 = &t646[393:int]
	 *t1040 = 43388:uint16
	 t1041 = &t646[394:int]
	 *t1041 = 43392:uint16
	 t1042 = &t646[395:int]
	 *t1042 = 43481:uint16
	 t1043 = &t646[396:int]
	 *t1043 = 43486:uint16
	 t1044 = &t646[397:int]
	 *t1044 = 43574:uint16
	 t1045 = &t646[398:int]
	 *t1045 = 43584:uint16
	 t1046 = &t646[399:int]
	 *t1046 = 43597:uint16
	 t1047 = &t646[400:int]
	 *t1047 = 43600:uint16
	 t1048 = &t646[401:int]
	 *t1048 = 43609:uint16
	 t1049 = &t646[402:int]
	 *t1049 = 43612:uint16
	 t1050 = &t646[403:int]
	 *t1050 = 43714:uint16
	 t1051 = &t646[404:int]
	 *t1051 = 43739:uint16
	 t1052 = &t646[405:int]
	 *t1052 = 43766:uint16
	 t1053 = &t646[406:int]
	 *t1053 = 43777:uint16
	 t1054 = &t646[407:int]
	 *t1054 = 43782:uint16
	 t1055 = &t646[408:int]
	 *t1055 = 43785:uint16
	 t1056 = &t646[409:int]
	 *t1056 = 43790:uint16
	 t1057 = &t646[410:int]
	 *t1057 = 43793:uint16
	 t1058 = &t646[411:int]
	 *t1058 = 43798:uint16
	 t1059 = &t646[412:int]
	 *t1059 = 43808:uint16
	 t1060 = &t646[413:int]
	 *t1060 = 43877:uint16
	 t1061 = &t646[414:int]
	 *t1061 = 43888:uint16
	 t1062 = &t646[415:int]
	 *t1062 = 44013:uint16
	 t1063 = &t646[416:int]
	 *t1063 = 44016:uint16
	 t1064 = &t646[417:int]
	 *t1064 = 44025:uint16
	 t1065 = &t646[418:int]
	 *t1065 = 44032:uint16
	 t1066 = &t646[419:int]
	 *t1066 = 55203:uint16
	 t1067 = &t646[420:int]
	 *t1067 = 55216:uint16
	 t1068 = &t646[421:int]
	 *t1068 = 55238:uint16
	 t1069 = &t646[422:int]
	 *t1069 = 55243:uint16
	 t1070 = &t646[423:int]
	 *t1070 = 55291:uint16
	 t1071 = &t646[424:int]
	 *t1071 = 63744:uint16
	 t1072 = &t646[425:int]
	 *t1072 = 64109:uint16
	 t1073 = &t646[426:int]
	 *t1073 = 64112:uint16
	 t1074 = &t646[427:int]
	 *t1074 = 64217:uint16
	 t1075 = &t646[428:int]
	 *t1075 = 64256:uint16
	 t1076 = &t646[429:int]
	 *t1076 = 64262:uint16
	 t1077 = &t646[430:int]
	 *t1077 = 64275:uint16
	 t1078 = &t646[431:int]
	 *t1078 = 64279:uint16
	 t1079 = &t646[432:int]
	 *t1079 = 64285:uint16
	 t1080 = &t646[433:int]
	 *t1080 = 64449:uint16
	 t1081 = &t646[434:int]
	 *t1081 = 64467:uint16
	 t1082 = &t646[435:int]
	 *t1082 = 64831:uint16
	 t1083 = &t646[436:int]
	 *t1083 = 64848:uint16
	 t1084 = &t646[437:int]
	 *t1084 = 64911:uint16
	 t1085 = &t646[438:int]
	 *t1085 = 64914:uint16
	 t1086 = &t646[439:int]
	 *t1086 = 64967:uint16
	 t1087 = &t646[440:int]
	 *t1087 = 65008:uint16
	 t1088 = &t646[441:int]
	 *t1088 = 65021:uint16
	 t1089 = &t646[442:int]
	 *t1089 = 65024:uint16
	 t1090 = &t646[443:int]
	 *t1090 = 65049:uint16
	 t1091 = &t646[444:int]
	 *t1091 = 65056:uint16
	 t1092 = &t646[445:int]
	 *t1092 = 65131:uint16
	 t1093 = &t646[446:int]
	 *t1093 = 65136:uint16
	 t1094 = &t646[447:int]
	 *t1094 = 65276:uint16
	 t1095 = &t646[448:int]
	 *t1095 = 65281:uint16
	 t1096 = &t646[449:int]
	 *t1096 = 65470:uint16
	 t1097 = &t646[450:int]
	 *t1097 = 65474:uint16
	 t1098 = &t646[451:int]
	 *t1098 = 65479:uint16
	 t1099 = &t646[452:int]
	 *t1099 = 65482:uint16
	 t1100 = &t646[453:int]
	 *t1100 = 65487:uint16
	 t1101 = &t646[454:int]
	 *t1101 = 65490:uint16
	 t1102 = &t646[455:int]
	 *t1102 = 65495:uint16
	 t1103 = &t646[456:int]
	 *t1103 = 65498:uint16
	 t1104 = &t646[457:int]
	 *t1104 = 65500:uint16
	 t1105 = &t646[458:int]
	 *t1105 = 65504:uint16
	 t1106 = &t646[459:int]
	 *t1106 = 65518:uint16
	 t1107 = &t646[460:int]
	 *t1107 = 65532:uint16
	 t1108 = &t646[461:int]
	 *t1108 = 65533:uint16
	 t1109 = slice t646[:]
	 *isPrint16 = t1109
	 t1110 = new [139]uint16 (slicelit)
	 t1111 = &t1110[0:int]
	 *t1111 = 173:uint16
	 t1112 = &t1110[1:int]
	 *t1112 = 907:uint16
	 t1113 = &t1110[2:int]
	 *t1113 = 909:uint16
	 t1114 = &t1110[3:int]
	 *t1114 = 930:uint16
	 t1115 = &t1110[4:int]
	 *t1115 = 1328:uint16
	 t1116 = &t1110[5:int]
	 *t1116 = 1376:uint16
	 t1117 = &t1110[6:int]
	 *t1117 = 1416:uint16
	 t1118 = &t1110[7:int]
	 *t1118 = 1424:uint16
	 t1119 = &t1110[8:int]
	 *t1119 = 1757:uint16
	 t1120 = &t1110[9:int]
	 *t1120 = 2111:uint16
	 t1121 = &t1110[10:int]
	 *t1121 = 2229:uint16
	 t1122 = &t1110[11:int]
	 *t1122 = 2274:uint16
	 t1123 = &t1110[12:int]
	 *t1123 = 2436:uint16
	 t1124 = &t1110[13:int]
	 *t1124 = 2473:uint16
	 t1125 = &t1110[14:int]
	 *t1125 = 2481:uint16
	 t1126 = &t1110[15:int]
	 *t1126 = 2526:uint16
	 t1127 = &t1110[16:int]
	 *t1127 = 2564:uint16
	 t1128 = &t1110[17:int]
	 *t1128 = 2601:uint16
	 t1129 = &t1110[18:int]
	 *t1129 = 2609:uint16
	 t1130 = &t1110[19:int]
	 *t1130 = 2612:uint16
	 t1131 = &t1110[20:int]
	 *t1131 = 2615:uint16
	 t1132 = &t1110[21:int]
	 *t1132 = 2621:uint16
	 t1133 = &t1110[22:int]
	 *t1133 = 2653:uint16
	 t1134 = &t1110[23:int]
	 *t1134 = 2692:uint16
	 t1135 = &t1110[24:int]
	 *t1135 = 2702:uint16
	 t1136 = &t1110[25:int]
	 *t1136 = 2706:uint16
	 t1137 = &t1110[26:int]
	 *t1137 = 2729:uint16
	 t1138 = &t1110[27:int]
	 *t1138 = 2737:uint16
	 t1139 = &t1110[28:int]
	 *t1139 = 2740:uint16
	 t1140 = &t1110[29:int]
	 *t1140 = 2758:uint16
	 t1141 = &t1110[30:int]
	 *t1141 = 2762:uint16
	 t1142 = &t1110[31:int]
	 *t1142 = 2820:uint16
	 t1143 = &t1110[32:int]
	 *t1143 = 2857:uint16
	 t1144 = &t1110[33:int]
	 *t1144 = 2865:uint16
	 t1145 = &t1110[34:int]
	 *t1145 = 2868:uint16
	 t1146 = &t1110[35:int]
	 *t1146 = 2910:uint16
	 t1147 = &t1110[36:int]
	 *t1147 = 2948:uint16
	 t1148 = &t1110[37:int]
	 *t1148 = 2961:uint16
	 t1149 = &t1110[38:int]
	 *t1149 = 2971:uint16
	 t1150 = &t1110[39:int]
	 *t1150 = 2973:uint16
	 t1151 = &t1110[40:int]
	 *t1151 = 3017:uint16
	 t1152 = &t1110[41:int]
	 *t1152 = 3076:uint16
	 t1153 = &t1110[42:int]
	 *t1153 = 3085:uint16
	 t1154 = &t1110[43:int]
	 *t1154 = 3089:uint16
	 t1155 = &t1110[44:int]
	 *t1155 = 3113:uint16
	 t1156 = &t1110[45:int]
	 *t1156 = 3141:uint16
	 t1157 = &t1110[46:int]
	 *t1157 = 3145:uint16
	 t1158 = &t1110[47:int]
	 *t1158 = 3159:uint16
	 t1159 = &t1110[48:int]
	 *t1159 = 3204:uint16
	 t1160 = &t1110[49:int]
	 *t1160 = 3213:uint16
	 t1161 = &t1110[50:int]
	 *t1161 = 3217:uint16
	 t1162 = &t1110[51:int]
	 *t1162 = 3241:uint16
	 t1163 = &t1110[52:int]
	 *t1163 = 3252:uint16
	 t1164 = &t1110[53:int]
	 *t1164 = 3269:uint16
	 t1165 = &t1110[54:int]
	 *t1165 = 3273:uint16
	 t1166 = &t1110[55:int]
	 *t1166 = 3295:uint16
	 t1167 = &t1110[56:int]
	 *t1167 = 3312:uint16
	 t1168 = &t1110[57:int]
	 *t1168 = 3332:uint16
	 t1169 = &t1110[58:int]
	 *t1169 = 3341:uint16
	 t1170 = &t1110[59:int]
	 *t1170 = 3345:uint16
	 t1171 = &t1110[60:int]
	 *t1171 = 3397:uint16
	 t1172 = &t1110[61:int]
	 *t1172 = 3401:uint16
	 t1173 = &t1110[62:int]
	 *t1173 = 3460:uint16
	 t1174 = &t1110[63:int]
	 *t1174 = 3506:uint16
	 t1175 = &t1110[64:int]
	 *t1175 = 3516:uint16
	 t1176 = &t1110[65:int]
	 *t1176 = 3541:uint16
	 t1177 = &t1110[66:int]
	 *t1177 = 3543:uint16
	 t1178 = &t1110[67:int]
	 *t1178 = 3715:uint16
	 t1179 = &t1110[68:int]
	 *t1179 = 3721:uint16
	 t1180 = &t1110[69:int]
	 *t1180 = 3736:uint16
	 t1181 = &t1110[70:int]
	 *t1181 = 3744:uint16
	 t1182 = &t1110[71:int]
	 *t1182 = 3748:uint16
	 t1183 = &t1110[72:int]
	 *t1183 = 3750:uint16
	 t1184 = &t1110[73:int]
	 *t1184 = 3756:uint16
	 t1185 = &t1110[74:int]
	 *t1185 = 3770:uint16
	 t1186 = &t1110[75:int]
	 *t1186 = 3781:uint16
	 t1187 = &t1110[76:int]
	 *t1187 = 3783:uint16
	 t1188 = &t1110[77:int]
	 *t1188 = 3912:uint16
	 t1189 = &t1110[78:int]
	 *t1189 = 3992:uint16
	 t1190 = &t1110[79:int]
	 *t1190 = 4029:uint16
	 t1191 = &t1110[80:int]
	 *t1191 = 4045:uint16
	 t1192 = &t1110[81:int]
	 *t1192 = 4294:uint16
	 t1193 = &t1110[82:int]
	 *t1193 = 4681:uint16
	 t1194 = &t1110[83:int]
	 *t1194 = 4695:uint16
	 t1195 = &t1110[84:int]
	 *t1195 = 4697:uint16
	 t1196 = &t1110[85:int]
	 *t1196 = 4745:uint16
	 t1197 = &t1110[86:int]
	 *t1197 = 4785:uint16
	 t1198 = &t1110[87:int]
	 *t1198 = 4799:uint16
	 t1199 = &t1110[88:int]
	 *t1199 = 4801:uint16
	 t1200 = &t1110[89:int]
	 *t1200 = 4823:uint16
	 t1201 = &t1110[90:int]
	 *t1201 = 4881:uint16
	 t1202 = &t1110[91:int]
	 *t1202 = 5760:uint16
	 t1203 = &t1110[92:int]
	 *t1203 = 5901:uint16
	 t1204 = &t1110[93:int]
	 *t1204 = 5997:uint16
	 t1205 = &t1110[94:int]
	 *t1205 = 6001:uint16
	 t1206 = &t1110[95:int]
	 *t1206 = 6431:uint16
	 t1207 = &t1110[96:int]
	 *t1207 = 6751:uint16
	 t1208 = &t1110[97:int]
	 *t1208 = 7415:uint16
	 t1209 = &t1110[98:int]
	 *t1209 = 8024:uint16
	 t1210 = &t1110[99:int]
	 *t1210 = 8026:uint16
	 t1211 = &t1110[100:int]
	 *t1211 = 8028:uint16
	 t1212 = &t1110[101:int]
	 *t1212 = 8030:uint16
	 t1213 = &t1110[102:int]
	 *t1213 = 8117:uint16
	 t1214 = &t1110[103:int]
	 *t1214 = 8133:uint16
	 t1215 = &t1110[104:int]
	 *t1215 = 8156:uint16
	 t1216 = &t1110[105:int]
	 *t1216 = 8181:uint16
	 t1217 = &t1110[106:int]
	 *t1217 = 8335:uint16
	 t1218 = &t1110[107:int]
	 *t1218 = 9215:uint16
	 t1219 = &t1110[108:int]
	 *t1219 = 11209:uint16
	 t1220 = &t1110[109:int]
	 *t1220 = 11311:uint16
	 t1221 = &t1110[110:int]
	 *t1221 = 11359:uint16
	 t1222 = &t1110[111:int]
	 *t1222 = 11558:uint16
	 t1223 = &t1110[112:int]
	 *t1223 = 11687:uint16
	 t1224 = &t1110[113:int]
	 *t1224 = 11695:uint16
	 t1225 = &t1110[114:int]
	 *t1225 = 11703:uint16
	 t1226 = &t1110[115:int]
	 *t1226 = 11711:uint16
	 t1227 = &t1110[116:int]
	 *t1227 = 11719:uint16
	 t1228 = &t1110[117:int]
	 *t1228 = 11727:uint16
	 t1229 = &t1110[118:int]
	 *t1229 = 11735:uint16
	 t1230 = &t1110[119:int]
	 *t1230 = 11743:uint16
	 t1231 = &t1110[120:int]
	 *t1231 = 11930:uint16
	 t1232 = &t1110[121:int]
	 *t1232 = 12352:uint16
	 t1233 = &t1110[122:int]
	 *t1233 = 12687:uint16
	 t1234 = &t1110[123:int]
	 *t1234 = 12831:uint16
	 t1235 = &t1110[124:int]
	 *t1235 = 13055:uint16
	 t1236 = &t1110[125:int]
	 *t1236 = 42927:uint16
	 t1237 = &t1110[126:int]
	 *t1237 = 43470:uint16
	 t1238 = &t1110[127:int]
	 *t1238 = 43519:uint16
	 t1239 = &t1110[128:int]
	 *t1239 = 43815:uint16
	 t1240 = &t1110[129:int]
	 *t1240 = 43823:uint16
	 t1241 = &t1110[130:int]
	 *t1241 = 64311:uint16
	 t1242 = &t1110[131:int]
	 *t1242 = 64317:uint16
	 t1243 = &t1110[132:int]
	 *t1243 = 64319:uint16
	 t1244 = &t1110[133:int]
	 *t1244 = 64322:uint16
	 t1245 = &t1110[134:int]
	 *t1245 = 64325:uint16
	 t1246 = &t1110[135:int]
	 *t1246 = 65107:uint16
	 t1247 = &t1110[136:int]
	 *t1247 = 65127:uint16
	 t1248 = &t1110[137:int]
	 *t1248 = 65141:uint16
	 t1249 = &t1110[138:int]
	 *t1249 = 65511:uint16
	 t1250 = slice t1110[:]
	 *isNotPrint16 = t1250
	 t1251 = new [378]uint32 (slicelit)
	 t1252 = &t1251[0:int]
	 *t1252 = 65536:uint32
	 t1253 = &t1251[1:int]
	 *t1253 = 65613:uint32
	 t1254 = &t1251[2:int]
	 *t1254 = 65616:uint32
	 t1255 = &t1251[3:int]
	 *t1255 = 65629:uint32
	 t1256 = &t1251[4:int]
	 *t1256 = 65664:uint32
	 t1257 = &t1251[5:int]
	 *t1257 = 65786:uint32
	 t1258 = &t1251[6:int]
	 *t1258 = 65792:uint32
	 t1259 = &t1251[7:int]
	 *t1259 = 65794:uint32
	 t1260 = &t1251[8:int]
	 *t1260 = 65799:uint32
	 t1261 = &t1251[9:int]
	 *t1261 = 65843:uint32
	 t1262 = &t1251[10:int]
	 *t1262 = 65847:uint32
	 t1263 = &t1251[11:int]
	 *t1263 = 65947:uint32
	 t1264 = &t1251[12:int]
	 *t1264 = 65952:uint32
	 t1265 = &t1251[13:int]
	 *t1265 = 65952:uint32
	 t1266 = &t1251[14:int]
	 *t1266 = 66000:uint32
	 t1267 = &t1251[15:int]
	 *t1267 = 66045:uint32
	 t1268 = &t1251[16:int]
	 *t1268 = 66176:uint32
	 t1269 = &t1251[17:int]
	 *t1269 = 66204:uint32
	 t1270 = &t1251[18:int]
	 *t1270 = 66208:uint32
	 t1271 = &t1251[19:int]
	 *t1271 = 66256:uint32
	 t1272 = &t1251[20:int]
	 *t1272 = 66272:uint32
	 t1273 = &t1251[21:int]
	 *t1273 = 66299:uint32
	 t1274 = &t1251[22:int]
	 *t1274 = 66304:uint32
	 t1275 = &t1251[23:int]
	 *t1275 = 66339:uint32
	 t1276 = &t1251[24:int]
	 *t1276 = 66352:uint32
	 t1277 = &t1251[25:int]
	 *t1277 = 66378:uint32
	 t1278 = &t1251[26:int]
	 *t1278 = 66384:uint32
	 t1279 = &t1251[27:int]
	 *t1279 = 66426:uint32
	 t1280 = &t1251[28:int]
	 *t1280 = 66432:uint32
	 t1281 = &t1251[29:int]
	 *t1281 = 66499:uint32
	 t1282 = &t1251[30:int]
	 *t1282 = 66504:uint32
	 t1283 = &t1251[31:int]
	 *t1283 = 66517:uint32
	 t1284 = &t1251[32:int]
	 *t1284 = 66560:uint32
	 t1285 = &t1251[33:int]
	 *t1285 = 66717:uint32
	 t1286 = &t1251[34:int]
	 *t1286 = 66720:uint32
	 t1287 = &t1251[35:int]
	 *t1287 = 66729:uint32
	 t1288 = &t1251[36:int]
	 *t1288 = 66736:uint32
	 t1289 = &t1251[37:int]
	 *t1289 = 66771:uint32
	 t1290 = &t1251[38:int]
	 *t1290 = 66776:uint32
	 t1291 = &t1251[39:int]
	 *t1291 = 66811:uint32
	 t1292 = &t1251[40:int]
	 *t1292 = 66816:uint32
	 t1293 = &t1251[41:int]
	 *t1293 = 66855:uint32
	 t1294 = &t1251[42:int]
	 *t1294 = 66864:uint32
	 t1295 = &t1251[43:int]
	 *t1295 = 66915:uint32
	 t1296 = &t1251[44:int]
	 *t1296 = 66927:uint32
	 t1297 = &t1251[45:int]
	 *t1297 = 66927:uint32
	 t1298 = &t1251[46:int]
	 *t1298 = 67072:uint32
	 t1299 = &t1251[47:int]
	 *t1299 = 67382:uint32
	 t1300 = &t1251[48:int]
	 *t1300 = 67392:uint32
	 t1301 = &t1251[49:int]
	 *t1301 = 67413:uint32
	 t1302 = &t1251[50:int]
	 *t1302 = 67424:uint32
	 t1303 = &t1251[51:int]
	 *t1303 = 67431:uint32
	 t1304 = &t1251[52:int]
	 *t1304 = 67584:uint32
	 t1305 = &t1251[53:int]
	 *t1305 = 67589:uint32
	 t1306 = &t1251[54:int]
	 *t1306 = 67592:uint32
	 t1307 = &t1251[55:int]
	 *t1307 = 67640:uint32
	 t1308 = &t1251[56:int]
	 *t1308 = 67644:uint32
	 t1309 = &t1251[57:int]
	 *t1309 = 67644:uint32
	 t1310 = &t1251[58:int]
	 *t1310 = 67647:uint32
	 t1311 = &t1251[59:int]
	 *t1311 = 67742:uint32
	 t1312 = &t1251[60:int]
	 *t1312 = 67751:uint32
	 t1313 = &t1251[61:int]
	 *t1313 = 67759:uint32
	 t1314 = &t1251[62:int]
	 *t1314 = 67808:uint32
	 t1315 = &t1251[63:int]
	 *t1315 = 67829:uint32
	 t1316 = &t1251[64:int]
	 *t1316 = 67835:uint32
	 t1317 = &t1251[65:int]
	 *t1317 = 67867:uint32
	 t1318 = &t1251[66:int]
	 *t1318 = 67871:uint32
	 t1319 = &t1251[67:int]
	 *t1319 = 67897:uint32
	 t1320 = &t1251[68:int]
	 *t1320 = 67903:uint32
	 t1321 = &t1251[69:int]
	 *t1321 = 67903:uint32
	 t1322 = &t1251[70:int]
	 *t1322 = 67968:uint32
	 t1323 = &t1251[71:int]
	 *t1323 = 68023:uint32
	 t1324 = &t1251[72:int]
	 *t1324 = 68028:uint32
	 t1325 = &t1251[73:int]
	 *t1325 = 68047:uint32
	 t1326 = &t1251[74:int]
	 *t1326 = 68050:uint32
	 t1327 = &t1251[75:int]
	 *t1327 = 68102:uint32
	 t1328 = &t1251[76:int]
	 *t1328 = 68108:uint32
	 t1329 = &t1251[77:int]
	 *t1329 = 68147:uint32
	 t1330 = &t1251[78:int]
	 *t1330 = 68152:uint32
	 t1331 = &t1251[79:int]
	 *t1331 = 68154:uint32
	 t1332 = &t1251[80:int]
	 *t1332 = 68159:uint32
	 t1333 = &t1251[81:int]
	 *t1333 = 68167:uint32
	 t1334 = &t1251[82:int]
	 *t1334 = 68176:uint32
	 t1335 = &t1251[83:int]
	 *t1335 = 68184:uint32
	 t1336 = &t1251[84:int]
	 *t1336 = 68192:uint32
	 t1337 = &t1251[85:int]
	 *t1337 = 68255:uint32
	 t1338 = &t1251[86:int]
	 *t1338 = 68288:uint32
	 t1339 = &t1251[87:int]
	 *t1339 = 68326:uint32
	 t1340 = &t1251[88:int]
	 *t1340 = 68331:uint32
	 t1341 = &t1251[89:int]
	 *t1341 = 68342:uint32
	 t1342 = &t1251[90:int]
	 *t1342 = 68352:uint32
	 t1343 = &t1251[91:int]
	 *t1343 = 68405:uint32
	 t1344 = &t1251[92:int]
	 *t1344 = 68409:uint32
	 t1345 = &t1251[93:int]
	 *t1345 = 68437:uint32
	 t1346 = &t1251[94:int]
	 *t1346 = 68440:uint32
	 t1347 = &t1251[95:int]
	 *t1347 = 68466:uint32
	 t1348 = &t1251[96:int]
	 *t1348 = 68472:uint32
	 t1349 = &t1251[97:int]
	 *t1349 = 68497:uint32
	 t1350 = &t1251[98:int]
	 *t1350 = 68505:uint32
	 t1351 = &t1251[99:int]
	 *t1351 = 68508:uint32
	 t1352 = &t1251[100:int]
	 *t1352 = 68521:uint32
	 t1353 = &t1251[101:int]
	 *t1353 = 68527:uint32
	 t1354 = &t1251[102:int]
	 *t1354 = 68608:uint32
	 t1355 = &t1251[103:int]
	 *t1355 = 68680:uint32
	 t1356 = &t1251[104:int]
	 *t1356 = 68736:uint32
	 t1357 = &t1251[105:int]
	 *t1357 = 68786:uint32
	 t1358 = &t1251[106:int]
	 *t1358 = 68800:uint32
	 t1359 = &t1251[107:int]
	 *t1359 = 68850:uint32
	 t1360 = &t1251[108:int]
	 *t1360 = 68858:uint32
	 t1361 = &t1251[109:int]
	 *t1361 = 68863:uint32
	 t1362 = &t1251[110:int]
	 *t1362 = 69216:uint32
	 t1363 = &t1251[111:int]
	 *t1363 = 69246:uint32
	 t1364 = &t1251[112:int]
	 *t1364 = 69632:uint32
	 t1365 = &t1251[113:int]
	 *t1365 = 69709:uint32
	 t1366 = &t1251[114:int]
	 *t1366 = 69714:uint32
	 t1367 = &t1251[115:int]
	 *t1367 = 69743:uint32
	 t1368 = &t1251[116:int]
	 *t1368 = 69759:uint32
	 t1369 = &t1251[117:int]
	 *t1369 = 69825:uint32
	 t1370 = &t1251[118:int]
	 *t1370 = 69840:uint32
	 t1371 = &t1251[119:int]
	 *t1371 = 69864:uint32
	 t1372 = &t1251[120:int]
	 *t1372 = 69872:uint32
	 t1373 = &t1251[121:int]
	 *t1373 = 69881:uint32
	 t1374 = &t1251[122:int]
	 *t1374 = 69888:uint32
	 t1375 = &t1251[123:int]
	 *t1375 = 69955:uint32
	 t1376 = &t1251[124:int]
	 *t1376 = 69968:uint32
	 t1377 = &t1251[125:int]
	 *t1377 = 70006:uint32
	 t1378 = &t1251[126:int]
	 *t1378 = 70016:uint32
	 t1379 = &t1251[127:int]
	 *t1379 = 70093:uint32
	 t1380 = &t1251[128:int]
	 *t1380 = 70096:uint32
	 t1381 = &t1251[129:int]
	 *t1381 = 70132:uint32
	 t1382 = &t1251[130:int]
	 *t1382 = 70144:uint32
	 t1383 = &t1251[131:int]
	 *t1383 = 70206:uint32
	 t1384 = &t1251[132:int]
	 *t1384 = 70272:uint32
	 t1385 = &t1251[133:int]
	 *t1385 = 70313:uint32
	 t1386 = &t1251[134:int]
	 *t1386 = 70320:uint32
	 t1387 = &t1251[135:int]
	 *t1387 = 70378:uint32
	 t1388 = &t1251[136:int]
	 *t1388 = 70384:uint32
	 t1389 = &t1251[137:int]
	 *t1389 = 70393:uint32
	 t1390 = &t1251[138:int]
	 *t1390 = 70400:uint32
	 t1391 = &t1251[139:int]
	 *t1391 = 70412:uint32
	 t1392 = &t1251[140:int]
	 *t1392 = 70415:uint32
	 t1393 = &t1251[141:int]
	 *t1393 = 70416:uint32
	 t1394 = &t1251[142:int]
	 *t1394 = 70419:uint32
	 t1395 = &t1251[143:int]
	 *t1395 = 70457:uint32
	 t1396 = &t1251[144:int]
	 *t1396 = 70460:uint32
	 t1397 = &t1251[145:int]
	 *t1397 = 70468:uint32
	 t1398 = &t1251[146:int]
	 *t1398 = 70471:uint32
	 t1399 = &t1251[147:int]
	 *t1399 = 70472:uint32
	 t1400 = &t1251[148:int]
	 *t1400 = 70475:uint32
	 t1401 = &t1251[149:int]
	 *t1401 = 70477:uint32
	 t1402 = &t1251[150:int]
	 *t1402 = 70480:uint32
	 t1403 = &t1251[151:int]
	 *t1403 = 70480:uint32
	 t1404 = &t1251[152:int]
	 *t1404 = 70487:uint32
	 t1405 = &t1251[153:int]
	 *t1405 = 70487:uint32
	 t1406 = &t1251[154:int]
	 *t1406 = 70493:uint32
	 t1407 = &t1251[155:int]
	 *t1407 = 70499:uint32
	 t1408 = &t1251[156:int]
	 *t1408 = 70502:uint32
	 t1409 = &t1251[157:int]
	 *t1409 = 70508:uint32
	 t1410 = &t1251[158:int]
	 *t1410 = 70512:uint32
	 t1411 = &t1251[159:int]
	 *t1411 = 70516:uint32
	 t1412 = &t1251[160:int]
	 *t1412 = 70656:uint32
	 t1413 = &t1251[161:int]
	 *t1413 = 70749:uint32
	 t1414 = &t1251[162:int]
	 *t1414 = 70784:uint32
	 t1415 = &t1251[163:int]
	 *t1415 = 70855:uint32
	 t1416 = &t1251[164:int]
	 *t1416 = 70864:uint32
	 t1417 = &t1251[165:int]
	 *t1417 = 70873:uint32
	 t1418 = &t1251[166:int]
	 *t1418 = 71040:uint32
	 t1419 = &t1251[167:int]
	 *t1419 = 71093:uint32
	 t1420 = &t1251[168:int]
	 *t1420 = 71096:uint32
	 t1421 = &t1251[169:int]
	 *t1421 = 71133:uint32
	 t1422 = &t1251[170:int]
	 *t1422 = 71168:uint32
	 t1423 = &t1251[171:int]
	 *t1423 = 71236:uint32
	 t1424 = &t1251[172:int]
	 *t1424 = 71248:uint32
	 t1425 = &t1251[173:int]
	 *t1425 = 71257:uint32
	 t1426 = &t1251[174:int]
	 *t1426 = 71264:uint32
	 t1427 = &t1251[175:int]
	 *t1427 = 71276:uint32
	 t1428 = &t1251[176:int]
	 *t1428 = 71296:uint32
	 t1429 = &t1251[177:int]
	 *t1429 = 71351:uint32
	 t1430 = &t1251[178:int]
	 *t1430 = 71360:uint32
	 t1431 = &t1251[179:int]
	 *t1431 = 71369:uint32
	 t1432 = &t1251[180:int]
	 *t1432 = 71424:uint32
	 t1433 = &t1251[181:int]
	 *t1433 = 71449:uint32
	 t1434 = &t1251[182:int]
	 *t1434 = 71453:uint32
	 t1435 = &t1251[183:int]
	 *t1435 = 71467:uint32
	 t1436 = &t1251[184:int]
	 *t1436 = 71472:uint32
	 t1437 = &t1251[185:int]
	 *t1437 = 71487:uint32
	 t1438 = &t1251[186:int]
	 *t1438 = 71840:uint32
	 t1439 = &t1251[187:int]
	 *t1439 = 71922:uint32
	 t1440 = &t1251[188:int]
	 *t1440 = 71935:uint32
	 t1441 = &t1251[189:int]
	 *t1441 = 71935:uint32
	 t1442 = &t1251[190:int]
	 *t1442 = 72384:uint32
	 t1443 = &t1251[191:int]
	 *t1443 = 72440:uint32
	 t1444 = &t1251[192:int]
	 *t1444 = 72704:uint32
	 t1445 = &t1251[193:int]
	 *t1445 = 72773:uint32
	 t1446 = &t1251[194:int]
	 *t1446 = 72784:uint32
	 t1447 = &t1251[195:int]
	 *t1447 = 72812:uint32
	 t1448 = &t1251[196:int]
	 *t1448 = 72816:uint32
	 t1449 = &t1251[197:int]
	 *t1449 = 72847:uint32
	 t1450 = &t1251[198:int]
	 *t1450 = 72850:uint32
	 t1451 = &t1251[199:int]
	 *t1451 = 72886:uint32
	 t1452 = &t1251[200:int]
	 *t1452 = 73728:uint32
	 t1453 = &t1251[201:int]
	 *t1453 = 74649:uint32
	 t1454 = &t1251[202:int]
	 *t1454 = 74752:uint32
	 t1455 = &t1251[203:int]
	 *t1455 = 74868:uint32
	 t1456 = &t1251[204:int]
	 *t1456 = 74880:uint32
	 t1457 = &t1251[205:int]
	 *t1457 = 75075:uint32
	 t1458 = &t1251[206:int]
	 *t1458 = 77824:uint32
	 t1459 = &t1251[207:int]
	 *t1459 = 78894:uint32
	 t1460 = &t1251[208:int]
	 *t1460 = 82944:uint32
	 t1461 = &t1251[209:int]
	 *t1461 = 83526:uint32
	 t1462 = &t1251[210:int]
	 *t1462 = 92160:uint32
	 t1463 = &t1251[211:int]
	 *t1463 = 92728:uint32
	 t1464 = &t1251[212:int]
	 *t1464 = 92736:uint32
	 t1465 = &t1251[213:int]
	 *t1465 = 92777:uint32
	 t1466 = &t1251[214:int]
	 *t1466 = 92782:uint32
	 t1467 = &t1251[215:int]
	 *t1467 = 92783:uint32
	 t1468 = &t1251[216:int]
	 *t1468 = 92880:uint32
	 t1469 = &t1251[217:int]
	 *t1469 = 92909:uint32
	 t1470 = &t1251[218:int]
	 *t1470 = 92912:uint32
	 t1471 = &t1251[219:int]
	 *t1471 = 92917:uint32
	 t1472 = &t1251[220:int]
	 *t1472 = 92928:uint32
	 t1473 = &t1251[221:int]
	 *t1473 = 92997:uint32
	 t1474 = &t1251[222:int]
	 *t1474 = 93008:uint32
	 t1475 = &t1251[223:int]
	 *t1475 = 93047:uint32
	 t1476 = &t1251[224:int]
	 *t1476 = 93053:uint32
	 t1477 = &t1251[225:int]
	 *t1477 = 93071:uint32
	 t1478 = &t1251[226:int]
	 *t1478 = 93952:uint32
	 t1479 = &t1251[227:int]
	 *t1479 = 94020:uint32
	 t1480 = &t1251[228:int]
	 *t1480 = 94032:uint32
	 t1481 = &t1251[229:int]
	 *t1481 = 94078:uint32
	 t1482 = &t1251[230:int]
	 *t1482 = 94095:uint32
	 t1483 = &t1251[231:int]
	 *t1483 = 94111:uint32
	 t1484 = &t1251[232:int]
	 *t1484 = 94176:uint32
	 t1485 = &t1251[233:int]
	 *t1485 = 94176:uint32
	 t1486 = &t1251[234:int]
	 *t1486 = 94208:uint32
	 t1487 = &t1251[235:int]
	 *t1487 = 100332:uint32
	 t1488 = &t1251[236:int]
	 *t1488 = 100352:uint32
	 t1489 = &t1251[237:int]
	 *t1489 = 101106:uint32
	 t1490 = &t1251[238:int]
	 *t1490 = 110592:uint32
	 t1491 = &t1251[239:int]
	 *t1491 = 110593:uint32
	 t1492 = &t1251[240:int]
	 *t1492 = 113664:uint32
	 t1493 = &t1251[241:int]
	 *t1493 = 113770:uint32
	 t1494 = &t1251[242:int]
	 *t1494 = 113776:uint32
	 t1495 = &t1251[243:int]
	 *t1495 = 113788:uint32
	 t1496 = &t1251[244:int]
	 *t1496 = 113792:uint32
	 t1497 = &t1251[245:int]
	 *t1497 = 113800:uint32
	 t1498 = &t1251[246:int]
	 *t1498 = 113808:uint32
	 t1499 = &t1251[247:int]
	 *t1499 = 113817:uint32
	 t1500 = &t1251[248:int]
	 *t1500 = 113820:uint32
	 t1501 = &t1251[249:int]
	 *t1501 = 113823:uint32
	 t1502 = &t1251[250:int]
	 *t1502 = 118784:uint32
	 t1503 = &t1251[251:int]
	 *t1503 = 119029:uint32
	 t1504 = &t1251[252:int]
	 *t1504 = 119040:uint32
	 t1505 = &t1251[253:int]
	 *t1505 = 119078:uint32
	 t1506 = &t1251[254:int]
	 *t1506 = 119081:uint32
	 t1507 = &t1251[255:int]
	 *t1507 = 119154:uint32
	 t1508 = &t1251[256:int]
	 *t1508 = 119163:uint32
	 t1509 = &t1251[257:int]
	 *t1509 = 119272:uint32
	 t1510 = &t1251[258:int]
	 *t1510 = 119296:uint32
	 t1511 = &t1251[259:int]
	 *t1511 = 119365:uint32
	 t1512 = &t1251[260:int]
	 *t1512 = 119552:uint32
	 t1513 = &t1251[261:int]
	 *t1513 = 119638:uint32
	 t1514 = &t1251[262:int]
	 *t1514 = 119648:uint32
	 t1515 = &t1251[263:int]
	 *t1515 = 119665:uint32
	 t1516 = &t1251[264:int]
	 *t1516 = 119808:uint32
	 t1517 = &t1251[265:int]
	 *t1517 = 119967:uint32
	 t1518 = &t1251[266:int]
	 *t1518 = 119970:uint32
	 t1519 = &t1251[267:int]
	 *t1519 = 119970:uint32
	 t1520 = &t1251[268:int]
	 *t1520 = 119973:uint32
	 t1521 = &t1251[269:int]
	 *t1521 = 119974:uint32
	 t1522 = &t1251[270:int]
	 *t1522 = 119977:uint32
	 t1523 = &t1251[271:int]
	 *t1523 = 120074:uint32
	 t1524 = &t1251[272:int]
	 *t1524 = 120077:uint32
	 t1525 = &t1251[273:int]
	 *t1525 = 120134:uint32
	 t1526 = &t1251[274:int]
	 *t1526 = 120138:uint32
	 t1527 = &t1251[275:int]
	 *t1527 = 120485:uint32
	 t1528 = &t1251[276:int]
	 *t1528 = 120488:uint32
	 t1529 = &t1251[277:int]
	 *t1529 = 120779:uint32
	 t1530 = &t1251[278:int]
	 *t1530 = 120782:uint32
	 t1531 = &t1251[279:int]
	 *t1531 = 121483:uint32
	 t1532 = &t1251[280:int]
	 *t1532 = 121499:uint32
	 t1533 = &t1251[281:int]
	 *t1533 = 121519:uint32
	 t1534 = &t1251[282:int]
	 *t1534 = 122880:uint32
	 t1535 = &t1251[283:int]
	 *t1535 = 122904:uint32
	 t1536 = &t1251[284:int]
	 *t1536 = 122907:uint32
	 t1537 = &t1251[285:int]
	 *t1537 = 122922:uint32
	 t1538 = &t1251[286:int]
	 *t1538 = 124928:uint32
	 t1539 = &t1251[287:int]
	 *t1539 = 125124:uint32
	 t1540 = &t1251[288:int]
	 *t1540 = 125127:uint32
	 t1541 = &t1251[289:int]
	 *t1541 = 125142:uint32
	 t1542 = &t1251[290:int]
	 *t1542 = 125184:uint32
	 t1543 = &t1251[291:int]
	 *t1543 = 125258:uint32
	 t1544 = &t1251[292:int]
	 *t1544 = 125264:uint32
	 t1545 = &t1251[293:int]
	 *t1545 = 125273:uint32
	 t1546 = &t1251[294:int]
	 *t1546 = 125278:uint32
	 t1547 = &t1251[295:int]
	 *t1547 = 125279:uint32
	 t1548 = &t1251[296:int]
	 *t1548 = 126464:uint32
	 t1549 = &t1251[297:int]
	 *t1549 = 126500:uint32
	 t1550 = &t1251[298:int]
	 *t1550 = 126503:uint32
	 t1551 = &t1251[299:int]
	 *t1551 = 126523:uint32
	 t1552 = &t1251[300:int]
	 *t1552 = 126530:uint32
	 t1553 = &t1251[301:int]
	 *t1553 = 126530:uint32
	 t1554 = &t1251[302:int]
	 *t1554 = 126535:uint32
	 t1555 = &t1251[303:int]
	 *t1555 = 126548:uint32
	 t1556 = &t1251[304:int]
	 *t1556 = 126551:uint32
	 t1557 = &t1251[305:int]
	 *t1557 = 126564:uint32
	 t1558 = &t1251[306:int]
	 *t1558 = 126567:uint32
	 t1559 = &t1251[307:int]
	 *t1559 = 126619:uint32
	 t1560 = &t1251[308:int]
	 *t1560 = 126625:uint32
	 t1561 = &t1251[309:int]
	 *t1561 = 126651:uint32
	 t1562 = &t1251[310:int]
	 *t1562 = 126704:uint32
	 t1563 = &t1251[311:int]
	 *t1563 = 126705:uint32
	 t1564 = &t1251[312:int]
	 *t1564 = 126976:uint32
	 t1565 = &t1251[313:int]
	 *t1565 = 127019:uint32
	 t1566 = &t1251[314:int]
	 *t1566 = 127024:uint32
	 t1567 = &t1251[315:int]
	 *t1567 = 127123:uint32
	 t1568 = &t1251[316:int]
	 *t1568 = 127136:uint32
	 t1569 = &t1251[317:int]
	 *t1569 = 127150:uint32
	 t1570 = &t1251[318:int]
	 *t1570 = 127153:uint32
	 t1571 = &t1251[319:int]
	 *t1571 = 127221:uint32
	 t1572 = &t1251[320:int]
	 *t1572 = 127232:uint32
	 t1573 = &t1251[321:int]
	 *t1573 = 127244:uint32
	 t1574 = &t1251[322:int]
	 *t1574 = 127248:uint32
	 t1575 = &t1251[323:int]
	 *t1575 = 127339:uint32
	 t1576 = &t1251[324:int]
	 *t1576 = 127344:uint32
	 t1577 = &t1251[325:int]
	 *t1577 = 127404:uint32
	 t1578 = &t1251[326:int]
	 *t1578 = 127462:uint32
	 t1579 = &t1251[327:int]
	 *t1579 = 127490:uint32
	 t1580 = &t1251[328:int]
	 *t1580 = 127504:uint32
	 t1581 = &t1251[329:int]
	 *t1581 = 127547:uint32
	 t1582 = &t1251[330:int]
	 *t1582 = 127552:uint32
	 t1583 = &t1251[331:int]
	 *t1583 = 127560:uint32
	 t1584 = &t1251[332:int]
	 *t1584 = 127568:uint32
	 t1585 = &t1251[333:int]
	 *t1585 = 127569:uint32
	 t1586 = &t1251[334:int]
	 *t1586 = 127744:uint32
	 t1587 = &t1251[335:int]
	 *t1587 = 128722:uint32
	 t1588 = &t1251[336:int]
	 *t1588 = 128736:uint32
	 t1589 = &t1251[337:int]
	 *t1589 = 128748:uint32
	 t1590 = &t1251[338:int]
	 *t1590 = 128752:uint32
	 t1591 = &t1251[339:int]
	 *t1591 = 128758:uint32
	 t1592 = &t1251[340:int]
	 *t1592 = 128768:uint32
	 t1593 = &t1251[341:int]
	 *t1593 = 128883:uint32
	 t1594 = &t1251[342:int]
	 *t1594 = 128896:uint32
	 t1595 = &t1251[343:int]
	 *t1595 = 128980:uint32
	 t1596 = &t1251[344:int]
	 *t1596 = 129024:uint32
	 t1597 = &t1251[345:int]
	 *t1597 = 129035:uint32
	 t1598 = &t1251[346:int]
	 *t1598 = 129040:uint32
	 t1599 = &t1251[347:int]
	 *t1599 = 129095:uint32
	 t1600 = &t1251[348:int]
	 *t1600 = 129104:uint32
	 t1601 = &t1251[349:int]
	 *t1601 = 129113:uint32
	 t1602 = &t1251[350:int]
	 *t1602 = 129120:uint32
	 t1603 = &t1251[351:int]
	 *t1603 = 129159:uint32
	 t1604 = &t1251[352:int]
	 *t1604 = 129168:uint32
	 t1605 = &t1251[353:int]
	 *t1605 = 129197:uint32
	 t1606 = &t1251[354:int]
	 *t1606 = 129296:uint32
	 t1607 = &t1251[355:int]
	 *t1607 = 129319:uint32
	 t1608 = &t1251[356:int]
	 *t1608 = 129328:uint32
	 t1609 = &t1251[357:int]
	 *t1609 = 129328:uint32
	 t1610 = &t1251[358:int]
	 *t1610 = 129331:uint32
	 t1611 = &t1251[359:int]
	 *t1611 = 129355:uint32
	 t1612 = &t1251[360:int]
	 *t1612 = 129360:uint32
	 t1613 = &t1251[361:int]
	 *t1613 = 129374:uint32
	 t1614 = &t1251[362:int]
	 *t1614 = 129408:uint32
	 t1615 = &t1251[363:int]
	 *t1615 = 129425:uint32
	 t1616 = &t1251[364:int]
	 *t1616 = 129472:uint32
	 t1617 = &t1251[365:int]
	 *t1617 = 129472:uint32
	 t1618 = &t1251[366:int]
	 *t1618 = 131072:uint32
	 t1619 = &t1251[367:int]
	 *t1619 = 173782:uint32
	 t1620 = &t1251[368:int]
	 *t1620 = 173824:uint32
	 t1621 = &t1251[369:int]
	 *t1621 = 177972:uint32
	 t1622 = &t1251[370:int]
	 *t1622 = 177984:uint32
	 t1623 = &t1251[371:int]
	 *t1623 = 178205:uint32
	 t1624 = &t1251[372:int]
	 *t1624 = 178208:uint32
	 t1625 = &t1251[373:int]
	 *t1625 = 183969:uint32
	 t1626 = &t1251[374:int]
	 *t1626 = 194560:uint32
	 t1627 = &t1251[375:int]
	 *t1627 = 195101:uint32
	 t1628 = &t1251[376:int]
	 *t1628 = 917760:uint32
	 t1629 = &t1251[377:int]
	 *t1629 = 917999:uint32
	 t1630 = slice t1251[:]
	 *isPrint32 = t1630
	 t1631 = new [82]uint16 (slicelit)
	 t1632 = &t1631[0:int]
	 *t1632 = 12:uint16
	 t1633 = &t1631[1:int]
	 *t1633 = 39:uint16
	 t1634 = &t1631[2:int]
	 *t1634 = 59:uint16
	 t1635 = &t1631[3:int]
	 *t1635 = 62:uint16
	 t1636 = &t1631[4:int]
	 *t1636 = 399:uint16
	 t1637 = &t1631[5:int]
	 *t1637 = 926:uint16
	 t1638 = &t1631[6:int]
	 *t1638 = 2057:uint16
	 t1639 = &t1631[7:int]
	 *t1639 = 2102:uint16
	 t1640 = &t1631[8:int]
	 *t1640 = 2134:uint16
	 t1641 = &t1631[9:int]
	 *t1641 = 2291:uint16
	 t1642 = &t1631[10:int]
	 *t1642 = 2564:uint16
	 t1643 = &t1631[11:int]
	 *t1643 = 2580:uint16
	 t1644 = &t1631[12:int]
	 *t1644 = 2584:uint16
	 t1645 = &t1631[13:int]
	 *t1645 = 4285:uint16
	 t1646 = &t1631[14:int]
	 *t1646 = 4405:uint16
	 t1647 = &t1631[15:int]
	 *t1647 = 4576:uint16
	 t1648 = &t1631[16:int]
	 *t1648 = 4626:uint16
	 t1649 = &t1631[17:int]
	 *t1649 = 4743:uint16
	 t1650 = &t1631[18:int]
	 *t1650 = 4745:uint16
	 t1651 = &t1631[19:int]
	 *t1651 = 4750:uint16
	 t1652 = &t1631[20:int]
	 *t1652 = 4766:uint16
	 t1653 = &t1631[21:int]
	 *t1653 = 4868:uint16
	 t1654 = &t1631[22:int]
	 *t1654 = 4905:uint16
	 t1655 = &t1631[23:int]
	 *t1655 = 4913:uint16
	 t1656 = &t1631[24:int]
	 *t1656 = 4916:uint16
	 t1657 = &t1631[25:int]
	 *t1657 = 5210:uint16
	 t1658 = &t1631[26:int]
	 *t1658 = 5212:uint16
	 t1659 = &t1631[27:int]
	 *t1659 = 7177:uint16
	 t1660 = &t1631[28:int]
	 *t1660 = 7223:uint16
	 t1661 = &t1631[29:int]
	 *t1661 = 7336:uint16
	 t1662 = &t1631[30:int]
	 *t1662 = 9327:uint16
	 t1663 = &t1631[31:int]
	 *t1663 = 27231:uint16
	 t1664 = &t1631[32:int]
	 *t1664 = 27482:uint16
	 t1665 = &t1631[33:int]
	 *t1665 = 27490:uint16
	 t1666 = &t1631[34:int]
	 *t1666 = 54357:uint16
	 t1667 = &t1631[35:int]
	 *t1667 = 54429:uint16
	 t1668 = &t1631[36:int]
	 *t1668 = 54445:uint16
	 t1669 = &t1631[37:int]
	 *t1669 = 54458:uint16
	 t1670 = &t1631[38:int]
	 *t1670 = 54460:uint16
	 t1671 = &t1631[39:int]
	 *t1671 = 54468:uint16
	 t1672 = &t1631[40:int]
	 *t1672 = 54534:uint16
	 t1673 = &t1631[41:int]
	 *t1673 = 54549:uint16
	 t1674 = &t1631[42:int]
	 *t1674 = 54557:uint16
	 t1675 = &t1631[43:int]
	 *t1675 = 54586:uint16
	 t1676 = &t1631[44:int]
	 *t1676 = 54591:uint16
	 t1677 = &t1631[45:int]
	 *t1677 = 54597:uint16
	 t1678 = &t1631[46:int]
	 *t1678 = 54609:uint16
	 t1679 = &t1631[47:int]
	 *t1679 = 55968:uint16
	 t1680 = &t1631[48:int]
	 *t1680 = 57351:uint16
	 t1681 = &t1631[49:int]
	 *t1681 = 57378:uint16
	 t1682 = &t1631[50:int]
	 *t1682 = 57381:uint16
	 t1683 = &t1631[51:int]
	 *t1683 = 60932:uint16
	 t1684 = &t1631[52:int]
	 *t1684 = 60960:uint16
	 t1685 = &t1631[53:int]
	 *t1685 = 60963:uint16
	 t1686 = &t1631[54:int]
	 *t1686 = 60968:uint16
	 t1687 = &t1631[55:int]
	 *t1687 = 60979:uint16
	 t1688 = &t1631[56:int]
	 *t1688 = 60984:uint16
	 t1689 = &t1631[57:int]
	 *t1689 = 60986:uint16
	 t1690 = &t1631[58:int]
	 *t1690 = 61000:uint16
	 t1691 = &t1631[59:int]
	 *t1691 = 61002:uint16
	 t1692 = &t1631[60:int]
	 *t1692 = 61004:uint16
	 t1693 = &t1631[61:int]
	 *t1693 = 61008:uint16
	 t1694 = &t1631[62:int]
	 *t1694 = 61011:uint16
	 t1695 = &t1631[63:int]
	 *t1695 = 61016:uint16
	 t1696 = &t1631[64:int]
	 *t1696 = 61018:uint16
	 t1697 = &t1631[65:int]
	 *t1697 = 61020:uint16
	 t1698 = &t1631[66:int]
	 *t1698 = 61022:uint16
	 t1699 = &t1631[67:int]
	 *t1699 = 61024:uint16
	 t1700 = &t1631[68:int]
	 *t1700 = 61027:uint16
	 t1701 = &t1631[69:int]
	 *t1701 = 61035:uint16
	 t1702 = &t1631[70:int]
	 *t1702 = 61043:uint16
	 t1703 = &t1631[71:int]
	 *t1703 = 61048:uint16
	 t1704 = &t1631[72:int]
	 *t1704 = 61053:uint16
	 t1705 = &t1631[73:int]
	 *t1705 = 61055:uint16
	 t1706 = &t1631[74:int]
	 *t1706 = 61066:uint16
	 t1707 = &t1631[75:int]
	 *t1707 = 61092:uint16
	 t1708 = &t1631[76:int]
	 *t1708 = 61098:uint16
	 t1709 = &t1631[77:int]
	 *t1709 = 61632:uint16
	 t1710 = &t1631[78:int]
	 *t1710 = 61648:uint16
	 t1711 = &t1631[79:int]
	 *t1711 = 61743:uint16
	 t1712 = &t1631[80:int]
	 *t1712 = 63775:uint16
	 t1713 = &t1631[81:int]
	 *t1713 = 63807:uint16
	 t1714 = slice t1631[:]
	 *isNotPrint32 = t1714
	 t1715 = new [16]uint16 (slicelit)
	 t1716 = &t1715[0:int]
	 *t1716 = 160:uint16
	 t1717 = &t1715[1:int]
	 *t1717 = 5760:uint16
	 t1718 = &t1715[2:int]
	 *t1718 = 8192:uint16
	 t1719 = &t1715[3:int]
	 *t1719 = 8193:uint16
	 t1720 = &t1715[4:int]
	 *t1720 = 8194:uint16
	 t1721 = &t1715[5:int]
	 *t1721 = 8195:uint16
	 t1722 = &t1715[6:int]
	 *t1722 = 8196:uint16
	 t1723 = &t1715[7:int]
	 *t1723 = 8197:uint16
	 t1724 = &t1715[8:int]
	 *t1724 = 8198:uint16
	 t1725 = &t1715[9:int]
	 *t1725 = 8199:uint16
	 t1726 = &t1715[10:int]
	 *t1726 = 8200:uint16
	 t1727 = &t1715[11:int]
	 *t1727 = 8201:uint16
	 t1728 = &t1715[12:int]
	 *t1728 = 8202:uint16
	 t1729 = &t1715[13:int]
	 *t1729 = 8239:uint16
	 t1730 = &t1715[14:int]
	 *t1730 = 8287:uint16
	 t1731 = &t1715[15:int]
	 *t1731 = 12288:uint16
	 t1732 = slice t1715[:]
	 *isGraphic = t1732
	 t1733 = &shifts[2:int]
	 t1734 = &shifts[4:int]
	 t1735 = &shifts[8:int]
	 t1736 = &shifts[16:int]
	 t1737 = &shifts[32:int]
	 *t1733 = 1:uint
	 *t1734 = 2:uint
	 *t1735 = 3:uint
	 *t1736 = 4:uint
	 *t1737 = 5:uint
	 jump 2
.2:
	 return
Leaving strconv.init, resuming fmt.init.
	 t2 = unicode/utf8.init()
Entering unicode/utf8.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving unicode/utf8.init, resuming fmt.init.
	 t3 = errors.init()
Entering errors.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving errors.init, resuming fmt.init.
	 t4 = io.init()
Entering io.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = errors.init()
Entering errors.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving errors.init, resuming io.init.
	 t2 = sync.init()
Entering sync.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = sync/atomic.init()
Entering sync/atomic.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = unsafe.init()
Entering unsafe.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving unsafe.init, resuming sync/atomic.init.
	 jump 2
.2:
	 return
Leaving sync/atomic.init, resuming sync.init.
	 t2 = unsafe.init()
Entering unsafe.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving unsafe.init, resuming sync.init.
	 t3 = internal/race.init()
Entering internal/race.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = unsafe.init()
Entering unsafe.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving unsafe.init, resuming internal/race.init.
	 jump 2
.2:
	 return
Leaving internal/race.init, resuming sync.init.
	 t4 = runtime.init()
Entering runtime.init.
	(external)
Leaving runtime.init, resuming sync.init.
	 t5 = new interface{} (new)
	 t6 = convert unsafe.Pointer <- *interface{} (t5)
	 *expunged = t6
	 t7 = init#1()
Entering sync.init#1 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:246:6.
.0:
	 t0 = runtime_registerPoolCleanup(poolCleanup)
Entering sync.runtime_registerPoolCleanup at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:256:6.
	(external)
Leaving sync.runtime_registerPoolCleanup, resuming sync.init#1 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:247:29.
	 return
Leaving sync.init#1, resuming sync.init.
	 t8 = init#2()
Entering sync.init#2 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/runtime.go:51:6.
.0:
	 t0 = local notifyList (n)
	 t1 = runtime_notifyListCheck(32:uintptr)
Entering sync.runtime_notifyListCheck at /usr/local/Cellar/go/1.9.2/libexec/src/sync/runtime.go:50:6.
	(external)
Leaving sync.runtime_notifyListCheck, resuming sync.init#2 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/runtime.go:53:25.
	 return
Leaving sync.init#2, resuming sync.init.
	 jump 2
.2:
	 return
Leaving sync.init, resuming io.init.
	 t3 = errors.New("short write":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming io.init at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:28:31.
	 *ErrShortWrite = t3
	 t4 = errors.New("short buffer":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming io.init at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:31:32.
	 *ErrShortBuffer = t4
	 t5 = errors.New("EOF":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming io.init at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:38:21.
	 *EOF = t5
	 t6 = errors.New("unexpected EOF":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming io.init at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:42:34.
	 *ErrUnexpectedEOF = t6
	 t7 = errors.New("multiple Read cal...":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming io.init at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:47:31.
	 *ErrNoProgress = t7
	 t8 = errors.New("Seek: invalid whence":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming io.init at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:470:27.
	 *errWhence = t8
	 t9 = errors.New("Seek: invalid offset":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming io.init at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:471:27.
	 *errOffset = t9
	 t10 = errors.New("io: read/write on...":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming io.init at /usr/local/Cellar/go/1.9.2/libexec/src/io/pipe.go:16:31.
	 *ErrClosedPipe = t10
	 jump 2
.2:
	 return
Leaving io.init, resuming fmt.init.
	 t5 = os.init()
Entering os.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = io.init()
Entering io.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving io.init, resuming os.init.
	 t2 = runtime.init()
Entering runtime.init.
	(external)
Leaving runtime.init, resuming os.init.
	 t3 = syscall.init()
Entering syscall.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = unsafe.init()
Entering unsafe.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving unsafe.init, resuming syscall.init.
	 t2 = sync.init()
Entering sync.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving sync.init, resuming syscall.init.
	 t3 = runtime.init()
Entering runtime.init.
	(external)
Leaving runtime.init, resuming syscall.init.
	 t4 = errors.init()
Entering errors.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving errors.init, resuming syscall.init.
	 t5 = internal/race.init()
Entering internal/race.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving internal/race.init, resuming syscall.init.
	 t6 = runtime_envs()
Entering syscall.runtime_envs at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/env_unix.go:29:6.
	(external)
Leaving syscall.runtime_envs, resuming syscall.init at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/env_unix.go:26:30.
	 *envs = t6
	 *Stdin = 0:int
	 *Stdout = 1:int
	 *Stderr = 2:int
	 t7 = make error <- Errno (35:Errno)
	 *errEAGAIN = t7
	 t8 = make error <- Errno (22:Errno)
	 *errEINVAL = t8
	 t9 = make error <- Errno (2:Errno)
	 *errENOENT = t9
	 t10 = &errors[1:int]
	 t11 = &errors[2:int]
	 t12 = &errors[3:int]
	 t13 = &errors[4:int]
	 t14 = &errors[5:int]
	 t15 = &errors[6:int]
	 t16 = &errors[7:int]
	 t17 = &errors[8:int]
	 t18 = &errors[9:int]
	 t19 = &errors[10:int]
	 t20 = &errors[11:int]
	 t21 = &errors[12:int]
	 t22 = &errors[13:int]
	 t23 = &errors[14:int]
	 t24 = &errors[15:int]
	 t25 = &errors[16:int]
	 t26 = &errors[17:int]
	 t27 = &errors[18:int]
	 t28 = &errors[19:int]
	 t29 = &errors[20:int]
	 t30 = &errors[21:int]
	 t31 = &errors[22:int]
	 t32 = &errors[23:int]
	 t33 = &errors[24:int]
	 t34 = &errors[25:int]
	 t35 = &errors[26:int]
	 t36 = &errors[27:int]
	 t37 = &errors[28:int]
	 t38 = &errors[29:int]
	 t39 = &errors[30:int]
	 t40 = &errors[31:int]
	 t41 = &errors[32:int]
	 t42 = &errors[33:int]
	 t43 = &errors[34:int]
	 t44 = &errors[35:int]
	 t45 = &errors[36:int]
	 t46 = &errors[37:int]
	 t47 = &errors[38:int]
	 t48 = &errors[39:int]
	 t49 = &errors[40:int]
	 t50 = &errors[41:int]
	 t51 = &errors[42:int]
	 t52 = &errors[43:int]
	 t53 = &errors[44:int]
	 t54 = &errors[45:int]
	 t55 = &errors[46:int]
	 t56 = &errors[47:int]
	 t57 = &errors[48:int]
	 t58 = &errors[49:int]
	 t59 = &errors[50:int]
	 t60 = &errors[51:int]
	 t61 = &errors[52:int]
	 t62 = &errors[53:int]
	 t63 = &errors[54:int]
	 t64 = &errors[55:int]
	 t65 = &errors[56:int]
	 t66 = &errors[57:int]
	 t67 = &errors[58:int]
	 t68 = &errors[59:int]
	 t69 = &errors[60:int]
	 t70 = &errors[61:int]
	 t71 = &errors[62:int]
	 t72 = &errors[63:int]
	 t73 = &errors[64:int]
	 t74 = &errors[65:int]
	 t75 = &errors[66:int]
	 t76 = &errors[67:int]
	 t77 = &errors[68:int]
	 t78 = &errors[69:int]
	 t79 = &errors[70:int]
	 t80 = &errors[71:int]
	 t81 = &errors[72:int]
	 t82 = &errors[73:int]
	 t83 = &errors[74:int]
	 t84 = &errors[75:int]
	 t85 = &errors[76:int]
	 t86 = &errors[77:int]
	 t87 = &errors[78:int]
	 t88 = &errors[79:int]
	 t89 = &errors[80:int]
	 t90 = &errors[81:int]
	 t91 = &errors[82:int]
	 t92 = &errors[83:int]
	 t93 = &errors[84:int]
	 t94 = &errors[85:int]
	 t95 = &errors[86:int]
	 t96 = &errors[87:int]
	 t97 = &errors[88:int]
	 t98 = &errors[89:int]
	 t99 = &errors[90:int]
	 t100 = &errors[91:int]
	 t101 = &errors[92:int]
	 t102 = &errors[93:int]
	 t103 = &errors[94:int]
	 t104 = &errors[95:int]
	 t105 = &errors[96:int]
	 t106 = &errors[97:int]
	 t107 = &errors[98:int]
	 t108 = &errors[99:int]
	 t109 = &errors[100:int]
	 t110 = &errors[101:int]
	 t111 = &errors[102:int]
	 t112 = &errors[103:int]
	 t113 = &errors[104:int]
	 t114 = &errors[105:int]
	 *t10 = "operation not per...":string
	 *t11 = "no such file or d...":string
	 *t12 = "no such process":string
	 *t13 = "interrupted syste...":string
	 *t14 = "input/output error":string
	 *t15 = "device not config...":string
	 *t16 = "argument list too...":string
	 *t17 = "exec format error":string
	 *t18 = "bad file descriptor":string
	 *t19 = "no child processes":string
	 *t20 = "resource deadlock...":string
	 *t21 = "cannot allocate m...":string
	 *t22 = "permission denied":string
	 *t23 = "bad address":string
	 *t24 = "block device requ...":string
	 *t25 = "resource busy":string
	 *t26 = "file exists":string
	 *t27 = "cross-device link":string
	 *t28 = "operation not sup...":string
	 *t29 = "not a directory":string
	 *t30 = "is a directory":string
	 *t31 = "invalid argument":string
	 *t32 = "too many open fil...":string
	 *t33 = "too many open files":string
	 *t34 = "inappropriate ioc...":string
	 *t35 = "text file busy":string
	 *t36 = "file too large":string
	 *t37 = "no space left on ...":string
	 *t38 = "illegal seek":string
	 *t39 = "read-only file sy...":string
	 *t40 = "too many links":string
	 *t41 = "broken pipe":string
	 *t42 = "numerical argumen...":string
	 *t43 = "result too large":string
	 *t44 = "resource temporar...":string
	 *t45 = "operation now in ...":string
	 *t46 = "operation already...":string
	 *t47 = "socket operation ...":string
	 *t48 = "destination addre...":string
	 *t49 = "message too long":string
	 *t50 = "protocol wrong ty...":string
	 *t51 = "protocol not avai...":string
	 *t52 = "protocol not supp...":string
	 *t53 = "socket type not s...":string
	 *t54 = "operation not sup...":string
	 *t55 = "protocol family n...":string
	 *t56 = "address family no...":string
	 *t57 = "address already i...":string
	 *t58 = "can't assign requ...":string
	 *t59 = "network is down":string
	 *t60 = "network is unreac...":string
	 *t61 = "network dropped c...":string
	 *t62 = "software caused c...":string
	 *t63 = "connection reset ...":string
	 *t64 = "no buffer space a...":string
	 *t65 = "socket is already...":string
	 *t66 = "socket is not con...":string
	 *t67 = "can't send after ...":string
	 *t68 = "too many referenc...":string
	 *t69 = "operation timed out":string
	 *t70 = "connection refused":string
	 *t71 = "too many levels o...":string
	 *t72 = "file name too long":string
	 *t73 = "host is down":string
	 *t74 = "no route to host":string
	 *t75 = "directory not empty":string
	 *t76 = "too many processes":string
	 *t77 = "too many users":string
	 *t78 = "disc quota exceeded":string
	 *t79 = "stale NFS file ha...":string
	 *t80 = "too many levels o...":string
	 *t81 = "RPC struct is bad":string
	 *t82 = "RPC version wrong":string
	 *t83 = "RPC prog. not avail":string
	 *t84 = "program version w...":string
	 *t85 = "bad procedure for...":string
	 *t86 = "no locks available":string
	 *t87 = "function not impl...":string
	 *t88 = "inappropriate fil...":string
	 *t89 = "authentication error":string
	 *t90 = "need authenticator":string
	 *t91 = "device power is off":string
	 *t92 = "device error":string
	 *t93 = "value too large t...":string
	 *t94 = "bad executable (o...":string
	 *t95 = "bad CPU type in e...":string
	 *t96 = "shared library ve...":string
	 *t97 = "malformed Mach-o ...":string
	 *t98 = "operation canceled":string
	 *t99 = "identifier removed":string
	 *t100 = "no message of des...":string
	 *t101 = "illegal byte sequ...":string
	 *t102 = "attribute not found":string
	 *t103 = "bad message":string
	 *t104 = "EMULTIHOP (Reserved)":string
	 *t105 = "no message availa...":string
	 *t106 = "ENOLINK (Reserved)":string
	 *t107 = "no STREAM resources":string
	 *t108 = "not a STREAM":string
	 *t109 = "protocol error":string
	 *t110 = "STREAM ioctl timeout":string
	 *t111 = "operation not sup...":string
	 *t112 = "policy not found":string
	 *t113 = "state not recover...":string
	 *t114 = "previous owner died":string
	 t115 = &signals[1:int]
	 t116 = &signals[2:int]
	 t117 = &signals[3:int]
	 t118 = &signals[4:int]
	 t119 = &signals[5:int]
	 t120 = &signals[6:int]
	 t121 = &signals[7:int]
	 t122 = &signals[8:int]
	 t123 = &signals[9:int]
	 t124 = &signals[10:int]
	 t125 = &signals[11:int]
	 t126 = &signals[12:int]
	 t127 = &signals[13:int]
	 t128 = &signals[14:int]
	 t129 = &signals[15:int]
	 t130 = &signals[16:int]
	 t131 = &signals[17:int]
	 t132 = &signals[18:int]
	 t133 = &signals[19:int]
	 t134 = &signals[20:int]
	 t135 = &signals[21:int]
	 t136 = &signals[22:int]
	 t137 = &signals[23:int]
	 t138 = &signals[24:int]
	 t139 = &signals[25:int]
	 t140 = &signals[26:int]
	 t141 = &signals[27:int]
	 t142 = &signals[28:int]
	 t143 = &signals[29:int]
	 t144 = &signals[30:int]
	 t145 = &signals[31:int]
	 *t115 = "hangup":string
	 *t116 = "interrupt":string
	 *t117 = "quit":string
	 *t118 = "illegal instruction":string
	 *t119 = "trace/BPT trap":string
	 *t120 = "abort trap":string
	 *t121 = "EMT trap":string
	 *t122 = "floating point ex...":string
	 *t123 = "killed":string
	 *t124 = "bus error":string
	 *t125 = "segmentation fault":string
	 *t126 = "bad system call":string
	 *t127 = "broken pipe":string
	 *t128 = "alarm clock":string
	 *t129 = "terminated":string
	 *t130 = "urgent I/O condition":string
	 *t131 = "suspended (signal)":string
	 *t132 = "suspended":string
	 *t133 = "continued":string
	 *t134 = "child exited":string
	 *t135 = "stopped (tty input)":string
	 *t136 = "stopped (tty output)":string
	 *t137 = "I/O possible":string
	 *t138 = "cputime limit exc...":string
	 *t139 = "filesize limit ex...":string
	 *t140 = "virtual timer exp...":string
	 *t141 = "profiling timer e...":string
	 *t142 = "window size changes":string
	 *t143 = "information request":string
	 *t144 = "user defined sign...":string
	 *t145 = "user defined sign...":string
	 *fcntl64Syscall = 92:uintptr
	 t146 = new mmapper (complit)
	 t147 = &t146.active [#1]
	 t148 = make map[*byte][]byte 
	 t149 = &t146.mmap [#2]
	 t150 = &t146.munmap [#3]
	 *t147 = t148
	 *t149 = mmap
	 *t150 = munmap
	 *mapper = t146
	 t151 = rsaAlignOf(0:int)
Entering syscall.rsaAlignOf at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/route_bsd.go:20:6.
.0:
	 if true:untyped bool goto 1 else 3
.1:
	 jump 2
.2:
	 t0 = phi [1: 4:int, 4: 8:int, 5: 8:int, 6: 8:int, 7: 8:int] #salign
	 t1 = salen == 0:int
	 if t1 goto 8 else 9
.8:
	 return t0
Leaving syscall.rsaAlignOf, resuming syscall.init at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/route_bsd.go:16:36.
	 *minRoutingSockaddrLen = t151
	 jump 2
.2:
	 return
Leaving syscall.init, resuming os.init.
	 t4 = errors.init()
Entering errors.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving errors.init, resuming os.init.
	 t5 = sync.init()
Entering sync.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving sync.init, resuming os.init.
	 t6 = sync/atomic.init()
Entering sync/atomic.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving sync/atomic.init, resuming os.init.
	 t7 = time.init()
Entering time.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = errors.init()
Entering errors.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving errors.init, resuming time.init.
	 t2 = syscall.init()
Entering syscall.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving syscall.init, resuming time.init.
	 t3 = sync.init()
Entering sync.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving sync.init, resuming time.init.
	 t4 = runtime.init()
Entering runtime.init.
	(external)
Leaving runtime.init, resuming time.init.
	 t5 = &std0x[0:int]
	 t6 = &std0x[1:int]
	 t7 = &std0x[2:int]
	 t8 = &std0x[3:int]
	 t9 = &std0x[4:int]
	 t10 = &std0x[5:int]
	 *t5 = 260:int
	 *t6 = 265:int
	 *t7 = 524:int
	 *t8 = 526:int
	 *t9 = 528:int
	 *t10 = 274:int
	 t11 = new [7]string (slicelit)
	 t12 = &t11[0:int]
	 *t12 = "Sunday":string
	 t13 = &t11[1:int]
	 *t13 = "Monday":string
	 t14 = &t11[2:int]
	 *t14 = "Tuesday":string
	 t15 = &t11[3:int]
	 *t15 = "Wednesday":string
	 t16 = &t11[4:int]
	 *t16 = "Thursday":string
	 t17 = &t11[5:int]
	 *t17 = "Friday":string
	 t18 = &t11[6:int]
	 *t18 = "Saturday":string
	 t19 = slice t11[:]
	 *longDayNames = t19
	 t20 = new [7]string (slicelit)
	 t21 = &t20[0:int]
	 *t21 = "Sun":string
	 t22 = &t20[1:int]
	 *t22 = "Mon":string
	 t23 = &t20[2:int]
	 *t23 = "Tue":string
	 t24 = &t20[3:int]
	 *t24 = "Wed":string
	 t25 = &t20[4:int]
	 *t25 = "Thu":string
	 t26 = &t20[5:int]
	 *t26 = "Fri":string
	 t27 = &t20[6:int]
	 *t27 = "Sat":string
	 t28 = slice t20[:]
	 *shortDayNames = t28
	 t29 = new [13]string (slicelit)
	 t30 = &t29[0:int]
	 *t30 = "---":string
	 t31 = &t29[1:int]
	 *t31 = "Jan":string
	 t32 = &t29[2:int]
	 *t32 = "Feb":string
	 t33 = &t29[3:int]
	 *t33 = "Mar":string
	 t34 = &t29[4:int]
	 *t34 = "Apr":string
	 t35 = &t29[5:int]
	 *t35 = "May":string
	 t36 = &t29[6:int]
	 *t36 = "Jun":string
	 t37 = &t29[7:int]
	 *t37 = "Jul":string
	 t38 = &t29[8:int]
	 *t38 = "Aug":string
	 t39 = &t29[9:int]
	 *t39 = "Sep":string
	 t40 = &t29[10:int]
	 *t40 = "Oct":string
	 t41 = &t29[11:int]
	 *t41 = "Nov":string
	 t42 = &t29[12:int]
	 *t42 = "Dec":string
	 t43 = slice t29[:]
	 *shortMonthNames = t43
	 t44 = new [13]string (slicelit)
	 t45 = &t44[0:int]
	 *t45 = "---":string
	 t46 = &t44[1:int]
	 *t46 = "January":string
	 t47 = &t44[2:int]
	 *t47 = "February":string
	 t48 = &t44[3:int]
	 *t48 = "March":string
	 t49 = &t44[4:int]
	 *t49 = "April":string
	 t50 = &t44[5:int]
	 *t50 = "May":string
	 t51 = &t44[6:int]
	 *t51 = "June":string
	 t52 = &t44[7:int]
	 *t52 = "July":string
	 t53 = &t44[8:int]
	 *t53 = "August":string
	 t54 = &t44[9:int]
	 *t54 = "September":string
	 t55 = &t44[10:int]
	 *t55 = "October":string
	 t56 = &t44[11:int]
	 *t56 = "November":string
	 t57 = &t44[12:int]
	 *t57 = "December":string
	 t58 = slice t44[:]
	 *longMonthNames = t58
	 t59 = errors.New("time: invalid number":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming time.init at /usr/local/Cellar/go/1.9.2/libexec/src/time/format.go:381:27.
	 *atoiError = t59
	 t60 = errors.New("bad value for field":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming time.init at /usr/local/Cellar/go/1.9.2/libexec/src/time/format.go:653:24.
	 *errBad = t60
	 t61 = errors.New("time: bad [0-9]*":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming time.init at /usr/local/Cellar/go/1.9.2/libexec/src/time/format.go:1192:31.
	 *errLeadingInt = t61
	 t62 = &months[0:int]
	 t63 = &months[1:int]
	 t64 = &months[2:int]
	 t65 = &months[3:int]
	 t66 = &months[4:int]
	 t67 = &months[5:int]
	 t68 = &months[6:int]
	 t69 = &months[7:int]
	 t70 = &months[8:int]
	 t71 = &months[9:int]
	 t72 = &months[10:int]
	 t73 = &months[11:int]
	 *t62 = "January":string
	 *t63 = "February":string
	 *t64 = "March":string
	 *t65 = "April":string
	 *t66 = "May":string
	 *t67 = "June":string
	 *t68 = "July":string
	 *t69 = "August":string
	 *t70 = "September":string
	 *t71 = "October":string
	 *t72 = "November":string
	 *t73 = "December":string
	 t74 = &days[0:int]
	 t75 = &days[1:int]
	 t76 = &days[2:int]
	 t77 = &days[3:int]
	 t78 = &days[4:int]
	 t79 = &days[5:int]
	 t80 = &days[6:int]
	 *t74 = "Sunday":string
	 *t75 = "Monday":string
	 *t76 = "Tuesday":string
	 *t77 = "Wednesday":string
	 *t78 = "Thursday":string
	 *t79 = "Friday":string
	 *t80 = "Saturday":string
	 t81 = make map[string]int64 8:int
	 t81["ns":string] = 1:int64
	 t81["us":string] = 1000:int64
	 t81["µs":string] = 1000:int64
	 t81["μs":string] = 1000:int64
	 t81["ms":string] = 1000000:int64
	 t81["s":string] = 1000000000:int64
	 t81["m":string] = 60000000000:int64
	 t81["h":string] = 3600000000000:int64
	 *unitMap = t81
	 t82 = &daysBefore[0:int]
	 t83 = &daysBefore[1:int]
	 t84 = &daysBefore[2:int]
	 t85 = &daysBefore[3:int]
	 t86 = &daysBefore[4:int]
	 t87 = &daysBefore[5:int]
	 t88 = &daysBefore[6:int]
	 t89 = &daysBefore[7:int]
	 t90 = &daysBefore[8:int]
	 t91 = &daysBefore[9:int]
	 t92 = &daysBefore[10:int]
	 t93 = &daysBefore[11:int]
	 t94 = &daysBefore[12:int]
	 *t82 = 0:int32
	 *t83 = 31:int32
	 *t84 = 59:int32
	 *t85 = 90:int32
	 *t86 = 120:int32
	 *t87 = 151:int32
	 *t88 = 181:int32
	 *t89 = 212:int32
	 *t90 = 243:int32
	 *t91 = 273:int32
	 *t92 = 304:int32
	 *t93 = 334:int32
	 *t94 = 365:int32
	 t95 = &utcLoc.name [#0]
	 *t95 = "UTC":string
	 *UTC = utcLoc
	 *Local = localLoc
	 t96 = errors.New("time: invalid loc...":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming time.init at /usr/local/Cellar/go/1.9.2/libexec/src/time/zoneinfo.go:260:29.
	 *errLocation = t96
	 t97 = errors.New("malformed time zo...":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming time.init at /usr/local/Cellar/go/1.9.2/libexec/src/time/zoneinfo_read.go:77:25.
	 *badData = t97
	 t98 = new [4]string (slicelit)
	 t99 = &t98[0:int]
	 *t99 = "/usr/share/zoneinfo/":string
	 t100 = &t98[1:int]
	 *t100 = "/usr/share/lib/zo...":string
	 t101 = &t98[2:int]
	 *t101 = "/usr/lib/locale/TZ/":string
	 t102 = &t98[3:int]
	 t103 = runtime.GOROOT()
Entering runtime.GOROOT at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/extern.go:218:6.
.0:
	 t0 = gogetenv("GOROOT":string)
Entering runtime.gogetenv at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/env_posix.go:11:6.
.0:
	 t0 = environ()
Entering runtime.environ at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/runtime1.go:91:6.
	(external)
Leaving runtime.environ, resuming runtime.gogetenv at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/env_posix.go:12:16.
	 t1 = t0 == nil:[]string
	 if t1 goto 1 else 2
.2:
	 t3 = len(t0)
	 jump 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.7:
	 t15 = len(key)
	 t16 = slice t8[:t15]
	 t17 = t16 == key
	 if t17 goto 6 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.7:
	 t15 = len(key)
	 t16 = slice t8[:t15]
	 t17 = t16 == key
	 if t17 goto 6 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.7:
	 t15 = len(key)
	 t16 = slice t8[:t15]
	 t17 = t16 == key
	 if t17 goto 6 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.4:
	 t7 = &t0[t5]
	 t8 = *t7
	 t9 = len(t8)
	 t10 = len(key)
	 t11 = t9 > t10
	 if t11 goto 8 else 3
.8:
	 t18 = len(key)
	 t19 = t8[t18]
	 t20 = t19 == 61:byte
	 if t20 goto 7 else 3
.7:
	 t15 = len(key)
	 t16 = slice t8[:t15]
	 t17 = t16 == key
	 if t17 goto 6 else 3
.3:
	 t4 = phi [2: -1:int, 4: t5, 8: t5, 7: t5]
	 t5 = t4 + 1:int
	 t6 = t5 < t3
	 if t6 goto 4 else 5
.5:
	 return "":string
Leaving runtime.gogetenv, resuming runtime.GOROOT at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/extern.go:219:15.
	 t1 = t0 != "":string
	 if t1 goto 1 else 2
.2:
	 return "/usr/local/Cellar...":string
Leaving runtime.GOROOT, resuming time.init at /usr/local/Cellar/go/1.9.2/libexec/src/time/zoneinfo_unix.go:35:16.
	 t104 = t103 + "/lib/time/zoneinf...":string
	 *t102 = t104
	 t105 = slice t98[:]
	 *zoneDirs = t105
	 t106 = *zoneDirs
	 *origZoneDirs = t106
	 jump 2
.2:
	 return
Leaving time.init, resuming os.init.
	 t8 = internal/poll.init()
Entering internal/poll.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.1:
	 *init$guard = true:bool
	 t1 = errors.init()
Entering errors.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving errors.init, resuming internal/poll.init.
	 t2 = sync/atomic.init()
Entering sync/atomic.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving sync/atomic.init, resuming internal/poll.init.
	 t3 = sync.init()
Entering sync.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving sync.init, resuming internal/poll.init.
	 t4 = syscall.init()
Entering syscall.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving syscall.init, resuming internal/poll.init.
	 t5 = time.init()
Entering time.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving time.init, resuming internal/poll.init.
	 t6 = io.init()
Entering io.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving io.init, resuming internal/poll.init.
	 t7 = unsafe.init()
Entering unsafe.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving unsafe.init, resuming internal/poll.init.
	 t8 = errors.New("use of closed net...":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming internal/poll.init at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd.go:18:31.
	 *ErrNetClosing = t8
	 t9 = errors.New("use of closed file":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming internal/poll.init at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd.go:22:32.
	 *ErrFileClosing = t9
	 t10 = new TimeoutError (complit)
	 t11 = make error <- *TimeoutError (t10)
	 *ErrTimeout = t11
	 *TestHookDidWritev = init$1
	 *CloseFunc = syscall.Close
	 *AcceptFunc = syscall.Accept
	 jump 2
.2:
	 return
Leaving internal/poll.init, resuming os.init.
	 t9 = errors.New("invalid argument":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/error.go:13:28.
	 *ErrInvalid = t9
	 t10 = errors.New("permission denied":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/error.go:14:28.
	 *ErrPermission = t10
	 t11 = errors.New("file already exists":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/error.go:15:28.
	 *ErrExist = t11
	 t12 = errors.New("file does not exist":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/error.go:16:28.
	 *ErrNotExist = t12
	 t13 = errors.New("file already closed":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/error.go:17:28.
	 *ErrClosed = t13
	 t14 = make Signal <- syscall.Signal (2:syscall.Signal)
	 *Interrupt = t14
	 t15 = make Signal <- syscall.Signal (9:syscall.Signal)
	 *Kill = t15
	 t16 = errors.New("os: process alrea...":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/exec_unix.go:53:29.
	 *errFinished = t16
	 t17 = *syscall.Stdin
	 t18 = convert uintptr <- int (t17)
	 t19 = NewFile(t18, "/dev/stdin":string)
Entering os.NewFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:76:6.
.0:
	 t0 = newFile(fd, name, false:bool)
Entering os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:82:6.
.0:
	 t0 = convert int <- uintptr (fd)
	 t1 = t0 < 0:int
	 if t1 goto 1 else 2
.2:
	 t2 = new File (complit)
	 t3 = &t2.file [#0]
	 t4 = new file (complit)
	 t5 = &t4.pfd [#0]
	 t6 = &t5.Sysfd [#1]
	 t7 = &t5.IsStream [#4]
	 t8 = &t5.ZeroReadIsEOF [#5]
	 t9 = &t4.name [#1]
	 *t6 = t0
	 *t7 = true:bool
	 *t8 = true:bool
	 *t9 = name
	 *t3 = t4
	 if false:untyped bool goto 3 else 4
.4:
	 t10 = phi [2: pollable, 3: false:bool] #pollable
	 t11 = &t2.file [#0]
	 t12 = *t11
	 t13 = &t12.pfd [#0]
	 t14 = (*internal/poll.FD).Init(t13, "file":string, t10)
Entering (*internal/poll.FD).Init at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:46:15.
.0:
	 t0 = net == "file":string
	 if t0 goto 1 else 2
.1:
	 t1 = &fd.isFile [#6]
	 *t1 = true:bool
	 jump 2
.2:
	 if pollable goto 4 else 3
.3:
	 return nil:error
Leaving (*internal/poll.FD).Init, resuming os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:103:22.
	 t15 = t14 != nil:error
	 if t15 goto 5 else 6
.6:
	 if t10 goto 7 else 5
.5:
	 t16 = &t2.file [#0]
	 t17 = *t16
	 t18 = make interface{} <- *file (t17)
	 t19 = make interface{} <- func(file *file) error ((*file).close$thunk)
	 t20 = runtime.SetFinalizer(t18, t19)
Entering runtime.SetFinalizer at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:309:6.
	(external)
Leaving runtime.SetFinalizer, resuming os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:118:22.
	 return t2
Leaving os.newFile, resuming os.NewFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:77:16.
	 return t0
Leaving os.NewFile, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:56:18.
	 *Stdin = t19
	 t20 = *syscall.Stdout
	 t21 = convert uintptr <- int (t20)
	 t22 = NewFile(t21, "/dev/stdout":string)
Entering os.NewFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:76:6.
.0:
	 t0 = newFile(fd, name, false:bool)
Entering os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:82:6.
.0:
	 t0 = convert int <- uintptr (fd)
	 t1 = t0 < 0:int
	 if t1 goto 1 else 2
.2:
	 t2 = new File (complit)
	 t3 = &t2.file [#0]
	 t4 = new file (complit)
	 t5 = &t4.pfd [#0]
	 t6 = &t5.Sysfd [#1]
	 t7 = &t5.IsStream [#4]
	 t8 = &t5.ZeroReadIsEOF [#5]
	 t9 = &t4.name [#1]
	 *t6 = t0
	 *t7 = true:bool
	 *t8 = true:bool
	 *t9 = name
	 *t3 = t4
	 if false:untyped bool goto 3 else 4
.4:
	 t10 = phi [2: pollable, 3: false:bool] #pollable
	 t11 = &t2.file [#0]
	 t12 = *t11
	 t13 = &t12.pfd [#0]
	 t14 = (*internal/poll.FD).Init(t13, "file":string, t10)
Entering (*internal/poll.FD).Init at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:46:15.
.0:
	 t0 = net == "file":string
	 if t0 goto 1 else 2
.1:
	 t1 = &fd.isFile [#6]
	 *t1 = true:bool
	 jump 2
.2:
	 if pollable goto 4 else 3
.3:
	 return nil:error
Leaving (*internal/poll.FD).Init, resuming os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:103:22.
	 t15 = t14 != nil:error
	 if t15 goto 5 else 6
.6:
	 if t10 goto 7 else 5
.5:
	 t16 = &t2.file [#0]
	 t17 = *t16
	 t18 = make interface{} <- *file (t17)
	 t19 = make interface{} <- func(file *file) error ((*file).close$thunk)
	 t20 = runtime.SetFinalizer(t18, t19)
Entering runtime.SetFinalizer at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:309:6.
	(external)
Leaving runtime.SetFinalizer, resuming os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:118:22.
	 return t2
Leaving os.newFile, resuming os.NewFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:77:16.
	 return t0
Leaving os.NewFile, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:57:18.
	 *Stdout = t22
	 t23 = *syscall.Stderr
	 t24 = convert uintptr <- int (t23)
	 t25 = NewFile(t24, "/dev/stderr":string)
Entering os.NewFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:76:6.
.0:
	 t0 = newFile(fd, name, false:bool)
Entering os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:82:6.
.0:
	 t0 = convert int <- uintptr (fd)
	 t1 = t0 < 0:int
	 if t1 goto 1 else 2
.2:
	 t2 = new File (complit)
	 t3 = &t2.file [#0]
	 t4 = new file (complit)
	 t5 = &t4.pfd [#0]
	 t6 = &t5.Sysfd [#1]
	 t7 = &t5.IsStream [#4]
	 t8 = &t5.ZeroReadIsEOF [#5]
	 t9 = &t4.name [#1]
	 *t6 = t0
	 *t7 = true:bool
	 *t8 = true:bool
	 *t9 = name
	 *t3 = t4
	 if false:untyped bool goto 3 else 4
.4:
	 t10 = phi [2: pollable, 3: false:bool] #pollable
	 t11 = &t2.file [#0]
	 t12 = *t11
	 t13 = &t12.pfd [#0]
	 t14 = (*internal/poll.FD).Init(t13, "file":string, t10)
Entering (*internal/poll.FD).Init at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:46:15.
.0:
	 t0 = net == "file":string
	 if t0 goto 1 else 2
.1:
	 t1 = &fd.isFile [#6]
	 *t1 = true:bool
	 jump 2
.2:
	 if pollable goto 4 else 3
.3:
	 return nil:error
Leaving (*internal/poll.FD).Init, resuming os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:103:22.
	 t15 = t14 != nil:error
	 if t15 goto 5 else 6
.6:
	 if t10 goto 7 else 5
.5:
	 t16 = &t2.file [#0]
	 t17 = *t16
	 t18 = make interface{} <- *file (t17)
	 t19 = make interface{} <- func(file *file) error ((*file).close$thunk)
	 t20 = runtime.SetFinalizer(t18, t19)
Entering runtime.SetFinalizer at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:309:6.
	(external)
Leaving runtime.SetFinalizer, resuming os.newFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:118:22.
	 return t2
Leaving os.newFile, resuming os.NewFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:77:16.
	 return t0
Leaving os.NewFile, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:58:18.
	 *Stderr = t25
	 *useSyscallwd = init$1
	 *lstat = Lstat
	 t26 = Getwd()
Entering os.Getwd at /usr/local/Cellar/go/1.9.2/libexec/src/os/getwd.go:26:6.
.0:
	 if false:untyped bool goto 1 else 2
.2:
	 t3 = Stat(".":string)
Entering os.Stat at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_unix.go:30:6.
.0:
	 t0 = new fileStat (fs)
	 t1 = &t0.sys [#4]
	 t2 = syscall.Stat(name, t1)
Entering syscall.Stat at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/zsyscall_darwin_amd64.go:1193:6.
	(external)
Leaving syscall.Stat, resuming os.Stat at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_unix.go:32:21.
	 t3 = t2 != nil:error
	 if t3 goto 1 else 2
.2:
	 t9 = fillFileStatFromSys(t0, name)
Entering os.fillFileStatFromSys at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:12:6.
.0:
	 t0 = &fs.name [#0]
	 t1 = basename(name)
Entering os.basename at /usr/local/Cellar/go/1.9.2/libexec/src/os/path_unix.go:20:6.
.0:
	 t0 = len(name)
	 t1 = t0 - 1:int
	 jump 3
.3:
	 t5 = phi [0: name, 1: t2] #name
	 t6 = phi [0: t1, 1: t3] #i
	 t7 = t6 > 0:int
	 if t7 goto 4 else 2
.2:
	 t4 = t6 - 1:int
	 jump 7
.7:
	 t13 = phi [2: t4, 9: t17] #i
	 t14 = t13 >= 0:int
	 if t14 goto 5 else 6
.6:
	 t12 = phi [7: t5, 8: t16] #name
	 return t12
Leaving os.basename, resuming os.fillFileStatFromSys at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:13:20.
	 *t0 = t1
	 t2 = &fs.size [#1]
	 t3 = &fs.sys [#4]
	 t4 = &t3.Size [#12]
	 t5 = *t4
	 *t2 = t5
	 t6 = &fs.modTime [#3]
	 t7 = &fs.sys [#4]
	 t8 = &t7.Mtimespec [#9]
	 t9 = *t8
	 t10 = timespecToTime(t9)
Entering os.timespecToTime at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:44:6.
.0:
	 t0 = local syscall.Timespec (ts)
	 *t0 = ts
	 t1 = &t0.Sec [#0]
	 t2 = *t1
	 t3 = &t0.Nsec [#1]
	 t4 = *t3
	 t5 = time.Unix(t2, t4)
Entering time.Unix at /usr/local/Cellar/go/1.9.2/libexec/src/time/time.go:1261:6.
.0:
	 t0 = nsec < 0:int64
	 if t0 goto 1 else 3
.3:
	 t10 = nsec >= 1000000000:int64
	 if t10 goto 1 else 2
.2:
	 t6 = phi [3: sec, 1: t2, 4: t12] #sec
	 t7 = phi [3: nsec, 1: t4, 4: t11] #nsec
	 t8 = convert int32 <- int64 (t7)
	 t9 = unixTime(t6, t8)
Entering time.unixTime at /usr/local/Cellar/go/1.9.2/libexec/src/time/time.go:1052:6.
.0:
	 t0 = local Time (complit)
	 t1 = &t0.wall [#0]
	 t2 = convert uint64 <- int32 (nsec)
	 t3 = &t0.ext [#1]
	 t4 = sec + 62135596800:int64
	 t5 = &t0.loc [#2]
	 t6 = *Local
	 *t1 = t2
	 *t3 = t4
	 *t5 = t6
	 t7 = *t0
	 return t7
Leaving time.unixTime, resuming time.Unix at /usr/local/Cellar/go/1.9.2/libexec/src/time/time.go:1271:17.
	 return t9
Leaving time.Unix, resuming os.timespecToTime at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:45:18.
	 return t5
Leaving os.timespecToTime, resuming os.fillFileStatFromSys at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:15:29.
	 *t6 = t10
	 t11 = &fs.mode [#2]
	 t12 = &fs.sys [#4]
	 t13 = &t12.Mode [#1]
	 t14 = *t13
	 t15 = t14 & 511:uint16
	 t16 = convert FileMode <- uint16 (t15)
	 *t11 = t16
	 t17 = &fs.sys [#4]
	 t18 = &t17.Mode [#1]
	 t19 = *t18
	 t20 = t19 & 61440:uint16
	 t21 = t20 == 24576:uint16
	 if t21 goto 2 else 4
.4:
	 t33 = t20 == 57344:uint16
	 if t33 goto 2 else 5
.5:
	 t34 = t20 == 8192:uint16
	 if t34 goto 3 else 7
.7:
	 t38 = t20 == 16384:uint16
	 if t38 goto 6 else 9
.6:
	 t35 = &fs.mode [#2]
	 t36 = *t35
	 t37 = t36 | 2147483648:FileMode
	 *t35 = t37
	 jump 1
.1:
	 t22 = &fs.sys [#4]
	 t23 = &t22.Mode [#1]
	 t24 = *t23
	 t25 = t24 & 1024:uint16
	 t26 = t25 != 0:uint16
	 if t26 goto 15 else 16
.16:
	 t55 = &fs.sys [#4]
	 t56 = &t55.Mode [#1]
	 t57 = *t56
	 t58 = t57 & 2048:uint16
	 t59 = t58 != 0:uint16
	 if t59 goto 17 else 18
.18:
	 t63 = &fs.sys [#4]
	 t64 = &t63.Mode [#1]
	 t65 = *t64
	 t66 = t65 & 512:uint16
	 t67 = t66 != 0:uint16
	 if t67 goto 19 else 20
.19:
	 t68 = &fs.mode [#2]
	 t69 = *t68
	 t70 = t69 | 1048576:FileMode
	 *t68 = t70
	 jump 20
.20:
	 return
Leaving os.fillFileStatFromSys, resuming os.Stat at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_unix.go:36:21.
	 t10 = make FileInfo <- *fileStat (t0)
	 return t10, nil:error
Leaving os.Stat, resuming os.Getwd at /usr/local/Cellar/go/1.9.2/libexec/src/os/getwd.go:33:18.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = t5 != nil:error
	 if t6 goto 3 else 4
.4:
	 t7 = Getenv("PWD":string)
Entering os.Getenv at /usr/local/Cellar/go/1.9.2/libexec/src/os/env.go:80:6.
.0:
	 t0 = syscall.Getenv(key)
Entering syscall.Getenv at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/env_unix.go:71:6.
.0:
	 t0 = local string (value)
	 t1 = local bool (found)
	 t2 = (*sync.Once).Do(envOnce, copyenv)
Entering (*sync.Once).Do at /usr/local/Cellar/go/1.9.2/libexec/src/sync/once.go:35:16.
.0:
	 t0 = &o.done [#1]
	 t1 = sync/atomic.LoadUint32(t0)
Entering sync/atomic.LoadUint32 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:117:6.
	(external)
Leaving sync/atomic.LoadUint32, resuming (*sync.Once).Do at /usr/local/Cellar/go/1.9.2/libexec/src/sync/once.go:36:22.
	 t2 = t1 == 1:uint32
	 if t2 goto 1 else 2
.2:
	 t3 = &o.m [#0]
	 t4 = (*Mutex).Lock(t3)
Entering (*sync.Mutex).Lock at /usr/local/Cellar/go/1.9.2/libexec/src/sync/mutex.go:72:17.
.0:
	 t0 = &m.state [#0]
	 t1 = sync/atomic.CompareAndSwapInt32(t0, 0:int32, 1:int32)
Entering sync/atomic.CompareAndSwapInt32 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:74:6.
	(external)
Leaving sync/atomic.CompareAndSwapInt32, resuming (*sync.Mutex).Lock at /usr/local/Cellar/go/1.9.2/libexec/src/sync/mutex.go:74:31.
	 if t1 goto 1 else 2
.1:
	 if false:untyped bool goto 3 else 4
.4:
	 return
Leaving (*sync.Mutex).Lock, resuming (*sync.Once).Do at /usr/local/Cellar/go/1.9.2/libexec/src/sync/once.go:40:10.
	 t5 = &o.m [#0]
	 defer (*Mutex).Unlock(t5)
	 t6 = &o.done [#1]
	 t7 = *t6
	 t8 = t7 == 0:uint32
	 if t8 goto 4 else 5
.4:
	 t9 = &o.done [#1]
	 defer sync/atomic.StoreUint32(t9, 1:uint32)
	 t10 = f()
Entering syscall.copyenv at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/env_unix.go:36:6.
.0:
	 t0 = make map[string]int 
	 *env = t0
	 t1 = *envs
	 t2 = len(t1)
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.2:
	 t6 = &t1[t4]
	 t7 = *t6
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.7:
	 t18 = t10 + 1:int
	 jump 5
.5:
	 t10 = phi [2: 0:int, 7: t18] #j
	 t11 = len(t7)
	 t12 = t10 < t11
	 if t12 goto 4 else 1
.4:
	 t8 = t7[t10]
	 t9 = t8 == 61:byte
	 if t9 goto 6 else 7
.6:
	 t13 = slice t7[:t10]
	 t14 = *env
	 t15 = t14[t13],ok
	 t16 = extract t15 #0
	 t17 = extract t15 #1
	 if t17 goto 9 else 8
.8:
	 t19 = *env
	 t19[t13] = t4
	 jump 1
.1:
	 t3 = phi [0: -1:int, 5: t4, 8: t4, 9: t4]
	 t4 = t3 + 1:int
	 t5 = t4 < t2
	 if t5 goto 2 else 3
.3:
	 return
Leaving syscall.copyenv, resuming (*sync.Once).Do at /usr/local/Cellar/go/1.9.2/libexec/src/sync/once.go:44:4.
	 jump 5
.5:
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/sync/once.go:43:3: invoking deferred function call
Entering sync/atomic.StoreUint32 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:135:6.
	(external)
Leaving sync/atomic.StoreUint32, resuming (*sync.Once).Do at /usr/local/Cellar/go/1.9.2/libexec/src/sync/once.go:43:3.
/usr/local/Cellar/go/1.9.2/libexec/src/sync/once.go:41:2: invoking deferred function call
Entering (*sync.Mutex).Unlock at /usr/local/Cellar/go/1.9.2/libexec/src/sync/mutex.go:175:17.
.0:
	 if false:untyped bool goto 1 else 2
.2:
	 t4 = &m.state [#0]
	 t5 = sync/atomic.AddInt32(t4, -1:int32)
Entering sync/atomic.AddInt32 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:92:6.
	(external)
Leaving sync/atomic.AddInt32, resuming (*sync.Mutex).Unlock at /usr/local/Cellar/go/1.9.2/libexec/src/sync/mutex.go:182:24.
	 t6 = t5 + 1:int32
	 t7 = t6 & 1:int32
	 t8 = t7 == 0:int32
	 if t8 goto 3 else 4
.4:
	 t10 = t5 & 4:int32
	 t11 = t10 == 0:int32
	 if t11 goto 5 else 6
.5:
	 jump 7
.7:
	 t14 = phi [5: t5, 12: t26] #old
	 t15 = t14 >> 3:uint
	 t16 = t15 == 0:int32
	 if t16 goto 8 else 10
.8:
	 return
Leaving (*sync.Mutex).Unlock, resuming (*sync.Once).Do at /usr/local/Cellar/go/1.9.2/libexec/src/sync/once.go:41:2.
	 return
Leaving (*sync.Once).Do, resuming syscall.Getenv at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/env_unix.go:72:12.
	 t3 = len(key)
	 t4 = t3 == 0:int
	 if t4 goto 1 else 2
.2:
	 t7 = (*sync.RWMutex).RLock(envLock)
Entering (*sync.RWMutex).RLock at /usr/local/Cellar/go/1.9.2/libexec/src/sync/rwmutex.go:43:20.
.0:
	 if false:untyped bool goto 1 else 2
.2:
	 t4 = &rw.readerCount [#3]
	 t5 = sync/atomic.AddInt32(t4, 1:int32)
Entering sync/atomic.AddInt32 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:92:6.
	(external)
Leaving sync/atomic.AddInt32, resuming (*sync.RWMutex).RLock at /usr/local/Cellar/go/1.9.2/libexec/src/sync/rwmutex.go:48:20.
	 t6 = t5 < 0:int32
	 if t6 goto 3 else 4
.4:
	 if false:untyped bool goto 5 else 6
.6:
	 return
Leaving (*sync.RWMutex).RLock, resuming syscall.Getenv at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/env_unix.go:77:15.
	 defer (*sync.RWMutex).RUnlock(envLock)
	 t8 = *env
	 t9 = t8[key],ok
	 t10 = extract t9 #0
	 t11 = extract t9 #1
	 if t11 goto 5 else 4
.5:
	 t16 = *envs
	 t17 = &t16[t10]
	 t18 = *t17
	 jump 8
.8:
	 t23 = phi [5: 0:int, 10: t30] #i
	 t24 = len(t18)
	 t25 = t23 < t24
	 if t25 goto 6 else 7
.6:
	 t19 = t18[t23]
	 t20 = t19 == 61:byte
	 if t20 goto 9 else 10
.10:
	 t30 = t23 + 1:int
	 jump 8
.8:
	 t23 = phi [5: 0:int, 10: t30] #i
	 t24 = len(t18)
	 t25 = t23 < t24
	 if t25 goto 6 else 7
.6:
	 t19 = t18[t23]
	 t20 = t19 == 61:byte
	 if t20 goto 9 else 10
.10:
	 t30 = t23 + 1:int
	 jump 8
.8:
	 t23 = phi [5: 0:int, 10: t30] #i
	 t24 = len(t18)
	 t25 = t23 < t24
	 if t25 goto 6 else 7
.6:
	 t19 = t18[t23]
	 t20 = t19 == 61:byte
	 if t20 goto 9 else 10
.10:
	 t30 = t23 + 1:int
	 jump 8
.8:
	 t23 = phi [5: 0:int, 10: t30] #i
	 t24 = len(t18)
	 t25 = t23 < t24
	 if t25 goto 6 else 7
.6:
	 t19 = t18[t23]
	 t20 = t19 == 61:byte
	 if t20 goto 9 else 10
.9:
	 t26 = t23 + 1:int
	 t27 = slice t18[t26:]
	 *t0 = t27
	 *t1 = true:bool
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/syscall/env_unix.go:78:2: invoking deferred function call
Entering (*sync.RWMutex).RUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/sync/rwmutex.go:62:20.
.0:
	 if false:untyped bool goto 1 else 2
.2:
	 t7 = &rw.readerCount [#3]
	 t8 = sync/atomic.AddInt32(t7, -1:int32)
Entering sync/atomic.AddInt32 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:92:6.
	(external)
Leaving sync/atomic.AddInt32, resuming (*sync.RWMutex).RUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/sync/rwmutex.go:68:25.
	 t9 = t8 < 0:int32
	 if t9 goto 3 else 4
.4:
	 if false:untyped bool goto 9 else 10
.10:
	 return
Leaving (*sync.RWMutex).RUnlock, resuming syscall.Getenv at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/env_unix.go:78:2.
	 t28 = *t0
	 t29 = *t1
	 return t28, t29
Leaving syscall.Getenv, resuming os.Getenv at /usr/local/Cellar/go/1.9.2/libexec/src/os/env.go:81:24.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 return t1
Leaving os.Getenv, resuming os.Getwd at /usr/local/Cellar/go/1.9.2/libexec/src/os/getwd.go:37:14.
	 t8 = len(t7)
	 t9 = t8 > 0:int
	 if t9 goto 7 else 6
.7:
	 t14 = t7[0:int]
	 t15 = t14 == 47:byte
	 if t15 goto 5 else 6
.5:
	 t10 = Stat(t7)
Entering os.Stat at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_unix.go:30:6.
.0:
	 t0 = new fileStat (fs)
	 t1 = &t0.sys [#4]
	 t2 = syscall.Stat(name, t1)
Entering syscall.Stat at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/zsyscall_darwin_amd64.go:1193:6.
	(external)
Leaving syscall.Stat, resuming os.Stat at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_unix.go:32:21.
	 t3 = t2 != nil:error
	 if t3 goto 1 else 2
.2:
	 t9 = fillFileStatFromSys(t0, name)
Entering os.fillFileStatFromSys at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:12:6.
.0:
	 t0 = &fs.name [#0]
	 t1 = basename(name)
Entering os.basename at /usr/local/Cellar/go/1.9.2/libexec/src/os/path_unix.go:20:6.
.0:
	 t0 = len(name)
	 t1 = t0 - 1:int
	 jump 3
.3:
	 t5 = phi [0: name, 1: t2] #name
	 t6 = phi [0: t1, 1: t3] #i
	 t7 = t6 > 0:int
	 if t7 goto 4 else 2
.4:
	 t8 = t5[t6]
	 t9 = t8 == 47:byte
	 if t9 goto 1 else 2
.2:
	 t4 = t6 - 1:int
	 jump 7
.7:
	 t13 = phi [2: t4, 9: t17] #i
	 t14 = t13 >= 0:int
	 if t14 goto 5 else 6
.5:
	 t10 = t5[t13]
	 t11 = t10 == 47:byte
	 if t11 goto 8 else 9
.9:
	 t17 = t13 - 1:int
	 jump 7
.7:
	 t13 = phi [2: t4, 9: t17] #i
	 t14 = t13 >= 0:int
	 if t14 goto 5 else 6
.5:
	 t10 = t5[t13]
	 t11 = t10 == 47:byte
	 if t11 goto 8 else 9
.9:
	 t17 = t13 - 1:int
	 jump 7
.7:
	 t13 = phi [2: t4, 9: t17] #i
	 t14 = t13 >= 0:int
	 if t14 goto 5 else 6
.5:
	 t10 = t5[t13]
	 t11 = t10 == 47:byte
	 if t11 goto 8 else 9
.8:
	 t15 = t13 + 1:int
	 t16 = slice t5[t15:]
	 jump 6
.6:
	 t12 = phi [7: t5, 8: t16] #name
	 return t12
Leaving os.basename, resuming os.fillFileStatFromSys at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:13:20.
	 *t0 = t1
	 t2 = &fs.size [#1]
	 t3 = &fs.sys [#4]
	 t4 = &t3.Size [#12]
	 t5 = *t4
	 *t2 = t5
	 t6 = &fs.modTime [#3]
	 t7 = &fs.sys [#4]
	 t8 = &t7.Mtimespec [#9]
	 t9 = *t8
	 t10 = timespecToTime(t9)
Entering os.timespecToTime at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:44:6.
.0:
	 t0 = local syscall.Timespec (ts)
	 *t0 = ts
	 t1 = &t0.Sec [#0]
	 t2 = *t1
	 t3 = &t0.Nsec [#1]
	 t4 = *t3
	 t5 = time.Unix(t2, t4)
Entering time.Unix at /usr/local/Cellar/go/1.9.2/libexec/src/time/time.go:1261:6.
.0:
	 t0 = nsec < 0:int64
	 if t0 goto 1 else 3
.3:
	 t10 = nsec >= 1000000000:int64
	 if t10 goto 1 else 2
.2:
	 t6 = phi [3: sec, 1: t2, 4: t12] #sec
	 t7 = phi [3: nsec, 1: t4, 4: t11] #nsec
	 t8 = convert int32 <- int64 (t7)
	 t9 = unixTime(t6, t8)
Entering time.unixTime at /usr/local/Cellar/go/1.9.2/libexec/src/time/time.go:1052:6.
.0:
	 t0 = local Time (complit)
	 t1 = &t0.wall [#0]
	 t2 = convert uint64 <- int32 (nsec)
	 t3 = &t0.ext [#1]
	 t4 = sec + 62135596800:int64
	 t5 = &t0.loc [#2]
	 t6 = *Local
	 *t1 = t2
	 *t3 = t4
	 *t5 = t6
	 t7 = *t0
	 return t7
Leaving time.unixTime, resuming time.Unix at /usr/local/Cellar/go/1.9.2/libexec/src/time/time.go:1271:17.
	 return t9
Leaving time.Unix, resuming os.timespecToTime at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:45:18.
	 return t5
Leaving os.timespecToTime, resuming os.fillFileStatFromSys at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_darwin.go:15:29.
	 *t6 = t10
	 t11 = &fs.mode [#2]
	 t12 = &fs.sys [#4]
	 t13 = &t12.Mode [#1]
	 t14 = *t13
	 t15 = t14 & 511:uint16
	 t16 = convert FileMode <- uint16 (t15)
	 *t11 = t16
	 t17 = &fs.sys [#4]
	 t18 = &t17.Mode [#1]
	 t19 = *t18
	 t20 = t19 & 61440:uint16
	 t21 = t20 == 24576:uint16
	 if t21 goto 2 else 4
.4:
	 t33 = t20 == 57344:uint16
	 if t33 goto 2 else 5
.5:
	 t34 = t20 == 8192:uint16
	 if t34 goto 3 else 7
.7:
	 t38 = t20 == 16384:uint16
	 if t38 goto 6 else 9
.6:
	 t35 = &fs.mode [#2]
	 t36 = *t35
	 t37 = t36 | 2147483648:FileMode
	 *t35 = t37
	 jump 1
.1:
	 t22 = &fs.sys [#4]
	 t23 = &t22.Mode [#1]
	 t24 = *t23
	 t25 = t24 & 1024:uint16
	 t26 = t25 != 0:uint16
	 if t26 goto 15 else 16
.16:
	 t55 = &fs.sys [#4]
	 t56 = &t55.Mode [#1]
	 t57 = *t56
	 t58 = t57 & 2048:uint16
	 t59 = t58 != 0:uint16
	 if t59 goto 17 else 18
.18:
	 t63 = &fs.sys [#4]
	 t64 = &t63.Mode [#1]
	 t65 = *t64
	 t66 = t65 & 512:uint16
	 t67 = t66 != 0:uint16
	 if t67 goto 19 else 20
.19:
	 t68 = &fs.mode [#2]
	 t69 = *t68
	 t70 = t69 | 1048576:FileMode
	 *t68 = t70
	 jump 20
.20:
	 return
Leaving os.fillFileStatFromSys, resuming os.Stat at /usr/local/Cellar/go/1.9.2/libexec/src/os/stat_unix.go:36:21.
	 t10 = make FileInfo <- *fileStat (t0)
	 return t10, nil:error
Leaving os.Stat, resuming os.Getwd at /usr/local/Cellar/go/1.9.2/libexec/src/os/getwd.go:39:17.
	 t11 = extract t10 #0
	 t12 = extract t10 #1
	 t13 = t12 == nil:error
	 if t13 goto 9 else 6
.9:
	 t16 = SameFile(t4, t11)
Entering os.SameFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/types.go:116:6.
.0:
	 t0 = typeassert,ok fi1.(*fileStat)
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = typeassert,ok fi2.(*fileStat)
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 if t2 goto 3 else 1
.3:
	 if t5 goto 2 else 1
.2:
	 t6 = sameFile(t1, t4)
Entering os.sameFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/types_unix.go:29:6.
.0:
	 t0 = &fs1.sys [#4]
	 t1 = &t0.Dev [#0]
	 t2 = *t1
	 t3 = &fs2.sys [#4]
	 t4 = &t3.Dev [#0]
	 t5 = *t4
	 t6 = t2 == t5
	 if t6 goto 1 else 2
.1:
	 t7 = &fs1.sys [#4]
	 t8 = &t7.Ino [#3]
	 t9 = *t8
	 t10 = &fs2.sys [#4]
	 t11 = &t10.Ino [#3]
	 t12 = *t11
	 t13 = t9 == t12
	 jump 2
.2:
	 t14 = phi [0: false:bool, 1: t13] #&&
	 return t14
Leaving os.sameFile, resuming os.SameFile at /usr/local/Cellar/go/1.9.2/libexec/src/os/types.go:122:17.
	 return t6
Leaving os.SameFile, resuming os.Getwd at /usr/local/Cellar/go/1.9.2/libexec/src/os/getwd.go:40:28.
	 if t16 goto 8 else 6
.8:
	 return t7, nil:error
Leaving os.Getwd, resuming os.init at /usr/local/Cellar/go/1.9.2/libexec/src/os/executable_darwin.go:9:32.
	 t27 = extract t26 #0
	 *initCwd = t27
	 t28 = extract t26 #1
	 *initCwdErr = t28
	 t29 = init#1()
Entering os.init#1 at /usr/local/Cellar/go/1.9.2/libexec/src/os/getwd_darwin.go:9:6.
.0:
	 *useSyscallwd = useSyscallwdDarwin
	 return
Leaving os.init#1, resuming os.init.
	 t30 = init#2()
Entering os.init#2 at /usr/local/Cellar/go/1.9.2/libexec/src/os/proc.go:17:6.
.0:
	 if false:untyped bool goto 1 else 2
.2:
	 t0 = runtime_args()
Entering os.runtime_args at /usr/local/Cellar/go/1.9.2/libexec/src/os/proc.go:25:6.
	(external)
Leaving os.runtime_args, resuming os.init#2 at /usr/local/Cellar/go/1.9.2/libexec/src/os/proc.go:22:21.
	 *Args = t0
	 return
Leaving os.init#2, resuming os.init.
	 jump 2
.2:
	 return
Leaving os.init, resuming fmt.init.
	 t6 = reflect.init()
Entering reflect.init.
	(external)
Leaving reflect.init, resuming fmt.init.
	 t7 = sync.init()
Entering sync.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving sync.init, resuming fmt.init.
	 t8 = math.init()
Entering math.init.
.0:
	 t0 = *init$guard
	 if t0 goto 2 else 1
.2:
	 return
Leaving math.init, resuming fmt.init.
	 t9 = &ppFree.New [#3]
	 *t9 = init$1
	 t10 = new [10][2]uint16 (slicelit)
	 t11 = &t10[0:int]
	 t12 = &t11[0:int]
	 t13 = &t11[1:int]
	 *t12 = 9:uint16
	 *t13 = 13:uint16
	 t14 = &t10[1:int]
	 t15 = &t14[0:int]
	 t16 = &t14[1:int]
	 *t15 = 32:uint16
	 *t16 = 32:uint16
	 t17 = &t10[2:int]
	 t18 = &t17[0:int]
	 t19 = &t17[1:int]
	 *t18 = 133:uint16
	 *t19 = 133:uint16
	 t20 = &t10[3:int]
	 t21 = &t20[0:int]
	 t22 = &t20[1:int]
	 *t21 = 160:uint16
	 *t22 = 160:uint16
	 t23 = &t10[4:int]
	 t24 = &t23[0:int]
	 t25 = &t23[1:int]
	 *t24 = 5760:uint16
	 *t25 = 5760:uint16
	 t26 = &t10[5:int]
	 t27 = &t26[0:int]
	 t28 = &t26[1:int]
	 *t27 = 8192:uint16
	 *t28 = 8202:uint16
	 t29 = &t10[6:int]
	 t30 = &t29[0:int]
	 t31 = &t29[1:int]
	 *t30 = 8232:uint16
	 *t31 = 8233:uint16
	 t32 = &t10[7:int]
	 t33 = &t32[0:int]
	 t34 = &t32[1:int]
	 *t33 = 8239:uint16
	 *t34 = 8239:uint16
	 t35 = &t10[8:int]
	 t36 = &t35[0:int]
	 t37 = &t35[1:int]
	 *t36 = 8287:uint16
	 *t37 = 8287:uint16
	 t38 = &t10[9:int]
	 t39 = &t38[0:int]
	 t40 = &t38[1:int]
	 *t39 = 12288:uint16
	 *t40 = 12288:uint16
	 t41 = slice t10[:]
	 *space = t41
	 t42 = &ssFree.New [#3]
	 *t42 = init$2
	 t43 = errors.New("syntax error scan...":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming fmt.init at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:473:30.
	 *complexError = t43
	 t44 = errors.New("syntax error scan...":string)
Entering errors.New at /usr/local/Cellar/go/1.9.2/libexec/src/errors/errors.go:9:6.
.0:
	 t0 = new errorString (complit)
	 t1 = &t0.s [#0]
	 *t1 = text
	 t2 = make error <- *errorString (t0)
	 return t2
Leaving errors.New, resuming fmt.init at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:474:27.
	 *boolError = t44
	 jump 2
.2:
	 return
Leaving fmt.init, resuming main.init.
	 jump 2
.2:
	 return
Leaving main.init.
Entering main.main at /tmp/gogo.go:172:6.
.0:
	 t0 = new string (sa)
	 t1 = new string (sb)
	 t2 = new string (sc)
	 t3 = new [1]interface{} (varargs)
	 t4 = &t3[0:int]
	 t5 = make interface{} <- string ("Input 3 numbers":string)
	 *t4 = t5
	 t6 = slice t3[:]
	 t7 = fmt.Println(t6...)
Entering fmt.Println at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:256:6.
.0:
	 t0 = *os.Stdout
	 t1 = make io.Writer <- *os.File (t0)
	 t2 = Fprintln(t1, a...)
Entering fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:245:6.
.0:
	 t0 = newPrinter()
Entering fmt.newPrinter at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:132:6.
.0:
	 t0 = (*sync.Pool).Get(ppFree)
Entering (*sync.Pool).Get at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:124:16.
	(external)
Entering fmt.init$1 at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:128:7.
.0:
	 t0 = new pp (new)
	 t1 = make interface{} <- *pp (t0)
	 return t1
Leaving fmt.init$1, resuming (*sync.Pool).Get.
Leaving (*sync.Pool).Get, resuming fmt.newPrinter at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:133:17.
	 t1 = typeassert t0.(*pp)
	 t2 = &t1.panicking [#6]
	 *t2 = false:bool
	 t3 = &t1.erroring [#7]
	 *t3 = false:bool
	 t4 = &t1.fmt [#3]
	 t5 = &t1.buf [#0]
	 t6 = (*fmt).init(t4, t5)
Entering (*fmt.fmt).init at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:58:15.
.0:
	 t0 = &f.buf [#0]
	 *t0 = buf
	 t1 = (*fmt).clearflags(f)
Entering (*fmt.fmt).clearflags at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:54:15.
.0:
	 t0 = &f.fmtFlags [#1]
	 t1 = local fmtFlags ()
	 t2 = *t1
	 *t0 = t2
	 return
Leaving (*fmt.fmt).clearflags, resuming (*fmt.fmt).init at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:60:14.
	 return
Leaving (*fmt.fmt).init, resuming fmt.newPrinter at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:136:12.
	 return t1
Leaving fmt.newPrinter, resuming fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:246:17.
	 t1 = (*pp).doPrintln(t0, a)
Entering (*fmt.pp).doPrintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:1131:14.
.0:
	 t0 = len(a)
	 jump 1
.1:
	 t1 = phi [0: -1:int, 5: t2]
	 t2 = t1 + 1:int
	 t3 = t2 < t0
	 if t3 goto 2 else 3
.2:
	 t4 = &a[t2]
	 t5 = *t4
	 t6 = t2 > 0:int
	 if t6 goto 4 else 5
.5:
	 t11 = (*pp).printArg(p, t5, 118:rune)
Entering (*fmt.pp).printArg at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:604:14.
.0:
	 t0 = &p.arg [#1]
	 *t0 = arg
	 t1 = &p.value [#2]
	 t2 = local reflect.Value ()
	 t3 = *t2
	 *t1 = t3
	 t4 = arg == nil:interface{}
	 if t4 goto 1 else 2
.2:
	 t6 = verb == 84:rune
	 if t6 goto 7 else 9
.9:
	 t17 = verb == 112:rune
	 if t17 goto 8 else 10
.10:
	 t18 = typeassert,ok arg.(bool)
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 if t20 goto 12 else 13
.13:
	 t22 = typeassert,ok arg.(float32)
	 t23 = extract t22 #0
	 t24 = extract t22 #1
	 if t24 goto 14 else 15
.15:
	 t27 = typeassert,ok arg.(float64)
	 t28 = extract t27 #0
	 t29 = extract t27 #1
	 if t29 goto 16 else 17
.17:
	 t31 = typeassert,ok arg.(complex64)
	 t32 = extract t31 #0
	 t33 = extract t31 #1
	 if t33 goto 18 else 19
.19:
	 t36 = typeassert,ok arg.(complex128)
	 t37 = extract t36 #0
	 t38 = extract t36 #1
	 if t38 goto 20 else 21
.21:
	 t40 = typeassert,ok arg.(int)
	 t41 = extract t40 #0
	 t42 = extract t40 #1
	 if t42 goto 22 else 23
.23:
	 t45 = typeassert,ok arg.(int8)
	 t46 = extract t45 #0
	 t47 = extract t45 #1
	 if t47 goto 24 else 25
.25:
	 t50 = typeassert,ok arg.(int16)
	 t51 = extract t50 #0
	 t52 = extract t50 #1
	 if t52 goto 26 else 27
.27:
	 t55 = typeassert,ok arg.(int32)
	 t56 = extract t55 #0
	 t57 = extract t55 #1
	 if t57 goto 28 else 29
.29:
	 t60 = typeassert,ok arg.(int64)
	 t61 = extract t60 #0
	 t62 = extract t60 #1
	 if t62 goto 30 else 31
.31:
	 t65 = typeassert,ok arg.(uint)
	 t66 = extract t65 #0
	 t67 = extract t65 #1
	 if t67 goto 32 else 33
.33:
	 t70 = typeassert,ok arg.(uint8)
	 t71 = extract t70 #0
	 t72 = extract t70 #1
	 if t72 goto 34 else 35
.35:
	 t75 = typeassert,ok arg.(uint16)
	 t76 = extract t75 #0
	 t77 = extract t75 #1
	 if t77 goto 36 else 37
.37:
	 t80 = typeassert,ok arg.(uint32)
	 t81 = extract t80 #0
	 t82 = extract t80 #1
	 if t82 goto 38 else 39
.39:
	 t85 = typeassert,ok arg.(uint64)
	 t86 = extract t85 #0
	 t87 = extract t85 #1
	 if t87 goto 40 else 41
.41:
	 t89 = typeassert,ok arg.(uintptr)
	 t90 = extract t89 #0
	 t91 = extract t89 #1
	 if t91 goto 42 else 43
.43:
	 t94 = typeassert,ok arg.(string)
	 t95 = extract t94 #0
	 t96 = extract t94 #1
	 if t96 goto 44 else 45
.44:
	 t97 = (*pp).fmtString(p, t95, verb)
Entering (*fmt.pp).fmtString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:424:14.
.0:
	 t0 = verb == 118:rune
	 if t0 goto 2 else 4
.2:
	 t1 = &p.fmt [#3]
	 t2 = &t1.fmtFlags [#1]
	 t3 = &t2.sharpV [#8]
	 t4 = *t3
	 if t4 goto 5 else 6
.6:
	 t10 = &p.fmt [#3]
	 t11 = (*fmt).fmt_s(t10, v)
Entering (*fmt.fmt).fmt_s at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:326:15.
.0:
	 t0 = (*fmt).truncate(f, s)
Entering (*fmt.fmt).truncate at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:312:15.
.0:
	 t0 = &f.fmtFlags [#1]
	 t1 = &t0.precPresent [#1]
	 t2 = *t1
	 if t2 goto 1 else 2
.2:
	 return s
Leaving (*fmt.fmt).truncate, resuming (*fmt.fmt).fmt_s at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:327:16.
	 t1 = (*fmt).padString(f, t0)
Entering (*fmt.fmt).padString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:108:15.
.0:
	 t0 = &f.fmtFlags [#1]
	 t1 = &t0.widPresent [#0]
	 t2 = *t1
	 if t2 goto 3 else 1
.1:
	 t3 = &f.buf [#0]
	 t4 = *t3
	 t5 = (*buffer).WriteString(t4, s)
Entering (*fmt.buffer).WriteString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:81:18.
.0:
	 t0 = *b
	 t1 = append(t0, s...)
	 *b = t1
	 return
Leaving (*fmt.buffer).WriteString, resuming (*fmt.fmt).padString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:110:20.
	 return
Leaving (*fmt.fmt).padString, resuming (*fmt.fmt).fmt_s at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:328:13.
	 return
Leaving (*fmt.fmt).fmt_s, resuming (*fmt.pp).fmtString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:430:15.
	 jump 1
.1:
	 return
Leaving (*fmt.pp).fmtString, resuming (*fmt.pp).printArg at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:664:14.
	 jump 11
.11:
	 return
Leaving (*fmt.pp).printArg, resuming (*fmt.pp).doPrintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:1136:13.
	 jump 1
.1:
	 t1 = phi [0: -1:int, 5: t2]
	 t2 = t1 + 1:int
	 t3 = t2 < t0
	 if t3 goto 2 else 3
.3:
	 t7 = &p.buf [#0]
	 t8 = (*buffer).WriteByte(t7, 10:byte)
Entering (*fmt.buffer).WriteByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:85:18.
.0:
	 t0 = *b
	 t1 = new [1]byte (varargs)
	 t2 = &t1[0:int]
	 *t2 = c
	 t3 = slice t1[:]
	 t4 = append(t0, t3...)
	 *b = t4
	 return
Leaving (*fmt.buffer).WriteByte, resuming (*fmt.pp).doPrintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:1138:17.
	 return
Leaving (*fmt.pp).doPrintln, resuming fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:247:13.
	 t2 = &t0.buf [#0]
	 t3 = *t2
	 t4 = changetype []byte <- buffer (t3)
	 t5 = invoke w.Write(t4)
Entering (*os.File).Write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:136:16.
.0:
	 t0 = (*File).checkValid(f, "write":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:137:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).write(f, b)
Entering (*os.File).write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:232:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Write(t2, b)
Entering (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:205:15.
.0:
	 t0 = (*FD).writeLock(fd)
Entering (*internal/poll.FD).writeLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:236:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, false:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.2:
	 t1 = &mu.wsema [#2]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).writeLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:237:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).writeLock, resuming (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:206:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).writeUnlock(fd)
	 t2 = &fd.pd [#2]
	 t3 = &fd.isFile [#6]
	 t4 = *t3
	 t5 = (*pollDesc).prepareWrite(t2, t4)
Entering (*internal/poll.pollDesc).prepareWrite at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:77:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 119:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareWrite at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:78:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareWrite, resuming (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:210:30.
	 t6 = t5 != nil:error
	 if t6 goto 4 else 5
.5:
	 jump 6
.6:
	 t7 = phi [5: 0:int, 14: t23, 18: t23] #nn
	 t8 = len(p)
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 8
.9:
	 t20 = t8 - t7
	 t21 = t20 > 1073741824:int
	 if t21 goto 7 else 8
.8:
	 t12 = phi [6: t8, 9: t8, 7: t11] #max
	 t13 = &fd.Sysfd [#1]
	 t14 = *t13
	 t15 = slice p[t7:t12]
	 t16 = syscall.Write(t14, t15)
Entering syscall.Write at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:177:6.
	(external)
Leaving syscall.Write, resuming (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:219:26.
	 t17 = extract t16 #0
	 t18 = extract t16 #1
	 t19 = t17 > 0:int
	 if t19 goto 10 else 11
.10:
	 t22 = t7 + t17
	 jump 11
.11:
	 t23 = phi [8: t7, 10: t22] #nn
	 t24 = len(p)
	 t25 = t23 == t24
	 if t25 goto 12 else 13
.12:
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:209:2: invoking deferred function call
Entering (*internal/poll.FD).writeUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:246:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, false:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.2:
	 t1 = &mu.wsema [#2]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).writeUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:247:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).writeUnlock, resuming (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:209:2.
	 return t23, t18
Leaving (*internal/poll.FD).Write, resuming (*os.File).write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:233:22.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:234:19.
	 return t4, t5
Leaving (*os.File).write, resuming (*os.File).Write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:140:17.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = t3 < 0:int
	 if t5 goto 3 else 4
.4:
	 t6 = phi [2: t3, 3: 0:int] #n
	 t7 = len(b)
	 t8 = t6 != t7
	 if t8 goto 5 else 6
.6:
	 t10 = phi [4: nil:error, 5: t9] #err
	 t11 = epipecheck(f, t4)
Entering os.epipecheck at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:132:6.
.0:
	 t0 = make error <- syscall.Errno (32:syscall.Errno)
	 t1 = e == t0
	 if t1 goto 3 else 2
.2:
	 return
Leaving os.epipecheck, resuming (*os.File).Write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:148:12.
	 t12 = t4 != nil:error
	 if t12 goto 7 else 8
.8:
	 t14 = phi [6: t10, 7: t13] #err
	 return t6, t14
Leaving (*os.File).Write, resuming fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:248:18.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = (*pp).free(t0)
Entering (*fmt.pp).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:141:14.
.0:
	 t0 = &p.buf [#0]
	 t1 = &p.buf [#0]
	 t2 = *t1
	 t3 = slice t2[:0:int]
	 *t0 = t3
	 t4 = &p.arg [#1]
	 *t4 = nil:interface{}
	 t5 = &p.value [#2]
	 t6 = local reflect.Value ()
	 t7 = *t6
	 *t5 = t7
	 t8 = make interface{} <- *pp (p)
	 t9 = (*sync.Pool).Put(ppFree, t8)
Entering (*sync.Pool).Put at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:88:16.
	(external)
Leaving (*sync.Pool).Put, resuming (*fmt.pp).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:145:12.
	 return
Leaving (*fmt.pp).free, resuming fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:249:8.
	 return t6, t7
Leaving fmt.Fprintln, resuming fmt.Println at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:257:17.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 return t3, t4
Leaving fmt.Println, resuming main.main at /tmp/gogo.go:192:16.
	 t8 = new [1]interface{} (varargs)
	 t9 = &t8[0:int]
	 t10 = make interface{} <- *string (t0)
	 *t9 = t10
	 t11 = slice t8[:]
	 t12 = fmt.Scanf("%s":string, t11...)
Entering fmt.Scanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:80:6.
.0:
	 t0 = *os.Stdin
	 t1 = make io.Reader <- *os.File (t0)
	 t2 = Fscanf(t1, format, a...)
Entering fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:141:6.
.0:
	 t0 = local ssave (old)
	 t1 = newScanState(r, false:bool, false:bool)
Entering fmt.newScanState at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:390:6.
.0:
	 t0 = local ssave (old)
	 t1 = (*sync.Pool).Get(ssFree)
Entering (*sync.Pool).Get at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:124:16.
	(external)
Entering fmt.init$2 at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:386:7.
.0:
	 t0 = new ss (new)
	 t1 = make interface{} <- *ss (t0)
	 return t1
Leaving fmt.init$2, resuming (*sync.Pool).Get.
Leaving (*sync.Pool).Get, resuming fmt.newScanState at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:391:16.
	 t2 = typeassert t1.(*ss)
	 t3 = typeassert,ok r.(io.RuneScanner)
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 if t5 goto 1 else 3
.3:
	 t22 = &t2.rs [#0]
	 t23 = new readRune (complit)
	 t24 = &t23.reader [#0]
	 t25 = &t23.peekRune [#4]
	 *t24 = r
	 *t25 = -1:rune
	 t26 = make io.RuneScanner <- *readRune (t23)
	 *t22 = t26
	 jump 2
.2:
	 t7 = &t2.ssave [#4]
	 t8 = &t7.nlIsSpace [#2]
	 *t8 = nlIsSpace
	 t9 = &t2.ssave [#4]
	 t10 = &t9.nlIsEnd [#1]
	 *t10 = nlIsEnd
	 t11 = &t2.atEOF [#3]
	 *t11 = false:bool
	 t12 = &t2.ssave [#4]
	 t13 = &t12.limit [#4]
	 *t13 = 1073741824:int
	 t14 = &t2.ssave [#4]
	 t15 = &t14.argLimit [#3]
	 *t15 = 1073741824:int
	 t16 = &t2.ssave [#4]
	 t17 = &t16.maxWid [#5]
	 *t17 = 1073741824:int
	 t18 = &t2.ssave [#4]
	 t19 = &t18.validSave [#0]
	 *t19 = true:bool
	 t20 = &t2.count [#2]
	 *t20 = 0:int
	 t21 = *t0
	 return t2, t21
Leaving fmt.newScanState, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:142:24.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 *t0 = t3
	 t4 = (*ss).doScanf(t2, format, a)
Entering (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1156:14.
.0:
	 t0 = local int (numProcessed)
	 t1 = new error (err)
	 defer errorHandler(t1)
	 t2 = len(format)
	 t3 = t2 - 1:int
	 jump 4
.4:
	 t12 = phi [0: 0:int, 5: t14, 17: t32] #i
	 t13 = t12 <= t3
	 if t13 goto 2 else 3
.2:
	 t6 = slice format[t12:]
	 t7 = (*ss).advance(s, t6)
Entering (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1075:14.
.0:
	 jump 3
.3:
	 t5 = phi [0: 0:int, 14: t10, 41: t65, 30: t10, 33: t10] #i
	 t6 = len(format)
	 t7 = t5 < t6
	 if t7 goto 1 else 2
.1:
	 t0 = slice format[t5:]
	 t1 = unicode/utf8.DecodeRuneInString(t0)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1077:37.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 t4 = isSpace(t2)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1085:13.
	 if t4 goto 4 else 5
.5:
	 t8 = t2 == 37:rune
	 if t8 goto 34 else 35
.34:
	 t50 = t5 + t3
	 t51 = len(format)
	 t52 = t50 == t51
	 if t52 goto 36 else 37
.37:
	 t57 = t5 + t3
	 t58 = slice format[t57:]
	 t59 = unicode/utf8.DecodeRuneInString(t58)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1136:39.
	 t60 = extract t59 #0
	 t61 = extract t59 #1
	 t62 = t60 != 37:rune
	 if t62 goto 38 else 39
.38:
	 return t5
Leaving (*fmt.ss).advance, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1161:17.
	 t8 = t7 > 0:int
	 if t8 goto 5 else 6
.6:
	 t15 = format[t12]
	 t16 = t15 != 37:byte
	 if t16 goto 7 else 8
.8:
	 t18 = t12 + 1:int
	 t19 = &s.ssave [#4]
	 t20 = &t19.maxWid [#5]
	 t21 = parsenum(format, t18, t3)
Entering fmt.parsenum at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:289:6.
.0:
	 t0 = start >= end
	 if t0 goto 1 else 2
.1:
	 return 0:int, false:bool, end
Leaving fmt.parsenum, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1179:37.
	 t22 = extract t21 #0
	 *t20 = t22
	 t23 = extract t21 #1
	 t24 = extract t21 #2
	 if t23 goto 11 else 10
.10:
	 t26 = &s.ssave [#4]
	 t27 = &t26.maxWid [#5]
	 *t27 = 1073741824:int
	 jump 11
.11:
	 t28 = slice format[t24:]
	 t29 = unicode/utf8.DecodeRuneInString(t28)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1184:34.
	 t30 = extract t29 #0
	 t31 = extract t29 #1
	 t32 = t24 + t31
	 t33 = t30 != 99:rune
	 if t33 goto 12 else 13
.12:
	 t34 = (*ss).SkipSpace(s)
Entering (*fmt.ss).SkipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:304:14.
.0:
	 t0 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).SkipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:305:13.
	 return
Leaving (*fmt.ss).SkipSpace, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1188:15.
	 jump 13
.13:
	 t35 = &s.ssave [#4]
	 t36 = &t35.argLimit [#3]
	 t37 = &s.ssave [#4]
	 t38 = &t37.limit [#4]
	 t39 = *t38
	 *t36 = t39
	 t40 = &s.count [#2]
	 t41 = *t40
	 t42 = &s.ssave [#4]
	 t43 = &t42.maxWid [#5]
	 t44 = *t43
	 t45 = t41 + t44
	 t46 = &s.ssave [#4]
	 t47 = &t46.argLimit [#3]
	 t48 = *t47
	 t49 = t45 < t48
	 if t49 goto 14 else 15
.15:
	 t52 = *t0
	 t53 = len(a)
	 t54 = t52 >= t53
	 if t54 goto 16 else 17
.17:
	 t60 = *t0
	 t61 = &a[t60]
	 t62 = *t61
	 t63 = (*ss).scanOne(s, t30, t62)
Entering (*fmt.ss).scanOne at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:928:14.
.0:
	 t0 = &s.buf [#1]
	 t1 = &s.buf [#1]
	 t2 = *t1
	 t3 = slice t2[:0:int]
	 *t0 = t3
	 t4 = typeassert,ok arg.(Scanner)
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 if t6 goto 1 else 2
.2:
	 t10 = typeassert,ok arg.(*bool)
	 t11 = extract t10 #0
	 t12 = extract t10 #1
	 if t12 goto 8 else 9
.9:
	 t19 = typeassert,ok arg.(*complex64)
	 t20 = extract t19 #0
	 t21 = extract t19 #1
	 if t21 goto 10 else 11
.11:
	 t24 = typeassert,ok arg.(*complex128)
	 t25 = extract t24 #0
	 t26 = extract t24 #1
	 if t26 goto 12 else 13
.13:
	 t28 = typeassert,ok arg.(*int)
	 t29 = extract t28 #0
	 t30 = extract t28 #1
	 if t30 goto 14 else 15
.15:
	 t33 = typeassert,ok arg.(*int8)
	 t34 = extract t33 #0
	 t35 = extract t33 #1
	 if t35 goto 16 else 17
.17:
	 t38 = typeassert,ok arg.(*int16)
	 t39 = extract t38 #0
	 t40 = extract t38 #1
	 if t40 goto 18 else 19
.19:
	 t43 = typeassert,ok arg.(*int32)
	 t44 = extract t43 #0
	 t45 = extract t43 #1
	 if t45 goto 20 else 21
.21:
	 t48 = typeassert,ok arg.(*int64)
	 t49 = extract t48 #0
	 t50 = extract t48 #1
	 if t50 goto 22 else 23
.23:
	 t52 = typeassert,ok arg.(*uint)
	 t53 = extract t52 #0
	 t54 = extract t52 #1
	 if t54 goto 24 else 25
.25:
	 t57 = typeassert,ok arg.(*uint8)
	 t58 = extract t57 #0
	 t59 = extract t57 #1
	 if t59 goto 26 else 27
.27:
	 t62 = typeassert,ok arg.(*uint16)
	 t63 = extract t62 #0
	 t64 = extract t62 #1
	 if t64 goto 28 else 29
.29:
	 t67 = typeassert,ok arg.(*uint32)
	 t68 = extract t67 #0
	 t69 = extract t67 #1
	 if t69 goto 30 else 31
.31:
	 t72 = typeassert,ok arg.(*uint64)
	 t73 = extract t72 #0
	 t74 = extract t72 #1
	 if t74 goto 32 else 33
.33:
	 t76 = typeassert,ok arg.(*uintptr)
	 t77 = extract t76 #0
	 t78 = extract t76 #1
	 if t78 goto 34 else 35
.35:
	 t81 = typeassert,ok arg.(*float32)
	 t82 = extract t81 #0
	 t83 = extract t81 #1
	 if t83 goto 36 else 37
.37:
	 t85 = typeassert,ok arg.(*float64)
	 t86 = extract t85 #0
	 t87 = extract t85 #1
	 if t87 goto 39 else 40
.40:
	 t94 = typeassert,ok arg.(*string)
	 t95 = extract t94 #0
	 t96 = extract t94 #1
	 if t96 goto 42 else 43
.42:
	 t101 = (*ss).convertString(s, verb)
Entering (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:808:14.
.0:
	 t0 = (*ss).okVerb(s, verb, "svqxX":string, "string":string)
Entering (*fmt.ss).okVerb at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:528:14.
.0:
	 t0 = range okVerbs
	 jump 1
.1:
	 t1 = next t0
	 t2 = extract t1 #0
	 if t2 goto 2 else 3
.2:
	 t3 = extract t1 #2
	 t4 = t3 == verb
	 if t4 goto 4 else 1
.4:
	 return true:bool
Leaving (*fmt.ss).okVerb, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:809:14.
	 if t0 goto 2 else 1
.2:
	 t1 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:812:13.
	 t2 = (*ss).notEOF(s)
Entering (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:513:14.
.0:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:515:19.
	 t1 = t0 == -1:rune
	 if t1 goto 1 else 2
.2:
	 t4 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:518:14.
	 return
Leaving (*fmt.ss).notEOF, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:813:10.
	 t3 = verb == 113:rune
	 if t3 goto 4 else 6
.6:
	 t7 = verb == 120:rune
	 if t7 goto 5 else 7
.7:
	 t8 = verb == 88:rune
	 if t8 goto 5 else 8
.8:
	 t9 = (*ss).token(s, true:bool, notSpace)
Entering (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:454:14.
.0:
	 if skipSpace goto 1 else 2
.1:
	 t0 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:456:14.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.6:
	 t8 = &s.buf [#1]
	 t9 = (*buffer).WriteRune(t8, t1)
Entering (*fmt.buffer).WriteRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:89:19.
.0:
	 t0 = r < 128:rune
	 if t0 goto 1 else 2
.1:
	 t1 = *bp
	 t2 = convert byte <- rune (r)
	 t3 = new [1]byte (varargs)
	 t4 = &t3[0:int]
	 *t4 = t2
	 t5 = slice t3[:]
	 t6 = append(t1, t5...)
	 *bp = t6
	 return
Leaving (*fmt.buffer).WriteRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:468:18.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.6:
	 t8 = &s.buf [#1]
	 t9 = (*buffer).WriteRune(t8, t1)
Entering (*fmt.buffer).WriteRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:89:19.
.0:
	 t0 = r < 128:rune
	 if t0 goto 1 else 2
.1:
	 t1 = *bp
	 t2 = convert byte <- rune (r)
	 t3 = new [1]byte (varargs)
	 t4 = &t3[0:int]
	 *t4 = t2
	 t5 = slice t3[:]
	 t6 = append(t1, t5...)
	 *bp = t6
	 return
Leaving (*fmt.buffer).WriteRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:468:18.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.6:
	 t8 = &s.buf [#1]
	 t9 = (*buffer).WriteRune(t8, t1)
Entering (*fmt.buffer).WriteRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:89:19.
.0:
	 t0 = r < 128:rune
	 if t0 goto 1 else 2
.1:
	 t1 = *bp
	 t2 = convert byte <- rune (r)
	 t3 = new [1]byte (varargs)
	 t4 = &t3[0:int]
	 *t4 = t2
	 t5 = slice t3[:]
	 t6 = append(t1, t5...)
	 *bp = t6
	 return
Leaving (*fmt.buffer).WriteRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:468:18.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.6:
	 t8 = &s.buf [#1]
	 t9 = (*buffer).WriteRune(t8, t1)
Entering (*fmt.buffer).WriteRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:89:19.
.0:
	 t0 = r < 128:rune
	 if t0 goto 1 else 2
.1:
	 t1 = *bp
	 t2 = convert byte <- rune (r)
	 t3 = new [1]byte (varargs)
	 t4 = &t3[0:int]
	 *t4 = t2
	 t5 = slice t3[:]
	 t6 = append(t1, t5...)
	 *bp = t6
	 return
Leaving (*fmt.buffer).WriteRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:468:18.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.8:
	 return true:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.5:
	 t7 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:465:16.
	 jump 3
.3:
	 t3 = &s.buf [#1]
	 t4 = *t3
	 t5 = changetype []byte <- buffer (t4)
	 return t5
Leaving (*fmt.ss).token, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:820:23.
	 t10 = convert string <- []byte (t9)
	 jump 3
.3:
	 t4 = phi [4: t5, 5: t6, 8: t10] #str
	 return t4
Leaving (*fmt.ss).convertString, resuming (*fmt.ss).scanOne at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:987:23.
	 *t95 = t101
	 jump 7
.7:
	 return
Leaving (*fmt.ss).scanOne, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1201:12.
	 t64 = *t0
	 t65 = t64 + 1:int
	 *t0 = t65
	 t66 = &s.ssave [#4]
	 t67 = &t66.argLimit [#3]
	 t68 = &s.ssave [#4]
	 t69 = &t68.limit [#4]
	 t70 = *t69
	 *t67 = t70
	 jump 4
.4:
	 t12 = phi [0: 0:int, 5: t14, 17: t32] #i
	 t13 = t12 <= t3
	 if t13 goto 2 else 3
.3:
	 t9 = *t0
	 t10 = len(a)
	 t11 = t9 < t10
	 if t11 goto 18 else 19
.19:
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1157:2: invoking deferred function call
Entering fmt.errorHandler at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1032:6.
.0:
	 t0 = recover()
	 t1 = t0 != nil:interface{}
	 if t1 goto 1 else 2
.2:
	 return
Leaving fmt.errorHandler, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1157:2.
	 t72 = *t0
	 t73 = *t1
	 return t72, t73
Leaving (*fmt.ss).doScanf, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:143:20.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = *t0
	 t8 = (*ss).free(t2, t7)
Entering (*fmt.ss).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:409:14.
.0:
	 t0 = local ssave (old)
	 *t0 = old
	 t1 = &t0.validSave [#0]
	 t2 = *t1
	 if t2 goto 1 else 2
.2:
	 t5 = &s.buf [#1]
	 t6 = *t5
	 t7 = changetype []byte <- buffer (t6)
	 t8 = cap(t7)
	 t9 = t8 > 1024:int
	 if t9 goto 3 else 4
.4:
	 t10 = &s.buf [#1]
	 t11 = &s.buf [#1]
	 t12 = *t11
	 t13 = slice t12[:0:int]
	 *t10 = t13
	 t14 = &s.rs [#0]
	 *t14 = nil:io.RuneScanner
	 t15 = make interface{} <- *ss (s)
	 t16 = (*sync.Pool).Put(ssFree, t15)
Entering (*sync.Pool).Put at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:88:16.
	(external)
Leaving (*sync.Pool).Put, resuming (*fmt.ss).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:421:12.
	 return
Leaving (*fmt.ss).free, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:144:8.
	 return t5, t6
Leaving fmt.Fscanf, resuming fmt.Scanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:81:15.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 return t3, t4
Leaving fmt.Scanf, resuming main.main at /tmp/gogo.go:193:14.
	 t13 = new [1]interface{} (varargs)
	 t14 = &t13[0:int]
	 t15 = make interface{} <- *string (t1)
	 *t14 = t15
	 t16 = slice t13[:]
	 t17 = fmt.Scanf("%s":string, t16...)
Entering fmt.Scanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:80:6.
.0:
	 t0 = *os.Stdin
	 t1 = make io.Reader <- *os.File (t0)
	 t2 = Fscanf(t1, format, a...)
Entering fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:141:6.
.0:
	 t0 = local ssave (old)
	 t1 = newScanState(r, false:bool, false:bool)
Entering fmt.newScanState at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:390:6.
.0:
	 t0 = local ssave (old)
	 t1 = (*sync.Pool).Get(ssFree)
Entering (*sync.Pool).Get at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:124:16.
	(external)
Entering fmt.init$2 at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:386:7.
.0:
	 t0 = new ss (new)
	 t1 = make interface{} <- *ss (t0)
	 return t1
Leaving fmt.init$2, resuming (*sync.Pool).Get.
Leaving (*sync.Pool).Get, resuming fmt.newScanState at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:391:16.
	 t2 = typeassert t1.(*ss)
	 t3 = typeassert,ok r.(io.RuneScanner)
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 if t5 goto 1 else 3
.3:
	 t22 = &t2.rs [#0]
	 t23 = new readRune (complit)
	 t24 = &t23.reader [#0]
	 t25 = &t23.peekRune [#4]
	 *t24 = r
	 *t25 = -1:rune
	 t26 = make io.RuneScanner <- *readRune (t23)
	 *t22 = t26
	 jump 2
.2:
	 t7 = &t2.ssave [#4]
	 t8 = &t7.nlIsSpace [#2]
	 *t8 = nlIsSpace
	 t9 = &t2.ssave [#4]
	 t10 = &t9.nlIsEnd [#1]
	 *t10 = nlIsEnd
	 t11 = &t2.atEOF [#3]
	 *t11 = false:bool
	 t12 = &t2.ssave [#4]
	 t13 = &t12.limit [#4]
	 *t13 = 1073741824:int
	 t14 = &t2.ssave [#4]
	 t15 = &t14.argLimit [#3]
	 *t15 = 1073741824:int
	 t16 = &t2.ssave [#4]
	 t17 = &t16.maxWid [#5]
	 *t17 = 1073741824:int
	 t18 = &t2.ssave [#4]
	 t19 = &t18.validSave [#0]
	 *t19 = true:bool
	 t20 = &t2.count [#2]
	 *t20 = 0:int
	 t21 = *t0
	 return t2, t21
Leaving fmt.newScanState, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:142:24.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 *t0 = t3
	 t4 = (*ss).doScanf(t2, format, a)
Entering (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1156:14.
.0:
	 t0 = local int (numProcessed)
	 t1 = new error (err)
	 defer errorHandler(t1)
	 t2 = len(format)
	 t3 = t2 - 1:int
	 jump 4
.4:
	 t12 = phi [0: 0:int, 5: t14, 17: t32] #i
	 t13 = t12 <= t3
	 if t13 goto 2 else 3
.2:
	 t6 = slice format[t12:]
	 t7 = (*ss).advance(s, t6)
Entering (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1075:14.
.0:
	 jump 3
.3:
	 t5 = phi [0: 0:int, 14: t10, 41: t65, 30: t10, 33: t10] #i
	 t6 = len(format)
	 t7 = t5 < t6
	 if t7 goto 1 else 2
.1:
	 t0 = slice format[t5:]
	 t1 = unicode/utf8.DecodeRuneInString(t0)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1077:37.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 t4 = isSpace(t2)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1085:13.
	 if t4 goto 4 else 5
.5:
	 t8 = t2 == 37:rune
	 if t8 goto 34 else 35
.34:
	 t50 = t5 + t3
	 t51 = len(format)
	 t52 = t50 == t51
	 if t52 goto 36 else 37
.37:
	 t57 = t5 + t3
	 t58 = slice format[t57:]
	 t59 = unicode/utf8.DecodeRuneInString(t58)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1136:39.
	 t60 = extract t59 #0
	 t61 = extract t59 #1
	 t62 = t60 != 37:rune
	 if t62 goto 38 else 39
.38:
	 return t5
Leaving (*fmt.ss).advance, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1161:17.
	 t8 = t7 > 0:int
	 if t8 goto 5 else 6
.6:
	 t15 = format[t12]
	 t16 = t15 != 37:byte
	 if t16 goto 7 else 8
.8:
	 t18 = t12 + 1:int
	 t19 = &s.ssave [#4]
	 t20 = &t19.maxWid [#5]
	 t21 = parsenum(format, t18, t3)
Entering fmt.parsenum at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:289:6.
.0:
	 t0 = start >= end
	 if t0 goto 1 else 2
.1:
	 return 0:int, false:bool, end
Leaving fmt.parsenum, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1179:37.
	 t22 = extract t21 #0
	 *t20 = t22
	 t23 = extract t21 #1
	 t24 = extract t21 #2
	 if t23 goto 11 else 10
.10:
	 t26 = &s.ssave [#4]
	 t27 = &t26.maxWid [#5]
	 *t27 = 1073741824:int
	 jump 11
.11:
	 t28 = slice format[t24:]
	 t29 = unicode/utf8.DecodeRuneInString(t28)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1184:34.
	 t30 = extract t29 #0
	 t31 = extract t29 #1
	 t32 = t24 + t31
	 t33 = t30 != 99:rune
	 if t33 goto 12 else 13
.12:
	 t34 = (*ss).SkipSpace(s)
Entering (*fmt.ss).SkipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:304:14.
.0:
	 t0 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).SkipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:305:13.
	 return
Leaving (*fmt.ss).SkipSpace, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1188:15.
	 jump 13
.13:
	 t35 = &s.ssave [#4]
	 t36 = &t35.argLimit [#3]
	 t37 = &s.ssave [#4]
	 t38 = &t37.limit [#4]
	 t39 = *t38
	 *t36 = t39
	 t40 = &s.count [#2]
	 t41 = *t40
	 t42 = &s.ssave [#4]
	 t43 = &t42.maxWid [#5]
	 t44 = *t43
	 t45 = t41 + t44
	 t46 = &s.ssave [#4]
	 t47 = &t46.argLimit [#3]
	 t48 = *t47
	 t49 = t45 < t48
	 if t49 goto 14 else 15
.15:
	 t52 = *t0
	 t53 = len(a)
	 t54 = t52 >= t53
	 if t54 goto 16 else 17
.17:
	 t60 = *t0
	 t61 = &a[t60]
	 t62 = *t61
	 t63 = (*ss).scanOne(s, t30, t62)
Entering (*fmt.ss).scanOne at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:928:14.
.0:
	 t0 = &s.buf [#1]
	 t1 = &s.buf [#1]
	 t2 = *t1
	 t3 = slice t2[:0:int]
	 *t0 = t3
	 t4 = typeassert,ok arg.(Scanner)
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 if t6 goto 1 else 2
.2:
	 t10 = typeassert,ok arg.(*bool)
	 t11 = extract t10 #0
	 t12 = extract t10 #1
	 if t12 goto 8 else 9
.9:
	 t19 = typeassert,ok arg.(*complex64)
	 t20 = extract t19 #0
	 t21 = extract t19 #1
	 if t21 goto 10 else 11
.11:
	 t24 = typeassert,ok arg.(*complex128)
	 t25 = extract t24 #0
	 t26 = extract t24 #1
	 if t26 goto 12 else 13
.13:
	 t28 = typeassert,ok arg.(*int)
	 t29 = extract t28 #0
	 t30 = extract t28 #1
	 if t30 goto 14 else 15
.15:
	 t33 = typeassert,ok arg.(*int8)
	 t34 = extract t33 #0
	 t35 = extract t33 #1
	 if t35 goto 16 else 17
.17:
	 t38 = typeassert,ok arg.(*int16)
	 t39 = extract t38 #0
	 t40 = extract t38 #1
	 if t40 goto 18 else 19
.19:
	 t43 = typeassert,ok arg.(*int32)
	 t44 = extract t43 #0
	 t45 = extract t43 #1
	 if t45 goto 20 else 21
.21:
	 t48 = typeassert,ok arg.(*int64)
	 t49 = extract t48 #0
	 t50 = extract t48 #1
	 if t50 goto 22 else 23
.23:
	 t52 = typeassert,ok arg.(*uint)
	 t53 = extract t52 #0
	 t54 = extract t52 #1
	 if t54 goto 24 else 25
.25:
	 t57 = typeassert,ok arg.(*uint8)
	 t58 = extract t57 #0
	 t59 = extract t57 #1
	 if t59 goto 26 else 27
.27:
	 t62 = typeassert,ok arg.(*uint16)
	 t63 = extract t62 #0
	 t64 = extract t62 #1
	 if t64 goto 28 else 29
.29:
	 t67 = typeassert,ok arg.(*uint32)
	 t68 = extract t67 #0
	 t69 = extract t67 #1
	 if t69 goto 30 else 31
.31:
	 t72 = typeassert,ok arg.(*uint64)
	 t73 = extract t72 #0
	 t74 = extract t72 #1
	 if t74 goto 32 else 33
.33:
	 t76 = typeassert,ok arg.(*uintptr)
	 t77 = extract t76 #0
	 t78 = extract t76 #1
	 if t78 goto 34 else 35
.35:
	 t81 = typeassert,ok arg.(*float32)
	 t82 = extract t81 #0
	 t83 = extract t81 #1
	 if t83 goto 36 else 37
.37:
	 t85 = typeassert,ok arg.(*float64)
	 t86 = extract t85 #0
	 t87 = extract t85 #1
	 if t87 goto 39 else 40
.40:
	 t94 = typeassert,ok arg.(*string)
	 t95 = extract t94 #0
	 t96 = extract t94 #1
	 if t96 goto 42 else 43
.42:
	 t101 = (*ss).convertString(s, verb)
Entering (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:808:14.
.0:
	 t0 = (*ss).okVerb(s, verb, "svqxX":string, "string":string)
Entering (*fmt.ss).okVerb at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:528:14.
.0:
	 t0 = range okVerbs
	 jump 1
.1:
	 t1 = next t0
	 t2 = extract t1 #0
	 if t2 goto 2 else 3
.2:
	 t3 = extract t1 #2
	 t4 = t3 == verb
	 if t4 goto 4 else 1
.4:
	 return true:bool
Leaving (*fmt.ss).okVerb, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:809:14.
	 if t0 goto 2 else 1
.2:
	 t1 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:812:13.
	 t2 = (*ss).notEOF(s)
Entering (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:513:14.
.0:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:515:19.
	 t1 = t0 == -1:rune
	 if t1 goto 1 else 2
.2:
	 t4 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:518:14.
	 return
Leaving (*fmt.ss).notEOF, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:813:10.
	 t3 = verb == 113:rune
	 if t3 goto 4 else 6
.6:
	 t7 = verb == 120:rune
	 if t7 goto 5 else 7
.7:
	 t8 = verb == 88:rune
	 if t8 goto 5 else 8
.8:
	 t9 = (*ss).token(s, true:bool, notSpace)
Entering (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:454:14.
.0:
	 if skipSpace goto 1 else 2
.1:
	 t0 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:456:14.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.6:
	 t8 = &s.buf [#1]
	 t9 = (*buffer).WriteRune(t8, t1)
Entering (*fmt.buffer).WriteRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:89:19.
.0:
	 t0 = r < 128:rune
	 if t0 goto 1 else 2
.1:
	 t1 = *bp
	 t2 = convert byte <- rune (r)
	 t3 = new [1]byte (varargs)
	 t4 = &t3[0:int]
	 *t4 = t2
	 t5 = slice t3[:]
	 t6 = append(t1, t5...)
	 *bp = t6
	 return
Leaving (*fmt.buffer).WriteRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:468:18.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.8:
	 return true:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.5:
	 t7 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:465:16.
	 jump 3
.3:
	 t3 = &s.buf [#1]
	 t4 = *t3
	 t5 = changetype []byte <- buffer (t4)
	 return t5
Leaving (*fmt.ss).token, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:820:23.
	 t10 = convert string <- []byte (t9)
	 jump 3
.3:
	 t4 = phi [4: t5, 5: t6, 8: t10] #str
	 return t4
Leaving (*fmt.ss).convertString, resuming (*fmt.ss).scanOne at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:987:23.
	 *t95 = t101
	 jump 7
.7:
	 return
Leaving (*fmt.ss).scanOne, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1201:12.
	 t64 = *t0
	 t65 = t64 + 1:int
	 *t0 = t65
	 t66 = &s.ssave [#4]
	 t67 = &t66.argLimit [#3]
	 t68 = &s.ssave [#4]
	 t69 = &t68.limit [#4]
	 t70 = *t69
	 *t67 = t70
	 jump 4
.4:
	 t12 = phi [0: 0:int, 5: t14, 17: t32] #i
	 t13 = t12 <= t3
	 if t13 goto 2 else 3
.3:
	 t9 = *t0
	 t10 = len(a)
	 t11 = t9 < t10
	 if t11 goto 18 else 19
.19:
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1157:2: invoking deferred function call
Entering fmt.errorHandler at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1032:6.
.0:
	 t0 = recover()
	 t1 = t0 != nil:interface{}
	 if t1 goto 1 else 2
.2:
	 return
Leaving fmt.errorHandler, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1157:2.
	 t72 = *t0
	 t73 = *t1
	 return t72, t73
Leaving (*fmt.ss).doScanf, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:143:20.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = *t0
	 t8 = (*ss).free(t2, t7)
Entering (*fmt.ss).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:409:14.
.0:
	 t0 = local ssave (old)
	 *t0 = old
	 t1 = &t0.validSave [#0]
	 t2 = *t1
	 if t2 goto 1 else 2
.2:
	 t5 = &s.buf [#1]
	 t6 = *t5
	 t7 = changetype []byte <- buffer (t6)
	 t8 = cap(t7)
	 t9 = t8 > 1024:int
	 if t9 goto 3 else 4
.4:
	 t10 = &s.buf [#1]
	 t11 = &s.buf [#1]
	 t12 = *t11
	 t13 = slice t12[:0:int]
	 *t10 = t13
	 t14 = &s.rs [#0]
	 *t14 = nil:io.RuneScanner
	 t15 = make interface{} <- *ss (s)
	 t16 = (*sync.Pool).Put(ssFree, t15)
Entering (*sync.Pool).Put at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:88:16.
	(external)
Leaving (*sync.Pool).Put, resuming (*fmt.ss).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:421:12.
	 return
Leaving (*fmt.ss).free, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:144:8.
	 return t5, t6
Leaving fmt.Fscanf, resuming fmt.Scanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:81:15.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 return t3, t4
Leaving fmt.Scanf, resuming main.main at /tmp/gogo.go:194:14.
	 t18 = new [1]interface{} (varargs)
	 t19 = &t18[0:int]
	 t20 = make interface{} <- *string (t2)
	 *t19 = t20
	 t21 = slice t18[:]
	 t22 = fmt.Scanf("%s":string, t21...)
Entering fmt.Scanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:80:6.
.0:
	 t0 = *os.Stdin
	 t1 = make io.Reader <- *os.File (t0)
	 t2 = Fscanf(t1, format, a...)
Entering fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:141:6.
.0:
	 t0 = local ssave (old)
	 t1 = newScanState(r, false:bool, false:bool)
Entering fmt.newScanState at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:390:6.
.0:
	 t0 = local ssave (old)
	 t1 = (*sync.Pool).Get(ssFree)
Entering (*sync.Pool).Get at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:124:16.
	(external)
Entering fmt.init$2 at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:386:7.
.0:
	 t0 = new ss (new)
	 t1 = make interface{} <- *ss (t0)
	 return t1
Leaving fmt.init$2, resuming (*sync.Pool).Get.
Leaving (*sync.Pool).Get, resuming fmt.newScanState at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:391:16.
	 t2 = typeassert t1.(*ss)
	 t3 = typeassert,ok r.(io.RuneScanner)
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 if t5 goto 1 else 3
.3:
	 t22 = &t2.rs [#0]
	 t23 = new readRune (complit)
	 t24 = &t23.reader [#0]
	 t25 = &t23.peekRune [#4]
	 *t24 = r
	 *t25 = -1:rune
	 t26 = make io.RuneScanner <- *readRune (t23)
	 *t22 = t26
	 jump 2
.2:
	 t7 = &t2.ssave [#4]
	 t8 = &t7.nlIsSpace [#2]
	 *t8 = nlIsSpace
	 t9 = &t2.ssave [#4]
	 t10 = &t9.nlIsEnd [#1]
	 *t10 = nlIsEnd
	 t11 = &t2.atEOF [#3]
	 *t11 = false:bool
	 t12 = &t2.ssave [#4]
	 t13 = &t12.limit [#4]
	 *t13 = 1073741824:int
	 t14 = &t2.ssave [#4]
	 t15 = &t14.argLimit [#3]
	 *t15 = 1073741824:int
	 t16 = &t2.ssave [#4]
	 t17 = &t16.maxWid [#5]
	 *t17 = 1073741824:int
	 t18 = &t2.ssave [#4]
	 t19 = &t18.validSave [#0]
	 *t19 = true:bool
	 t20 = &t2.count [#2]
	 *t20 = 0:int
	 t21 = *t0
	 return t2, t21
Leaving fmt.newScanState, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:142:24.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 *t0 = t3
	 t4 = (*ss).doScanf(t2, format, a)
Entering (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1156:14.
.0:
	 t0 = local int (numProcessed)
	 t1 = new error (err)
	 defer errorHandler(t1)
	 t2 = len(format)
	 t3 = t2 - 1:int
	 jump 4
.4:
	 t12 = phi [0: 0:int, 5: t14, 17: t32] #i
	 t13 = t12 <= t3
	 if t13 goto 2 else 3
.2:
	 t6 = slice format[t12:]
	 t7 = (*ss).advance(s, t6)
Entering (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1075:14.
.0:
	 jump 3
.3:
	 t5 = phi [0: 0:int, 14: t10, 41: t65, 30: t10, 33: t10] #i
	 t6 = len(format)
	 t7 = t5 < t6
	 if t7 goto 1 else 2
.1:
	 t0 = slice format[t5:]
	 t1 = unicode/utf8.DecodeRuneInString(t0)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1077:37.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 t4 = isSpace(t2)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1085:13.
	 if t4 goto 4 else 5
.5:
	 t8 = t2 == 37:rune
	 if t8 goto 34 else 35
.34:
	 t50 = t5 + t3
	 t51 = len(format)
	 t52 = t50 == t51
	 if t52 goto 36 else 37
.37:
	 t57 = t5 + t3
	 t58 = slice format[t57:]
	 t59 = unicode/utf8.DecodeRuneInString(t58)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).advance at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1136:39.
	 t60 = extract t59 #0
	 t61 = extract t59 #1
	 t62 = t60 != 37:rune
	 if t62 goto 38 else 39
.38:
	 return t5
Leaving (*fmt.ss).advance, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1161:17.
	 t8 = t7 > 0:int
	 if t8 goto 5 else 6
.6:
	 t15 = format[t12]
	 t16 = t15 != 37:byte
	 if t16 goto 7 else 8
.8:
	 t18 = t12 + 1:int
	 t19 = &s.ssave [#4]
	 t20 = &t19.maxWid [#5]
	 t21 = parsenum(format, t18, t3)
Entering fmt.parsenum at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:289:6.
.0:
	 t0 = start >= end
	 if t0 goto 1 else 2
.1:
	 return 0:int, false:bool, end
Leaving fmt.parsenum, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1179:37.
	 t22 = extract t21 #0
	 *t20 = t22
	 t23 = extract t21 #1
	 t24 = extract t21 #2
	 if t23 goto 11 else 10
.10:
	 t26 = &s.ssave [#4]
	 t27 = &t26.maxWid [#5]
	 *t27 = 1073741824:int
	 jump 11
.11:
	 t28 = slice format[t24:]
	 t29 = unicode/utf8.DecodeRuneInString(t28)
Entering unicode/utf8.DecodeRuneInString at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:201:6.
.0:
	 t0 = len(s)
	 t1 = t0 < 1:int
	 if t1 goto 1 else 2
.2:
	 t2 = s[0:int]
	 t3 = convert int <- uint8 (t2)
	 t4 = &first[t3]
	 t5 = *t4
	 t6 = t5 >= 240:uint8
	 if t6 goto 3 else 4
.3:
	 t7 = convert rune <- uint8 (t5)
	 t8 = t7 << 31:uint
	 t9 = t8 >> 31:uint
	 t10 = s[0:int]
	 t11 = convert rune <- uint8 (t10)
	 t12 = t11 &^ t9
	 t13 = 65533:rune & t9
	 t14 = t12 | t13
	 return t14, 1:int
Leaving unicode/utf8.DecodeRuneInString, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1184:34.
	 t30 = extract t29 #0
	 t31 = extract t29 #1
	 t32 = t24 + t31
	 t33 = t30 != 99:rune
	 if t33 goto 12 else 13
.12:
	 t34 = (*ss).SkipSpace(s)
Entering (*fmt.ss).SkipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:304:14.
.0:
	 t0 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).SkipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:305:13.
	 return
Leaving (*fmt.ss).SkipSpace, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1188:15.
	 jump 13
.13:
	 t35 = &s.ssave [#4]
	 t36 = &t35.argLimit [#3]
	 t37 = &s.ssave [#4]
	 t38 = &t37.limit [#4]
	 t39 = *t38
	 *t36 = t39
	 t40 = &s.count [#2]
	 t41 = *t40
	 t42 = &s.ssave [#4]
	 t43 = &t42.maxWid [#5]
	 t44 = *t43
	 t45 = t41 + t44
	 t46 = &s.ssave [#4]
	 t47 = &t46.argLimit [#3]
	 t48 = *t47
	 t49 = t45 < t48
	 if t49 goto 14 else 15
.15:
	 t52 = *t0
	 t53 = len(a)
	 t54 = t52 >= t53
	 if t54 goto 16 else 17
.17:
	 t60 = *t0
	 t61 = &a[t60]
	 t62 = *t61
	 t63 = (*ss).scanOne(s, t30, t62)
Entering (*fmt.ss).scanOne at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:928:14.
.0:
	 t0 = &s.buf [#1]
	 t1 = &s.buf [#1]
	 t2 = *t1
	 t3 = slice t2[:0:int]
	 *t0 = t3
	 t4 = typeassert,ok arg.(Scanner)
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 if t6 goto 1 else 2
.2:
	 t10 = typeassert,ok arg.(*bool)
	 t11 = extract t10 #0
	 t12 = extract t10 #1
	 if t12 goto 8 else 9
.9:
	 t19 = typeassert,ok arg.(*complex64)
	 t20 = extract t19 #0
	 t21 = extract t19 #1
	 if t21 goto 10 else 11
.11:
	 t24 = typeassert,ok arg.(*complex128)
	 t25 = extract t24 #0
	 t26 = extract t24 #1
	 if t26 goto 12 else 13
.13:
	 t28 = typeassert,ok arg.(*int)
	 t29 = extract t28 #0
	 t30 = extract t28 #1
	 if t30 goto 14 else 15
.15:
	 t33 = typeassert,ok arg.(*int8)
	 t34 = extract t33 #0
	 t35 = extract t33 #1
	 if t35 goto 16 else 17
.17:
	 t38 = typeassert,ok arg.(*int16)
	 t39 = extract t38 #0
	 t40 = extract t38 #1
	 if t40 goto 18 else 19
.19:
	 t43 = typeassert,ok arg.(*int32)
	 t44 = extract t43 #0
	 t45 = extract t43 #1
	 if t45 goto 20 else 21
.21:
	 t48 = typeassert,ok arg.(*int64)
	 t49 = extract t48 #0
	 t50 = extract t48 #1
	 if t50 goto 22 else 23
.23:
	 t52 = typeassert,ok arg.(*uint)
	 t53 = extract t52 #0
	 t54 = extract t52 #1
	 if t54 goto 24 else 25
.25:
	 t57 = typeassert,ok arg.(*uint8)
	 t58 = extract t57 #0
	 t59 = extract t57 #1
	 if t59 goto 26 else 27
.27:
	 t62 = typeassert,ok arg.(*uint16)
	 t63 = extract t62 #0
	 t64 = extract t62 #1
	 if t64 goto 28 else 29
.29:
	 t67 = typeassert,ok arg.(*uint32)
	 t68 = extract t67 #0
	 t69 = extract t67 #1
	 if t69 goto 30 else 31
.31:
	 t72 = typeassert,ok arg.(*uint64)
	 t73 = extract t72 #0
	 t74 = extract t72 #1
	 if t74 goto 32 else 33
.33:
	 t76 = typeassert,ok arg.(*uintptr)
	 t77 = extract t76 #0
	 t78 = extract t76 #1
	 if t78 goto 34 else 35
.35:
	 t81 = typeassert,ok arg.(*float32)
	 t82 = extract t81 #0
	 t83 = extract t81 #1
	 if t83 goto 36 else 37
.37:
	 t85 = typeassert,ok arg.(*float64)
	 t86 = extract t85 #0
	 t87 = extract t85 #1
	 if t87 goto 39 else 40
.40:
	 t94 = typeassert,ok arg.(*string)
	 t95 = extract t94 #0
	 t96 = extract t94 #1
	 if t96 goto 42 else 43
.42:
	 t101 = (*ss).convertString(s, verb)
Entering (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:808:14.
.0:
	 t0 = (*ss).okVerb(s, verb, "svqxX":string, "string":string)
Entering (*fmt.ss).okVerb at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:528:14.
.0:
	 t0 = range okVerbs
	 jump 1
.1:
	 t1 = next t0
	 t2 = extract t1 #0
	 if t2 goto 2 else 3
.2:
	 t3 = extract t1 #2
	 t4 = t3 == verb
	 if t4 goto 4 else 1
.4:
	 return true:bool
Leaving (*fmt.ss).okVerb, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:809:14.
	 if t0 goto 2 else 1
.2:
	 t1 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:812:13.
	 t2 = (*ss).notEOF(s)
Entering (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:513:14.
.0:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:515:19.
	 t1 = t0 == -1:rune
	 if t1 goto 1 else 2
.2:
	 t4 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).notEOF at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:518:14.
	 return
Leaving (*fmt.ss).notEOF, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:813:10.
	 t3 = verb == 113:rune
	 if t3 goto 4 else 6
.6:
	 t7 = verb == 120:rune
	 if t7 goto 5 else 7
.7:
	 t8 = verb == 88:rune
	 if t8 goto 5 else 8
.8:
	 t9 = (*ss).token(s, true:bool, notSpace)
Entering (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:454:14.
.0:
	 if skipSpace goto 1 else 2
.1:
	 t0 = (*ss).skipSpace(s, false:bool)
Entering (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:425:14.
.0:
	 jump 1
.1:
	 t0 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:427:17.
	 t1 = t0 == -1:rune
	 if t1 goto 3 else 4
.4:
	 t2 = t0 == 13:rune
	 if t2 goto 6 else 5
.5:
	 t3 = t0 == 10:rune
	 if t3 goto 7 else 8
.8:
	 t5 = isSpace(t0)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:444:14.
	 if t5 goto 1 else 11
.11:
	 t10 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).skipSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:445:16.
	 jump 2
.2:
	 return
Leaving (*fmt.ss).skipSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:456:14.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.1:
	 t3 = &r.peekRune [#4]
	 t4 = *t3
	 t5 = &r.peekRune [#4]
	 t6 = &r.peekRune [#4]
	 t7 = *t6
	 t8 = ^t7
	 *t5 = t8
	 t9 = unicode/utf8.RuneLen(t4)
Entering unicode/utf8.RuneLen at /usr/local/Cellar/go/1.9.2/libexec/src/unicode/utf8/utf8.go:323:6.
.0:
	 t0 = r < 0:rune
	 if t0 goto 1 else 3
.3:
	 t1 = r <= 127:rune
	 if t1 goto 2 else 5
.2:
	 return 1:int
Leaving unicode/utf8.RuneLen, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:341:22.
	 return t4, t9, nil:error
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.6:
	 t8 = &s.buf [#1]
	 t9 = (*buffer).WriteRune(t8, t1)
Entering (*fmt.buffer).WriteRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:89:19.
.0:
	 t0 = r < 128:rune
	 if t0 goto 1 else 2
.1:
	 t1 = *bp
	 t2 = convert byte <- rune (r)
	 t3 = new [1]byte (varargs)
	 t4 = &t3[0:int]
	 *t4 = t2
	 t5 = slice t3[:]
	 t6 = append(t1, t5...)
	 *bp = t6
	 return
Leaving (*fmt.buffer).WriteRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:468:18.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.6:
	 return false:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.6:
	 t8 = &s.buf [#1]
	 t9 = (*buffer).WriteRune(t8, t1)
Entering (*fmt.buffer).WriteRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:89:19.
.0:
	 t0 = r < 128:rune
	 if t0 goto 1 else 2
.1:
	 t1 = *bp
	 t2 = convert byte <- rune (r)
	 t3 = new [1]byte (varargs)
	 t4 = &t3[0:int]
	 *t4 = t2
	 t5 = slice t3[:]
	 t6 = append(t1, t5...)
	 *bp = t6
	 return
Leaving (*fmt.buffer).WriteRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:468:18.
	 jump 2
.2:
	 t1 = (*ss).getRune(s)
Entering (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:210:14.
.0:
	 t0 = (*ss).ReadRune(s)
Entering (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:183:14.
.0:
	 t0 = &s.atEOF [#3]
	 t1 = *t0
	 if t1 goto 1 else 3
.3:
	 t10 = &s.count [#2]
	 t11 = *t10
	 t12 = &s.ssave [#4]
	 t13 = &t12.argLimit [#3]
	 t14 = *t13
	 t15 = t11 >= t14
	 if t15 goto 1 else 2
.2:
	 t3 = &s.rs [#0]
	 t4 = *t3
	 t5 = invoke t4.ReadRune()
Entering (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:337:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t10 = &r.buf [#1]
	 t11 = &t10[0:int]
	 t12 = (*readRune).readByte(r)
Entering (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:321:20.
.0:
	 t0 = &r.pending [#2]
	 t1 = *t0
	 t2 = t1 > 0:int
	 if t2 goto 1 else 2
.2:
	 t14 = &r.reader [#0]
	 t15 = *t14
	 t16 = &r.pendBuf [#3]
	 t17 = slice t16[:1:int]
	 t18 = io.ReadFull(t15, t17)
Entering io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:326:6.
.0:
	 t0 = len(buf)
	 t1 = ReadAtLeast(r, buf, t0)
Entering io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:303:6.
.0:
	 t0 = len(buf)
	 t1 = t0 < min
	 if t1 goto 1 else 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.5:
	 t12 = t10 == nil:error
	 if t12 goto 2 else 3
.2:
	 t3 = slice buf[t9:]
	 t4 = invoke r.Read(t3)
Entering (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:99:16.
.0:
	 t0 = (*File).checkValid(f, "read":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:100:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).read(f, b)
Entering (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:215:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Read(t2, b)
Entering (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:102:15.
.0:
	 t0 = (*FD).readLock(fd)
Entering (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:218:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).readLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:219:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).readLock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:103:23.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).readUnlock(fd)
	 t2 = len(p)
	 t3 = t2 == 0:int
	 if t3 goto 4 else 5
.5:
	 t4 = &fd.pd [#2]
	 t5 = &fd.isFile [#6]
	 t6 = *t5
	 t7 = (*pollDesc).prepareRead(t4, t6)
Entering (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:73:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 114:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareRead at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:74:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareRead, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:115:29.
	 t8 = t7 != nil:error
	 if t8 goto 6 else 7
.7:
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 10
.9:
	 t12 = len(p)
	 t13 = t12 > 1073741824:int
	 if t13 goto 8 else 10
.10:
	 t14 = phi [7: p, 13: t14, 9: p, 8: t11] #p
	 t15 = &fd.Sysfd [#1]
	 t16 = *t15
	 t17 = syscall.Read(t16, t14)
Entering syscall.Read at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:161:6.
	(external)
Leaving syscall.Read, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:122:25.
	 t18 = extract t17 #0
	 t19 = extract t17 #1
	 t20 = t19 != nil:error
	 if t20 goto 11 else 12
.12:
	 t23 = phi [10: t18, 11: 0:int, 14: 0:int, 13: 0:int] #n
	 t24 = phi [10: t19, 11: t19, 14: t19, 13: t29] #err
	 t25 = (*FD).eofError(fd, t23, t24)
Entering (*internal/poll.FD).eofError at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_posix.go:16:15.
.0:
	 t0 = n == 0:int
	 if t0 goto 4 else 2
.2:
	 return err
Leaving (*internal/poll.FD).eofError, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:131:20.
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2: invoking deferred function call
Entering (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:228:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, true:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.1:
	 t0 = &mu.rsema [#1]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).readUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:229:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).readUnlock, resuming (*internal/poll.FD).Read at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:106:2.
	 return t23, t25
Leaving (*internal/poll.FD).Read, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:216:21.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:217:19.
	 return t4, t5
Leaving (*os.File).read, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:103:16.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = (*File).wrapErr(f, "read":string, t4)
Entering (*os.File).wrapErr at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:273:16.
.0:
	 t0 = err == nil:error
	 if t0 goto 1 else 3
.1:
	 return err
Leaving (*os.File).wrapErr, resuming (*os.File).Read at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:104:21.
	 return t3, t5
Leaving (*os.File).Read, resuming io.ReadAtLeast at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:309:19.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = t9 + t5
	 jump 4
.4:
	 t9 = phi [0: 0:int, 2: t7] #n
	 t10 = phi [0: nil:error, 2: t6] #err
	 t11 = t9 < min
	 if t11 goto 5 else 3
.3:
	 t8 = t9 >= min
	 if t8 goto 6 else 8
.6:
	 jump 7
.7:
	 t13 = phi [6: nil:error, 8: t10, 10: t10, 9: t15] #err
	 return t9, t13
Leaving io.ReadAtLeast, resuming io.ReadFull at /usr/local/Cellar/go/1.9.2/libexec/src/io/io.go:327:20.
	 t2 = extract t1 #0
	 t3 = extract t1 #1
	 return t2, t3
Leaving io.ReadFull, resuming (*fmt.readRune).readByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:328:23.
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 t21 = t19 != 1:int
	 if t21 goto 3 else 4
.4:
	 t22 = &r.pendBuf [#3]
	 t23 = &t22[0:int]
	 t24 = *t23
	 return t24, t20
Leaving (*fmt.readRune).readByte, resuming (*fmt.readRune).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:344:28.
	 t13 = extract t12 #0
	 *t11 = t13
	 t14 = extract t12 #1
	 t15 = t14 != nil:error
	 if t15 goto 3 else 4
.4:
	 t16 = &r.buf [#1]
	 t17 = &t16[0:int]
	 t18 = *t17
	 t19 = t18 < 128:byte
	 if t19 goto 5 else 6
.5:
	 t20 = &r.buf [#1]
	 t21 = &t20[0:int]
	 t22 = *t21
	 t23 = convert rune <- byte (t22)
	 t24 = &r.peekRune [#4]
	 t25 = ^t23
	 *t24 = t25
	 return t23, 1:int, t14
Leaving (*fmt.readRune).ReadRune, resuming (*fmt.ss).ReadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:189:30.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = extract t5 #2
	 t9 = t8 == nil:error
	 if t9 goto 4 else 6
.4:
	 t16 = &s.count [#2]
	 t17 = *t16
	 t18 = t17 + 1:int
	 *t16 = t18
	 t19 = &s.ssave [#4]
	 t20 = &t19.nlIsEnd [#1]
	 t21 = *t20
	 if t21 goto 8 else 5
.5:
	 return t6, t7, t8
Leaving (*fmt.ss).ReadRune, resuming (*fmt.ss).getRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:211:25.
	 t1 = extract t0 #0
	 t2 = extract t0 #1
	 t3 = extract t0 #2
	 t4 = t3 != nil:error
	 if t4 goto 1 else 2
.2:
	 return t1
Leaving (*fmt.ss).getRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:460:17.
	 t2 = t1 == -1:rune
	 if t2 goto 3 else 4
.4:
	 t6 = f(t1)
Entering fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:297:6.
.0:
	 t0 = isSpace(r)
Entering fmt.isSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:280:6.
.0:
	 t0 = r >= 65536:rune
	 if t0 goto 1 else 2
.2:
	 t1 = convert uint16 <- rune (r)
	 t2 = local [2]uint16 (rng)
	 t3 = *space
	 t4 = len(t3)
	 jump 3
.3:
	 t5 = phi [2: -1:int, 7: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 4 else 5
.4:
	 t8 = &t3[t6]
	 t9 = *t8
	 *t2 = t9
	 t10 = &t2[0:int]
	 t11 = *t10
	 t12 = t1 < t11
	 if t12 goto 6 else 7
.7:
	 t13 = &t2[1:int]
	 t14 = *t13
	 t15 = t1 <= t14
	 if t15 goto 8 else 3
.8:
	 return true:bool
Leaving fmt.isSpace, resuming fmt.notSpace at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:298:17.
	 t1 = !t0
	 return t1
Leaving fmt.notSpace, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:464:8.
	 if t6 goto 6 else 5
.5:
	 t7 = (*ss).UnreadRune(s)
Entering (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:232:14.
.0:
	 t0 = &s.rs [#0]
	 t1 = *t0
	 t2 = invoke t1.UnreadRune()
Entering (*fmt.readRune).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:376:20.
.0:
	 t0 = &r.peekRune [#4]
	 t1 = *t0
	 t2 = t1 >= 0:rune
	 if t2 goto 1 else 2
.2:
	 t4 = &r.peekRune [#4]
	 t5 = &r.peekRune [#4]
	 t6 = *t5
	 t7 = ^t6
	 *t4 = t7
	 return nil:error
Leaving (*fmt.readRune).UnreadRune, resuming (*fmt.ss).UnreadRune at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:233:17.
	 t3 = &s.atEOF [#3]
	 *t3 = false:bool
	 t4 = &s.count [#2]
	 t5 = *t4
	 t6 = t5 - 1:int
	 *t4 = t6
	 return nil:error
Leaving (*fmt.ss).UnreadRune, resuming (*fmt.ss).token at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:465:16.
	 jump 3
.3:
	 t3 = &s.buf [#1]
	 t4 = *t3
	 t5 = changetype []byte <- buffer (t4)
	 return t5
Leaving (*fmt.ss).token, resuming (*fmt.ss).convertString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:820:23.
	 t10 = convert string <- []byte (t9)
	 jump 3
.3:
	 t4 = phi [4: t5, 5: t6, 8: t10] #str
	 return t4
Leaving (*fmt.ss).convertString, resuming (*fmt.ss).scanOne at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:987:23.
	 *t95 = t101
	 jump 7
.7:
	 return
Leaving (*fmt.ss).scanOne, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1201:12.
	 t64 = *t0
	 t65 = t64 + 1:int
	 *t0 = t65
	 t66 = &s.ssave [#4]
	 t67 = &t66.argLimit [#3]
	 t68 = &s.ssave [#4]
	 t69 = &t68.limit [#4]
	 t70 = *t69
	 *t67 = t70
	 jump 4
.4:
	 t12 = phi [0: 0:int, 5: t14, 17: t32] #i
	 t13 = t12 <= t3
	 if t13 goto 2 else 3
.3:
	 t9 = *t0
	 t10 = len(a)
	 t11 = t9 < t10
	 if t11 goto 18 else 19
.19:
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1157:2: invoking deferred function call
Entering fmt.errorHandler at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1032:6.
.0:
	 t0 = recover()
	 t1 = t0 != nil:interface{}
	 if t1 goto 1 else 2
.2:
	 return
Leaving fmt.errorHandler, resuming (*fmt.ss).doScanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:1157:2.
	 t72 = *t0
	 t73 = *t1
	 return t72, t73
Leaving (*fmt.ss).doScanf, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:143:20.
	 t5 = extract t4 #0
	 t6 = extract t4 #1
	 t7 = *t0
	 t8 = (*ss).free(t2, t7)
Entering (*fmt.ss).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:409:14.
.0:
	 t0 = local ssave (old)
	 *t0 = old
	 t1 = &t0.validSave [#0]
	 t2 = *t1
	 if t2 goto 1 else 2
.2:
	 t5 = &s.buf [#1]
	 t6 = *t5
	 t7 = changetype []byte <- buffer (t6)
	 t8 = cap(t7)
	 t9 = t8 > 1024:int
	 if t9 goto 3 else 4
.4:
	 t10 = &s.buf [#1]
	 t11 = &s.buf [#1]
	 t12 = *t11
	 t13 = slice t12[:0:int]
	 *t10 = t13
	 t14 = &s.rs [#0]
	 *t14 = nil:io.RuneScanner
	 t15 = make interface{} <- *ss (s)
	 t16 = (*sync.Pool).Put(ssFree, t15)
Entering (*sync.Pool).Put at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:88:16.
	(external)
Leaving (*sync.Pool).Put, resuming (*fmt.ss).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:421:12.
	 return
Leaving (*fmt.ss).free, resuming fmt.Fscanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:144:8.
	 return t5, t6
Leaving fmt.Fscanf, resuming fmt.Scanf at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/scan.go:81:15.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 return t3, t4
Leaving fmt.Scanf, resuming main.main at /tmp/gogo.go:195:14.
	 t23 = *t0
	 t24 = func6(t23)
Entering main.func6 at /tmp/gogo.go:141:6.
.0:
	 t0 = len(a)
	 t1 = make []int 0:int t0
	 t2 = len(a)
	 t3 = t2 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.1:
	 t4 = a[t9]
	 t5 = t4 - 48:byte
	 t6 = convert int <- byte (t5)
	 t7 = t6 >= 0:int
	 if t7 goto 6 else 5
.6:
	 t17 = t6 < 10:int
	 if t17 goto 4 else 5
.4:
	 t11 = new [1]int (varargs)
	 t12 = &t11[0:int]
	 *t12 = t6
	 t13 = slice t11[:]
	 t14 = append(t8, t13...)
	 jump 5
.5:
	 t15 = phi [1: t8, 6: t8, 4: t14] #rst
	 t16 = t9 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.1:
	 t4 = a[t9]
	 t5 = t4 - 48:byte
	 t6 = convert int <- byte (t5)
	 t7 = t6 >= 0:int
	 if t7 goto 6 else 5
.6:
	 t17 = t6 < 10:int
	 if t17 goto 4 else 5
.4:
	 t11 = new [1]int (varargs)
	 t12 = &t11[0:int]
	 *t12 = t6
	 t13 = slice t11[:]
	 t14 = append(t8, t13...)
	 jump 5
.5:
	 t15 = phi [1: t8, 6: t8, 4: t14] #rst
	 t16 = t9 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.1:
	 t4 = a[t9]
	 t5 = t4 - 48:byte
	 t6 = convert int <- byte (t5)
	 t7 = t6 >= 0:int
	 if t7 goto 6 else 5
.6:
	 t17 = t6 < 10:int
	 if t17 goto 4 else 5
.4:
	 t11 = new [1]int (varargs)
	 t12 = &t11[0:int]
	 *t12 = t6
	 t13 = slice t11[:]
	 t14 = append(t8, t13...)
	 jump 5
.5:
	 t15 = phi [1: t8, 6: t8, 4: t14] #rst
	 t16 = t9 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.1:
	 t4 = a[t9]
	 t5 = t4 - 48:byte
	 t6 = convert int <- byte (t5)
	 t7 = t6 >= 0:int
	 if t7 goto 6 else 5
.6:
	 t17 = t6 < 10:int
	 if t17 goto 4 else 5
.4:
	 t11 = new [1]int (varargs)
	 t12 = &t11[0:int]
	 *t12 = t6
	 t13 = slice t11[:]
	 t14 = append(t8, t13...)
	 jump 5
.5:
	 t15 = phi [1: t8, 6: t8, 4: t14] #rst
	 t16 = t9 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.2:
	 return t8
Leaving main.func6, resuming main.main at /tmp/gogo.go:197:15.
	 t25 = *t1
	 t26 = func6(t25)
Entering main.func6 at /tmp/gogo.go:141:6.
.0:
	 t0 = len(a)
	 t1 = make []int 0:int t0
	 t2 = len(a)
	 t3 = t2 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.1:
	 t4 = a[t9]
	 t5 = t4 - 48:byte
	 t6 = convert int <- byte (t5)
	 t7 = t6 >= 0:int
	 if t7 goto 6 else 5
.6:
	 t17 = t6 < 10:int
	 if t17 goto 4 else 5
.4:
	 t11 = new [1]int (varargs)
	 t12 = &t11[0:int]
	 *t12 = t6
	 t13 = slice t11[:]
	 t14 = append(t8, t13...)
	 jump 5
.5:
	 t15 = phi [1: t8, 6: t8, 4: t14] #rst
	 t16 = t9 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.2:
	 return t8
Leaving main.func6, resuming main.main at /tmp/gogo.go:198:15.
	 t27 = *t2
	 t28 = func6(t27)
Entering main.func6 at /tmp/gogo.go:141:6.
.0:
	 t0 = len(a)
	 t1 = make []int 0:int t0
	 t2 = len(a)
	 t3 = t2 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.1:
	 t4 = a[t9]
	 t5 = t4 - 48:byte
	 t6 = convert int <- byte (t5)
	 t7 = t6 >= 0:int
	 if t7 goto 6 else 5
.6:
	 t17 = t6 < 10:int
	 if t17 goto 4 else 5
.4:
	 t11 = new [1]int (varargs)
	 t12 = &t11[0:int]
	 *t12 = t6
	 t13 = slice t11[:]
	 t14 = append(t8, t13...)
	 jump 5
.5:
	 t15 = phi [1: t8, 6: t8, 4: t14] #rst
	 t16 = t9 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.1:
	 t4 = a[t9]
	 t5 = t4 - 48:byte
	 t6 = convert int <- byte (t5)
	 t7 = t6 >= 0:int
	 if t7 goto 6 else 5
.6:
	 t17 = t6 < 10:int
	 if t17 goto 4 else 5
.4:
	 t11 = new [1]int (varargs)
	 t12 = &t11[0:int]
	 *t12 = t6
	 t13 = slice t11[:]
	 t14 = append(t8, t13...)
	 jump 5
.5:
	 t15 = phi [1: t8, 6: t8, 4: t14] #rst
	 t16 = t9 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t15] #rst
	 t9 = phi [0: t3, 5: t16] #i
	 t10 = t9 >= 0:int
	 if t10 goto 1 else 2
.2:
	 return t8
Leaving main.func6, resuming main.main at /tmp/gogo.go:199:15.
	 t29 = len(t24)
	 t30 = t29 == 0:int
	 if t30 goto 1 else 4
.4:
	 t43 = len(t26)
	 t44 = t43 == 0:int
	 if t44 goto 1 else 3
.3:
	 t41 = len(t28)
	 t42 = t41 == 0:int
	 if t42 goto 1 else 2
.2:
	 t36 = new [1]int (slicelit)
	 t37 = &t36[0:int]
	 *t37 = 0:int
	 t38 = slice t36[:]
	 t39 = func1(t24, t38)
Entering main.func1 at /tmp/gogo.go:18:6.
.0:
	 t0 = len(aa)
	 t1 = t0 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.4:
	 t10 = t8 + 1:int
	 t11 = slice aa[:t10]
	 jump 2
.2:
	 t5 = phi [3: nil:[]int, 4: t11] #a
	 t6 = len(bb)
	 t7 = t6 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.6:
	 t13 = &bb[t20]
	 t14 = *t13
	 t15 = t14 > 0:int
	 if t15 goto 9 else 10
.10:
	 t24 = t20 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.7:
	 t16 = phi [8: nil:[]int, 9: t23] #b
	 t17 = len(t5)
	 t18 = len(t16)
	 t19 = t17 > t18
	 if t19 goto 11 else 12
.11:
	 return 1:int
Leaving main.func1, resuming main.main at /tmp/gogo.go:207:13.
	 t40 = t39 <= 0:int
	 if t40 goto 5 else 8
.8:
	 t74 = new [1]int (slicelit)
	 t75 = &t74[0:int]
	 *t75 = 0:int
	 t76 = slice t74[:]
	 t77 = func1(t26, t76)
Entering main.func1 at /tmp/gogo.go:18:6.
.0:
	 t0 = len(aa)
	 t1 = t0 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.4:
	 t10 = t8 + 1:int
	 t11 = slice aa[:t10]
	 jump 2
.2:
	 t5 = phi [3: nil:[]int, 4: t11] #a
	 t6 = len(bb)
	 t7 = t6 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.6:
	 t13 = &bb[t20]
	 t14 = *t13
	 t15 = t14 > 0:int
	 if t15 goto 9 else 10
.10:
	 t24 = t20 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.7:
	 t16 = phi [8: nil:[]int, 9: t23] #b
	 t17 = len(t5)
	 t18 = len(t16)
	 t19 = t17 > t18
	 if t19 goto 11 else 12
.11:
	 return 1:int
Leaving main.func1, resuming main.main at /tmp/gogo.go:208:14.
	 t78 = t77 <= 0:int
	 if t78 goto 5 else 7
.7:
	 t69 = new [1]int (slicelit)
	 t70 = &t69[0:int]
	 *t70 = 0:int
	 t71 = slice t69[:]
	 t72 = func1(t28, t71)
Entering main.func1 at /tmp/gogo.go:18:6.
.0:
	 t0 = len(aa)
	 t1 = t0 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.4:
	 t10 = t8 + 1:int
	 t11 = slice aa[:t10]
	 jump 2
.2:
	 t5 = phi [3: nil:[]int, 4: t11] #a
	 t6 = len(bb)
	 t7 = t6 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.6:
	 t13 = &bb[t20]
	 t14 = *t13
	 t15 = t14 > 0:int
	 if t15 goto 9 else 10
.10:
	 t24 = t20 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.7:
	 t16 = phi [8: nil:[]int, 9: t23] #b
	 t17 = len(t5)
	 t18 = len(t16)
	 t19 = t17 > t18
	 if t19 goto 11 else 12
.11:
	 return 1:int
Leaving main.func1, resuming main.main at /tmp/gogo.go:209:14.
	 t73 = t72 <= 0:int
	 if t73 goto 5 else 6
.6:
	 t50 = func2(t24, t26)
Entering main.func2 at /tmp/gogo.go:51:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = func0(t0, t1)
Entering main.func0 at /tmp/gogo.go:8:6.
.0:
	 t0 = a > b
	 if t0 goto 1 else 2
.1:
	 return a
Leaving main.func0, resuming main.func2 at /tmp/gogo.go:52:18.
	 t3 = t2 + 1:int
	 t4 = make []int t3 t3
	 t5 = len(t4)
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.8:
	 t24 = t21 % 10:int
	 jump 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.3:
	 return t4
Leaving main.func2, resuming main.main at /tmp/gogo.go:214:16.
	 t51 = func2(t24, t28)
Entering main.func2 at /tmp/gogo.go:51:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = func0(t0, t1)
Entering main.func0 at /tmp/gogo.go:8:6.
.0:
	 t0 = a > b
	 if t0 goto 1 else 2
.1:
	 return a
Leaving main.func0, resuming main.func2 at /tmp/gogo.go:52:18.
	 t3 = t2 + 1:int
	 t4 = make []int t3 t3
	 t5 = len(t4)
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.3:
	 return t4
Leaving main.func2, resuming main.main at /tmp/gogo.go:215:16.
	 t52 = func2(t26, t28)
Entering main.func2 at /tmp/gogo.go:51:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = func0(t0, t1)
Entering main.func0 at /tmp/gogo.go:8:6.
.0:
	 t0 = a > b
	 if t0 goto 1 else 2
.2:
	 return b
Leaving main.func0, resuming main.func2 at /tmp/gogo.go:52:18.
	 t3 = t2 + 1:int
	 t4 = make []int t3 t3
	 t5 = len(t4)
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.3:
	 return t4
Leaving main.func2, resuming main.main at /tmp/gogo.go:216:16.
	 t53 = func4(t50, t51)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
for(int i<len(b))
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
for(int j<len(a))
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16// a[j]
	 t18 = &b[t13]
	 t19 = *t18// b[i]
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:218:22.
	 t54 = func4(t53, t24)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:218:16.
	 t55 = func4(t50, t52)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:219:22.
	 t56 = func4(t55, t26)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:219:16.
	 t57 = func4(t51, t52)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:220:22.
	 t58 = func4(t57, t28)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:220:16.
	 t59 = func2(t56, t58)
Entering main.func2 at /tmp/gogo.go:51:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = func0(t0, t1)
Entering main.func0 at /tmp/gogo.go:8:6.
.0:
	 t0 = a > b
	 if t0 goto 1 else 2
.2:
	 return b
Leaving main.func0, resuming main.func2 at /tmp/gogo.go:52:18.
	 t3 = t2 + 1:int
	 t4 = make []int t3 t3
	 t5 = len(t4)
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.8:
	 t24 = t21 % 10:int
	 jump 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.3:
	 return t4
Leaving main.func2, resuming main.main at /tmp/gogo.go:231:26.
	 t60 = func2(t54, t59)
Entering main.func2 at /tmp/gogo.go:51:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = func0(t0, t1)
Entering main.func0 at /tmp/gogo.go:8:6.
.0:
	 t0 = a > b
	 if t0 goto 1 else 2
.1:
	 return a
Leaving main.func0, resuming main.func2 at /tmp/gogo.go:52:18.
	 t3 = t2 + 1:int
	 t4 = make []int t3 t3
	 t5 = len(t4)
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.8:
	 t24 = t21 % 10:int
	 jump 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.8:
	 t24 = t21 % 10:int
	 jump 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.8:
	 t24 = t21 % 10:int
	 jump 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.8:
	 t24 = t21 % 10:int
	 jump 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.8:
	 t24 = t21 % 10:int
	 jump 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.6:
	 t17 = &b[t8]
	 t18 = *t17
	 jump 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.4:
	 t12 = &a[t8]
	 t13 = *t12
	 jump 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.2:
	 t10 = len(a)
	 t11 = t8 < t10
	 if t11 goto 4 else 5
.5:
	 t14 = phi [2: 0:int, 4: t13] #a_i
	 t15 = len(b)
	 t16 = t8 < t15
	 if t16 goto 6 else 7
.7:
	 t19 = phi [5: 0:int, 6: t18] #b_i
	 t20 = t14 + t19
	 t21 = t20 + t6
	 t22 = t21 / 10:int
	 t23 = t21 >= 10:int
	 if t23 goto 8 else 9
.9:
	 t25 = phi [7: t21, 8: t24] #tmp
	 t26 = &t4[t8]
	 *t26 = t25
	 jump 1
.1:
	 t6 = phi [0: 0:int, 9: t22] #carry
	 t7 = phi [0: -1:int, 9: t8]
	 t8 = t7 + 1:int
	 t9 = t8 < t5
	 if t9 goto 2 else 3
.3:
	 return t4
Leaving main.func2, resuming main.main at /tmp/gogo.go:231:16.
	 t61 = new [1]int (slicelit)
	 t62 = &t61[0:int]
	 *t62 = 10:int
	 t63 = slice t61[:]
	 t64 = func4(t51, t52)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:234:36.
	 t65 = func4(t50, t64)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:234:26.
	 t66 = func4(t63, t65)
Entering main.func4 at /tmp/gogo.go:104:6.
.0:
	 t0 = len(a)
	 t1 = len(b)
	 t2 = t0 + t1
	 t3 = make []int t2 t2
	 t4 = len(t3)
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.2:
	 t8 = &t3[t6]
	 *t8 = 0:int
	 jump 1
.1:
	 t5 = phi [0: -1:int, 2: t6]
	 t6 = t5 + 1:int
	 t7 = t6 < t4
	 if t7 goto 2 else 3
.3:
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.4:
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.7:
	 t16 = &a[t27]
	 t17 = *t16
	 t18 = &b[t13]
	 t19 = *t18
	 t20 = t17 * t19
	 t21 = t13 + t27
	 t22 = &t3[t21]
	 t23 = *t22
	 t24 = t23 + t20
	 *t22 = t24
	 t25 = t27 + 1:int
	 jump 9
.9:
	 t27 = phi [4: 0:int, 7: t25] #j
	 t28 = len(a)
	 t29 = t27 < t28
	 if t29 goto 7 else 8
.8:
	 t26 = t13 + 1:int
	 jump 6
.6:
	 t13 = phi [3: 0:int, 8: t26] #i
	 t14 = len(b)
	 t15 = t13 < t14
	 if t15 goto 4 else 5
.5:
	 t9 = len(t3)
	 t10 = t9 - 1:int
	 t11 = slice t3[:t10]
	 t12 = len(t11)
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.13:
	 t36 = t31 + 1:int
	 t37 = &t3[t36]
	 t38 = &t3[t31]
	 t39 = *t38
	 t40 = t39 / 10:int
	 t41 = *t37
	 t42 = t41 + t40
	 *t37 = t42
	 t43 = &t3[t31]
	 t44 = *t43
	 t45 = t44 % 10:int
	 *t43 = t45
	 jump 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.11:
	 t33 = &t3[t31]
	 t34 = *t33
	 t35 = t34 >= 10:int
	 if t35 goto 13 else 10
.10:
	 t30 = phi [5: -1:int, 11: t31, 13: t31]
	 t31 = t30 + 1:int
	 t32 = t31 < t12
	 if t32 goto 11 else 12
.12:
	 return t3
Leaving main.func4, resuming main.main at /tmp/gogo.go:234:16.
	 t67 = func1(t60, t66)
Entering main.func1 at /tmp/gogo.go:18:6.
.0:
	 t0 = len(aa)
	 t1 = t0 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.5:
	 t12 = t8 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.5:
	 t12 = t8 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.5:
	 t12 = t8 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.5:
	 t12 = t8 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.5:
	 t12 = t8 - 1:int
	 jump 3
.3:
	 t8 = phi [0: t1, 5: t12] #i
	 t9 = t8 >= 0:int
	 if t9 goto 1 else 2
.1:
	 t2 = &aa[t8]
	 t3 = *t2
	 t4 = t3 > 0:int
	 if t4 goto 4 else 5
.4:
	 t10 = t8 + 1:int
	 t11 = slice aa[:t10]
	 jump 2
.2:
	 t5 = phi [3: nil:[]int, 4: t11] #a
	 t6 = len(bb)
	 t7 = t6 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.6:
	 t13 = &bb[t20]
	 t14 = *t13
	 t15 = t14 > 0:int
	 if t15 goto 9 else 10
.10:
	 t24 = t20 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.6:
	 t13 = &bb[t20]
	 t14 = *t13
	 t15 = t14 > 0:int
	 if t15 goto 9 else 10
.10:
	 t24 = t20 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.6:
	 t13 = &bb[t20]
	 t14 = *t13
	 t15 = t14 > 0:int
	 if t15 goto 9 else 10
.10:
	 t24 = t20 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.6:
	 t13 = &bb[t20]
	 t14 = *t13
	 t15 = t14 > 0:int
	 if t15 goto 9 else 10
.10:
	 t24 = t20 - 1:int
	 jump 8
.8:
	 t20 = phi [2: t7, 10: t24] #i
	 t21 = t20 >= 0:int
	 if t21 goto 6 else 7
.6:
	 t13 = &bb[t20]
	 t14 = *t13
	 t15 = t14 > 0:int
	 if t15 goto 9 else 10
.9:
	 t22 = t20 + 1:int
	 t23 = slice bb[:t22]
	 jump 7
.7:
	 t16 = phi [8: nil:[]int, 9: t23] #b
	 t17 = len(t5)
	 t18 = len(t16)
	 t19 = t17 > t18
	 if t19 goto 11 else 12
.12:
	 t25 = len(t5)
	 t26 = len(t16)
	 t27 = t25 < t26
	 if t27 goto 13 else 14
.14:
	 t28 = len(t5)
	 t29 = t28 - 1:int
	 jump 17
.17:
	 t35 = phi [14: t29, 21: t42] #i
	 t36 = t35 >= 0:int
	 if t36 goto 15 else 16
.15:
	 t30 = &t5[t35]
	 t31 = *t30
	 t32 = &t16[t35]
	 t33 = *t32
	 t34 = t31 > t33
	 if t34 goto 18 else 19
.18:
	 return 1:int
Leaving main.func1, resuming main.main at /tmp/gogo.go:236:13.
	 t68 = t67 == 0:int
	 if t68 goto 9 else 11
.11:
	 t84 = new [1]interface{} (varargs)
	 t85 = &t84[0:int]
	 t86 = make interface{} <- string ("Wrong! Try again!!":string)
	 *t85 = t86
	 t87 = slice t84[:]
	 t88 = fmt.Println(t87...)
Entering fmt.Println at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:256:6.
.0:
	 t0 = *os.Stdout
	 t1 = make io.Writer <- *os.File (t0)
	 t2 = Fprintln(t1, a...)
Entering fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:245:6.
.0:
	 t0 = newPrinter()
Entering fmt.newPrinter at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:132:6.
.0:
	 t0 = (*sync.Pool).Get(ppFree)
Entering (*sync.Pool).Get at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:124:16.
	(external)
Entering fmt.init$1 at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:128:7.
.0:
	 t0 = new pp (new)
	 t1 = make interface{} <- *pp (t0)
	 return t1
Leaving fmt.init$1, resuming (*sync.Pool).Get.
Leaving (*sync.Pool).Get, resuming fmt.newPrinter at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:133:17.
	 t1 = typeassert t0.(*pp)
	 t2 = &t1.panicking [#6]
	 *t2 = false:bool
	 t3 = &t1.erroring [#7]
	 *t3 = false:bool
	 t4 = &t1.fmt [#3]
	 t5 = &t1.buf [#0]
	 t6 = (*fmt).init(t4, t5)
Entering (*fmt.fmt).init at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:58:15.
.0:
	 t0 = &f.buf [#0]
	 *t0 = buf
	 t1 = (*fmt).clearflags(f)
Entering (*fmt.fmt).clearflags at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:54:15.
.0:
	 t0 = &f.fmtFlags [#1]
	 t1 = local fmtFlags ()
	 t2 = *t1
	 *t0 = t2
	 return
Leaving (*fmt.fmt).clearflags, resuming (*fmt.fmt).init at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:60:14.
	 return
Leaving (*fmt.fmt).init, resuming fmt.newPrinter at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:136:12.
	 return t1
Leaving fmt.newPrinter, resuming fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:246:17.
	 t1 = (*pp).doPrintln(t0, a)
Entering (*fmt.pp).doPrintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:1131:14.
.0:
	 t0 = len(a)
	 jump 1
.1:
	 t1 = phi [0: -1:int, 5: t2]
	 t2 = t1 + 1:int
	 t3 = t2 < t0
	 if t3 goto 2 else 3
.2:
	 t4 = &a[t2]
	 t5 = *t4
	 t6 = t2 > 0:int
	 if t6 goto 4 else 5
.5:
	 t11 = (*pp).printArg(p, t5, 118:rune)
Entering (*fmt.pp).printArg at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:604:14.
.0:
	 t0 = &p.arg [#1]
	 *t0 = arg
	 t1 = &p.value [#2]
	 t2 = local reflect.Value ()
	 t3 = *t2
	 *t1 = t3
	 t4 = arg == nil:interface{}
	 if t4 goto 1 else 2
.2:
	 t6 = verb == 84:rune
	 if t6 goto 7 else 9
.9:
	 t17 = verb == 112:rune
	 if t17 goto 8 else 10
.10:
	 t18 = typeassert,ok arg.(bool)
	 t19 = extract t18 #0
	 t20 = extract t18 #1
	 if t20 goto 12 else 13
.13:
	 t22 = typeassert,ok arg.(float32)
	 t23 = extract t22 #0
	 t24 = extract t22 #1
	 if t24 goto 14 else 15
.15:
	 t27 = typeassert,ok arg.(float64)
	 t28 = extract t27 #0
	 t29 = extract t27 #1
	 if t29 goto 16 else 17
.17:
	 t31 = typeassert,ok arg.(complex64)
	 t32 = extract t31 #0
	 t33 = extract t31 #1
	 if t33 goto 18 else 19
.19:
	 t36 = typeassert,ok arg.(complex128)
	 t37 = extract t36 #0
	 t38 = extract t36 #1
	 if t38 goto 20 else 21
.21:
	 t40 = typeassert,ok arg.(int)
	 t41 = extract t40 #0
	 t42 = extract t40 #1
	 if t42 goto 22 else 23
.23:
	 t45 = typeassert,ok arg.(int8)
	 t46 = extract t45 #0
	 t47 = extract t45 #1
	 if t47 goto 24 else 25
.25:
	 t50 = typeassert,ok arg.(int16)
	 t51 = extract t50 #0
	 t52 = extract t50 #1
	 if t52 goto 26 else 27
.27:
	 t55 = typeassert,ok arg.(int32)
	 t56 = extract t55 #0
	 t57 = extract t55 #1
	 if t57 goto 28 else 29
.29:
	 t60 = typeassert,ok arg.(int64)
	 t61 = extract t60 #0
	 t62 = extract t60 #1
	 if t62 goto 30 else 31
.31:
	 t65 = typeassert,ok arg.(uint)
	 t66 = extract t65 #0
	 t67 = extract t65 #1
	 if t67 goto 32 else 33
.33:
	 t70 = typeassert,ok arg.(uint8)
	 t71 = extract t70 #0
	 t72 = extract t70 #1
	 if t72 goto 34 else 35
.35:
	 t75 = typeassert,ok arg.(uint16)
	 t76 = extract t75 #0
	 t77 = extract t75 #1
	 if t77 goto 36 else 37
.37:
	 t80 = typeassert,ok arg.(uint32)
	 t81 = extract t80 #0
	 t82 = extract t80 #1
	 if t82 goto 38 else 39
.39:
	 t85 = typeassert,ok arg.(uint64)
	 t86 = extract t85 #0
	 t87 = extract t85 #1
	 if t87 goto 40 else 41
.41:
	 t89 = typeassert,ok arg.(uintptr)
	 t90 = extract t89 #0
	 t91 = extract t89 #1
	 if t91 goto 42 else 43
.43:
	 t94 = typeassert,ok arg.(string)
	 t95 = extract t94 #0
	 t96 = extract t94 #1
	 if t96 goto 44 else 45
.44:
	 t97 = (*pp).fmtString(p, t95, verb)
Entering (*fmt.pp).fmtString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:424:14.
.0:
	 t0 = verb == 118:rune
	 if t0 goto 2 else 4
.2:
	 t1 = &p.fmt [#3]
	 t2 = &t1.fmtFlags [#1]
	 t3 = &t2.sharpV [#8]
	 t4 = *t3
	 if t4 goto 5 else 6
.6:
	 t10 = &p.fmt [#3]
	 t11 = (*fmt).fmt_s(t10, v)
Entering (*fmt.fmt).fmt_s at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:326:15.
.0:
	 t0 = (*fmt).truncate(f, s)
Entering (*fmt.fmt).truncate at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:312:15.
.0:
	 t0 = &f.fmtFlags [#1]
	 t1 = &t0.precPresent [#1]
	 t2 = *t1
	 if t2 goto 1 else 2
.2:
	 return s
Leaving (*fmt.fmt).truncate, resuming (*fmt.fmt).fmt_s at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:327:16.
	 t1 = (*fmt).padString(f, t0)
Entering (*fmt.fmt).padString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:108:15.
.0:
	 t0 = &f.fmtFlags [#1]
	 t1 = &t0.widPresent [#0]
	 t2 = *t1
	 if t2 goto 3 else 1
.1:
	 t3 = &f.buf [#0]
	 t4 = *t3
	 t5 = (*buffer).WriteString(t4, s)
Entering (*fmt.buffer).WriteString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:81:18.
.0:
	 t0 = *b
	 t1 = append(t0, s...)
	 *b = t1
	 return
Leaving (*fmt.buffer).WriteString, resuming (*fmt.fmt).padString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:110:20.
	 return
Leaving (*fmt.fmt).padString, resuming (*fmt.fmt).fmt_s at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/format.go:328:13.
	 return
Leaving (*fmt.fmt).fmt_s, resuming (*fmt.pp).fmtString at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:430:15.
	 jump 1
.1:
	 return
Leaving (*fmt.pp).fmtString, resuming (*fmt.pp).printArg at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:664:14.
	 jump 11
.11:
	 return
Leaving (*fmt.pp).printArg, resuming (*fmt.pp).doPrintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:1136:13.
	 jump 1
.1:
	 t1 = phi [0: -1:int, 5: t2]
	 t2 = t1 + 1:int
	 t3 = t2 < t0
	 if t3 goto 2 else 3
.3:
	 t7 = &p.buf [#0]
	 t8 = (*buffer).WriteByte(t7, 10:byte)
Entering (*fmt.buffer).WriteByte at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:85:18.
.0:
	 t0 = *b
	 t1 = new [1]byte (varargs)
	 t2 = &t1[0:int]
	 *t2 = c
	 t3 = slice t1[:]
	 t4 = append(t0, t3...)
	 *b = t4
	 return
Leaving (*fmt.buffer).WriteByte, resuming (*fmt.pp).doPrintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:1138:17.
	 return
Leaving (*fmt.pp).doPrintln, resuming fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:247:13.
	 t2 = &t0.buf [#0]
	 t3 = *t2
	 t4 = changetype []byte <- buffer (t3)
	 t5 = invoke w.Write(t4)
Entering (*os.File).Write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:136:16.
.0:
	 t0 = (*File).checkValid(f, "write":string)
Entering (*os.File).checkValid at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_posix.go:164:16.
.0:
	 t0 = f == nil:*File
	 if t0 goto 1 else 2
.2:
	 return nil:error
Leaving (*os.File).checkValid, resuming (*os.File).Write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:137:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 t2 = (*File).write(f, b)
Entering (*os.File).write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:232:16.
.0:
	 t0 = &f.file [#0]
	 t1 = *t0
	 t2 = &t1.pfd [#0]
	 t3 = (*internal/poll.FD).Write(t2, b)
Entering (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:205:15.
.0:
	 t0 = (*FD).writeLock(fd)
Entering (*internal/poll.FD).writeLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:236:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwlock(t0, false:bool)
Entering (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:115:20.
.0:
	 if read goto 1 else 2
.2:
	 t1 = &mu.wsema [#2]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 7: t2, 2: 4:uint64, 13: t2] #mutexBit
	 t3 = phi [1: 8388608:uint64, 7: t3, 2: 8796093022208:uint64, 13: t3] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 7: t4, 2: 9223363240761753600:uint64, 13: t4] #mutexMask
	 t5 = phi [1: t0, 7: t5, 2: t1, 13: t5] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:130:27.
	 t8 = t7 & 1:uint64
	 t9 = t8 != 0:uint64
	 if t9 goto 4 else 5
.5:
	 t10 = t7 & t2
	 t11 = t10 == 0:uint64
	 if t11 goto 6 else 8
.6:
	 t12 = t7 | t2
	 t13 = t12 + 8:uint64
	 t14 = t13 & 8388600:uint64
	 t15 = t14 == 0:uint64
	 if t15 goto 9 else 7
.7:
	 t16 = phi [6: t13, 8: t19] #new
	 t17 = &mu.state [#0]
	 t18 = sync/atomic.CompareAndSwapUint64(t17, t7, t16)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:148:33.
	 if t18 goto 11 else 3
.11:
	 t24 = t7 & t2
	 t25 = t24 == 0:uint64
	 if t25 goto 12 else 13
.12:
	 return true:bool
Leaving (*internal/poll.fdMutex).rwlock, resuming (*internal/poll.FD).writeLock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:237:20.
	 if t1 goto 2 else 1
.2:
	 return nil:error
Leaving (*internal/poll.FD).writeLock, resuming (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:206:24.
	 t1 = t0 != nil:error
	 if t1 goto 1 else 2
.2:
	 defer (*FD).writeUnlock(fd)
	 t2 = &fd.pd [#2]
	 t3 = &fd.isFile [#6]
	 t4 = *t3
	 t5 = (*pollDesc).prepareWrite(t2, t4)
Entering (*internal/poll.pollDesc).prepareWrite at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:77:21.
.0:
	 t0 = (*pollDesc).prepare(pd, 119:int, isFile)
Entering (*internal/poll.pollDesc).prepare at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:65:21.
.0:
	 t0 = &pd.runtimeCtx [#0]
	 t1 = *t0
	 t2 = t1 == 0:uintptr
	 if t2 goto 1 else 2
.1:
	 return nil:error
Leaving (*internal/poll.pollDesc).prepare, resuming (*internal/poll.pollDesc).prepareWrite at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_poll_runtime.go:78:19.
	 return t0
Leaving (*internal/poll.pollDesc).prepareWrite, resuming (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:210:30.
	 t6 = t5 != nil:error
	 if t6 goto 4 else 5
.5:
	 jump 6
.6:
	 t7 = phi [5: 0:int, 14: t23, 18: t23] #nn
	 t8 = len(p)
	 t9 = &fd.IsStream [#4]
	 t10 = *t9
	 if t10 goto 9 else 8
.9:
	 t20 = t8 - t7
	 t21 = t20 > 1073741824:int
	 if t21 goto 7 else 8
.8:
	 t12 = phi [6: t8, 9: t8, 7: t11] #max
	 t13 = &fd.Sysfd [#1]
	 t14 = *t13
	 t15 = slice p[t7:t12]
	 t16 = syscall.Write(t14, t15)
Entering syscall.Write at /usr/local/Cellar/go/1.9.2/libexec/src/syscall/syscall_unix.go:177:6.
	(external)
Leaving syscall.Write, resuming (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:219:26.
	 t17 = extract t16 #0
	 t18 = extract t16 #1
	 t19 = t17 > 0:int
	 if t19 goto 10 else 11
.10:
	 t22 = t7 + t17
	 jump 11
.11:
	 t23 = phi [8: t7, 10: t22] #nn
	 t24 = len(p)
	 t25 = t23 == t24
	 if t25 goto 12 else 13
.12:
	 rundefers
/usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:209:2: invoking deferred function call
Entering (*internal/poll.FD).writeUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:246:15.
.0:
	 t0 = &fd.fdmu [#0]
	 t1 = (*fdMutex).rwunlock(t0, false:bool)
Entering (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:160:20.
.0:
	 if read goto 1 else 2
.2:
	 t1 = &mu.wsema [#2]
	 jump 3
.3:
	 t2 = phi [1: 2:uint64, 8: t2, 2: 4:uint64] #mutexBit
	 t3 = phi [1: 8388608:uint64, 8: t3, 2: 8796093022208:uint64] #mutexWait
	 t4 = phi [1: 8796084633600:uint64, 8: t4, 2: 9223363240761753600:uint64] #mutexMask
	 t5 = phi [1: t0, 8: t5, 2: t1] #mutexSema
	 t6 = &mu.state [#0]
	 t7 = sync/atomic.LoadUint64(t6)
Entering sync/atomic.LoadUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:120:6.
	(external)
Leaving sync/atomic.LoadUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:175:27.
	 t8 = t7 & t2
	 t9 = t8 == 0:uint64
	 if t9 goto 4 else 6
.6:
	 t15 = t7 & 8388600:uint64
	 t16 = t15 == 0:uint64
	 if t16 goto 4 else 5
.5:
	 t11 = t7 &^ t2
	 t12 = t11 - 8:uint64
	 t13 = t7 & t4
	 t14 = t13 != 0:uint64
	 if t14 goto 7 else 8
.8:
	 t18 = phi [5: t12, 7: t17] #new
	 t19 = &mu.state [#0]
	 t20 = sync/atomic.CompareAndSwapUint64(t19, t7, t18)
Entering sync/atomic.CompareAndSwapUint64 at /usr/local/Cellar/go/1.9.2/libexec/src/sync/atomic/doc.go:83:6.
	(external)
Leaving sync/atomic.CompareAndSwapUint64, resuming (*internal/poll.fdMutex).rwunlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:184:33.
	 if t20 goto 9 else 3
.9:
	 t21 = t7 & t4
	 t22 = t21 != 0:uint64
	 if t22 goto 10 else 11
.11:
	 t24 = t18 & 8388601:uint64
	 t25 = t24 == 1:uint64
	 return t25
Leaving (*internal/poll.fdMutex).rwunlock, resuming (*internal/poll.FD).writeUnlock at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_mutex.go:247:21.
	 if t1 goto 1 else 2
.2:
	 return
Leaving (*internal/poll.FD).writeUnlock, resuming (*internal/poll.FD).Write at /usr/local/Cellar/go/1.9.2/libexec/src/internal/poll/fd_unix.go:209:2.
	 return t23, t18
Leaving (*internal/poll.FD).Write, resuming (*os.File).write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:233:22.
	 t4 = extract t3 #0
	 t5 = extract t3 #1
	 t6 = make interface{} <- *File (f)
	 t7 = runtime.KeepAlive(t6)
Entering runtime.KeepAlive at /usr/local/Cellar/go/1.9.2/libexec/src/runtime/mfinal.go:490:6.
	(external)
Leaving runtime.KeepAlive, resuming (*os.File).write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:234:19.
	 return t4, t5
Leaving (*os.File).write, resuming (*os.File).Write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:140:17.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 t5 = t3 < 0:int
	 if t5 goto 3 else 4
.4:
	 t6 = phi [2: t3, 3: 0:int] #n
	 t7 = len(b)
	 t8 = t6 != t7
	 if t8 goto 5 else 6
.6:
	 t10 = phi [4: nil:error, 5: t9] #err
	 t11 = epipecheck(f, t4)
Entering os.epipecheck at /usr/local/Cellar/go/1.9.2/libexec/src/os/file_unix.go:132:6.
.0:
	 t0 = make error <- syscall.Errno (32:syscall.Errno)
	 t1 = e == t0
	 if t1 goto 3 else 2
.2:
	 return
Leaving os.epipecheck, resuming (*os.File).Write at /usr/local/Cellar/go/1.9.2/libexec/src/os/file.go:148:12.
	 t12 = t4 != nil:error
	 if t12 goto 7 else 8
.8:
	 t14 = phi [6: t10, 7: t13] #err
	 return t6, t14
Leaving (*os.File).Write, resuming fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:248:18.
	 t6 = extract t5 #0
	 t7 = extract t5 #1
	 t8 = (*pp).free(t0)
Entering (*fmt.pp).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:141:14.
.0:
	 t0 = &p.buf [#0]
	 t1 = &p.buf [#0]
	 t2 = *t1
	 t3 = slice t2[:0:int]
	 *t0 = t3
	 t4 = &p.arg [#1]
	 *t4 = nil:interface{}
	 t5 = &p.value [#2]
	 t6 = local reflect.Value ()
	 t7 = *t6
	 *t5 = t7
	 t8 = make interface{} <- *pp (p)
	 t9 = (*sync.Pool).Put(ppFree, t8)
Entering (*sync.Pool).Put at /usr/local/Cellar/go/1.9.2/libexec/src/sync/pool.go:88:16.
	(external)
Leaving (*sync.Pool).Put, resuming (*fmt.pp).free at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:145:12.
	 return
Leaving (*fmt.pp).free, resuming fmt.Fprintln at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:249:8.
	 return t6, t7
Leaving fmt.Fprintln, resuming fmt.Println at /usr/local/Cellar/go/1.9.2/libexec/src/fmt/print.go:257:17.
	 t3 = extract t2 #0
	 t4 = extract t2 #1
	 return t3, t4
Leaving fmt.Println, resuming main.main at /tmp/gogo.go:239:20.
	 jump 10
.10:
	 return
Leaving main.main.