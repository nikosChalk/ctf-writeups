
def lift_loop():
    N=24
    p5f = [0x10, 0, int("010", 8), 20, 0xe, int("014", 8), 0x12, int("02", 8), 0x16, int("012", 8), 6, 4]
    assert(len(p5f) == 12)
    for i in range(0, N, 4):
        if (i < 12):
            print(f"j9n[{p5f[i + 3] // 2}] = B2D(flag[{p5f[i + 3]}], flag[{p5f[i + 3] + 1}]);")
            print(f"g7k[{i // 4}] = XOR(C3E(flag[{i * 2}], flag[{i * 2 + 2}]), C3E(flag[{i * 2 + 4}], flag[{i * 2 + 6}]));")
            if (i < 4):
                print(f"h8m[{i // 4}] = A1C(flag[{i}], flag[{i + 4}], flag[{i + 8}], flag[{i + 12}]);")
            print(f"g7k[{(i // 4) + 3}] = XOR(C3E(flag[{i * 2 + 1}], flag[{i * 2 + 3}]), C3E(flag[{i * 2 + 5}], flag[{i * 2 + 7}]));")
            print(f"j9n[{p5f[i + 1] // 2}] = B2D(flag[{p5f[i + 1]}], flag[{p5f[i + 1] + 1}]);")
            print(f"j9n[{p5f[i + 2] // 2}] = B2D(flag[{p5f[i + 2]}], flag[{p5f[i + 2] + 1}]);")
            if (i == 4):
                print(f"h8m[1] = A1C(flag[16], flag[20], flag[1], flag[5]);")
            print(f"j9n[{p5f[i] // 2}] = B2D(flag[{p5f[i]}], flag[{p5f[i] + 1}]);")
        else:
            if (i < 16):
                print(f"h8m[{i // 6}] = A1C(flag[{i - 3}], flag[{i + 1}], flag[{i + 5}], flag[{i * 2 - 3}]);")
                print(f"h8m[3] = A1C(flag[2], flag[6], flag[10], flag[14]);")
            print("rc_cond_inc(g7k[0], 0x202);")
            print("rc_cond_inc(g7k[1], 0x1aa2);")
            print("rc_cond_inc(g7k[2], 0x5a5);")

def lift_interleaved_computations():
    ra = 1
    rb = 1
    rc = 10
    print(f"h8m[4] = A1C(flag[{rc * 2 - ra - rb}], flag[{rc * 2 + ra + rb}], flag[{ra * 3}], flag[{rb * 7}]);")
    print(f"h8m[5] = A1C(flag[{rc + ra}], flag[{rc + 5}], flag[{rc * 2 - rb}], flag[{rc * 2 + 3}]);")

print("lift_loop")
lift_loop()
print("")

print("lift_interleaved_computations")
lift_interleaved_computations()
print("")
