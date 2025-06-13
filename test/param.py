from fips205 import SLH_DSA

if __name__ == '__main__':

    mxp = [0] * 11
    mxl = 0
    mxl1 = 0
    mxl2 = 0

    with open("param.txt") as f:
        for line in f:
            if len(line) < 2:
                continue
            if line[0] == '#':
                continue
            v = line.split()
            if len(v) < 12:
                continue

            name = v[0]
            par = [ int(v[i]) for i in range(1,12) ]
            (n, h, d, hp, a, k, lg_w, m, cat, pk_sz, sig_sz) = par

            #   maximum parameters
            mxp = [ max(mxp[i], par[i]) for i in range(11) ]

            slh = SLH_DSA(param=("SHAKE", n, h, d, hp, a, k, lg_w, m))
            if slh.sig_sz != sig_sz:
                print('!!! sig', name, sig_sz, slh.sig_sz)
            if slh.pk_sz != pk_sz:
                print('!!! pk', name, sig_sz, slh.sig_sz)
            mxl = max(mxl, slh.len)
            mxl1 = max(mxl1, slh.len1)
            mxl2 = max(mxl2, slh.len2)

            print(f'\t{{ "{name}", {n}, {h}, {d}, {hp}, {a}, {k}, {lg_w}, {m} }},')

    (n, h, d, hp, a, k, lg_w, m, cat, pk_sz, sig_sz) = mxp
    print(f"// max: n={n} h={h} d={d} h'={hp} a={a} k={k} lg_w={lg_w} m={m}")
    print(f"// max: len={mxl} len1={mxl1} len2={mxl2} sig_sz={sig_sz}")
