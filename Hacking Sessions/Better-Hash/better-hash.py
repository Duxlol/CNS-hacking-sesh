FLAG = "5f070b54361613bca31a123e95321cff154ba64f549bb34fdc7688f10efb569aed4ccbd6ba"

def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff


def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff

def better_hash(msg):
    state = bytearray.fromhex(msg)

    for rnd in range(7, -1, -1):
        state = state[-1:] + state[:-1]
        

        for i in range(len(state)-1, 0 , -1):
            state[i] ^= state[i - 1]

        for i in range(len(state)):
                    state[i] = ror(state[i], (rnd + i) & 7)
                    state[i] ^= (rnd * 41 + i * 17) & 0xff
                    

        

    return state.hex()

print(better_hash(FLAG))
