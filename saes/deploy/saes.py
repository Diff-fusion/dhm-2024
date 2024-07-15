from aes import AES, bytes2matrix, matrix2bytes, add_round_key, sub_bytes, shift_rows, mix_columns

class SAES(AES):
    def __init__(self, master_key, sauce):
        assert sauce in range(0, 2**127)
        super().__init__(master_key)
        self.sauce = sauce

    def mix_sauce(self):
        for i in range(127):
            feedback = self.sauce >> 126
            self.sauce = (self.sauce << 1) & (2**127 - 1)
            if feedback:
                self.sauce ^= 0x3

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        add_round_key(plain_state, bytes2matrix(self.sauce.to_bytes(16, "big")))
        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        self.mix_sauce()

        return matrix2bytes(plain_state)
