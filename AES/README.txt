Aplikace slouží k šifrování a dešifrování textu pomocí algoritmu AES s délkou klíče 128 bitů.
Nabízí 3 režimy šifrování: ECB, CBC a CFB
Aplikace je napsána v jazyce Python a používá knihovnu numpy.

Spuštění:
python3 main.py <-d/-e> <soubor>
Do aktuální složky, odkud byl program spuštěn, se uloží výsledky operace:
- šifrování: <soubor>.aes, <soubor>_cbc.aes, <soubor>_cfb.aes, aes_key.txt
- dešifrování: <soubor>.csv

Všechny klíčové metody algoritmu jsou součástí souboru AESModule.py (třída AESModule).
Všechny metody této třídy jsou komentovány dokumentačními komentáři a je dodržována konvence, kde metoda začínající znaky "__" je privátní.

Funkce počítají se zarovnanými daty a pro neodpovídající velikost vrátí výjimku informující o chybě.

Pro režimy CBC a CFB je použit inicializační vektor IV, který je deklarován v konstruktoru jako řetězec "ABCDEFGHIJKLMNOP". Tento řetězec lze přepsat, ale je nutné dodržet velikost 16 znaků (bajtů).

Stručný popis kódu:
Třída AESModule v konstruktoru inicializuje klíč a základní tabulky (Sbox, Inverse S-box, Rcon, MixColumns, Inverse MixColumns).
Následně jsou implementovány jednotlivé metody pro šifrování a dešifrování (SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion).
Tyto metody jsou pak následně volány v metodách __encrypt a __decrypt, které šifrují/dešifrují jeden blok dat v režimu ECB.

Veřejné metody encrypt_data_ecb, encrypt_data_cbc a encrypt_data_cfb jsou pouze nadstavbou, která rozdělí data do bloků a postupně volají metodu __encrypt (případně pro CBC a CFB u toho provádí modifikaci s daty).
Veřejné metody decrypt_data_ecb, decrypt_data_cbc a decrypt_data_cfb jsou obdobné, ale volají metodu __decrypt.