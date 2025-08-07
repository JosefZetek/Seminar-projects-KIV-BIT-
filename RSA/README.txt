Semestrální práce KIV/BIT - Asymetrický šifrovací algoritmus RSA
Josef Zetek

Práce je zaměřena na implementaci asymetrického šifrovacího algoritmu RSA.
Algoritmus nejprve vygeneruje dvojici klíčů (veřejný a soukromý), které se používají k šifrování.

Veřejný klíč (e, n)
Soukromý klíč (d, n)

Vygenerují se dvě velká prvočísla p a q
Výpočet n jako n = p * q
Výpočet phi(n) jako phi(n) = (p-1)(q-1)
Hodnota e je zvolena tak, aby byla menší než phi(n) a zároveň byla nesoudělná s phi(n) - zde je optimalizace

Protože čísla p a q se generují vždy takové, že mají MSB nastavený na 1 a počet bitů je 1024,
tak mohu počítat s tím, že číslo bude >= (1<<1023 | 1) - OR s 1 pro zajištění lichosti. Díky tomu je phi(n) dostatečně velké a tím pádem mohu
volit parametr e jako jakékoliv prvočíslo (je vždy nesoudělné), které bude menší než (1<<1023) ^ 2 (odečtená jednička
pro p i q, viz vzorec výše), což je součin dvou nejmenších možných vygenerovaných čísel - nejmenší možný výsledek phi(n).
Já jsem zvolil 65537, což je běžně používaná hodnota. Hodnota se proto nemusí generovat a ani ukládat do souboru (přesto
je zde uložena, aby bylo splněno zadání).

Jedna z nevýhod algoritmu je to, že generování prvočísel je časově náročné, včetně hledání d - multiplikativní inverze čísla e.
Další nevýhodou je větší velikost šifrovaných souborů, doba trvání umocnění, vyšší nároky na programovací jazyk/programátora pro
uložení velkého čísla. Výhodou je bezpečnost a možnost fungování bez nutnosti znalosti šifrovacího klíče předem.