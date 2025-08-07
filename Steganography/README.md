# KIV -- BIT

## Semestrální práce 1 -- Steganografie

### Obsah projektu

- `weber.bmp`
- `test/`
- `out/`
- `validation/`
- `decoded/`

### Jednotkové testy

- složka `test/`, v případě implementace v jazyce Python využijte pro vaši práci. V případě, že implementujete v jiném jazyce, doporučujeme vytvořit podobné jednotkové testy.
  Testy kontrolují následující výstupy:

1. `test_steganography_img_sizes`

- porovná se, zda všechny obrázky po provedení steganografieve složce out/ mají stejnou velikost, jako weber.bmp

2. `test_all_imgs_after_steganography`

- porovná se, zda všechny obrázky ve složce out/ jsou odlišné od weber.bmp a zároveň jdou korektně načíst pomocí opencv knihovny

3. `test_decoded_results`

- porovná se, zda po provedení steganografie všechny soubory ve složce decoded/ a odpovídající ve složce validation/ jsou stejné

V jednotkových testech se využívá Python knihovna `opencv-python`, instalace pomocí

```
pip install opencv-python
```

### Vyhodnocení

Po nahrání vašeho ZIP archivu na Courseware dojde automaticky k jeho rozbalení a spuštění programu. Vyhodnocení proběhne na PC s operačním systémem Linux (distribuce Ubuntu 20.04).
Zajistěte prosím, aby hlavní spouštěcí skript měl název `main` (tzn. `main.py`, nebo `main.jar`, případně spustitelný `main` bez koncovky v případě C/C++).
Pokud práci vytvoříte v C/C++ vytvořte také `makefile`, který automaticky sestaví program a vytvoří spustitelný soubor `main`. Pokud implemtujete v Javě, ověřte, že váš JAR soubor je korektní a spustitelný.

Vyhodnocení proběhne na náhodně zvolených testovacích souborech. Plný počet bodů obdržíte pouze v případě, že váš program korektně zakóduje a dekóduje všechny testovací soubory.

### Nápověda

Využijte přednášku a dostupnou literaturu
