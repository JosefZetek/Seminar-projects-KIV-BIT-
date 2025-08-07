Aplikace obsahuje dva soubory main a DigitalSignature
Třída DigitalSignature zajišťuje podpis a ověření.
Program po spuštění přečte soubory x, p, g, y a případně je vytvoří. Pro ověření je potřeba podpis, který se rovněž stejně jako soubory x, y, p, g hledá ve stejném adresáři, odkud je program spuštěn.
Pokud soubor signature není nalezen, vrací funkce pro ověření vždy False.
Program pro zkoušku šifruje osobní číslo a ověřuje správné a chybné osobní číslo.

