# TME : Cryptanalyse du chiffre de Vigenère

- L'[énoncé du TME](https://moodle-sciences.upmc.fr/moodle-2019/pluginfile.php/157066/mod_label/intro/TME_Vigenere.pdf) se trouve sur Moodle.
- Le fichier à modifier est `cryptanalyse_vigenere.py`.
- Le dossier `data` contient 100 textes chiffrés avec Vigenère. Pour chaque texte, on donne le texte clair `.plain`, le texte chiffré `.cipher` et la clé `.key`. Cela peut vous être utile pour tester votre code.
- Des tests automatiques sont à votre disposition. Vous pouvez lancer la commande `./test-all.sh` pour les executer, ou bien les executer séparément avec `python test-N-*.py` où N est le numéro du test que vous souhaitez effectuer. Ces tests sont automatiquement lancés lorsque vous effectuez un `push` sur GitLab, mais nous vous conseillons de les lancer d'abord localement et de ne soumettre votre travail que si les tests fonctionnent.

NB: il est possible que vous ayez à appliquer des correctifs en cours de route (par exemple à cause de tests deffectueux...). Pour appliquer ces correctifs sur votre travail :

```
# Seulement la première fois
$ git remote add upstream https://stl.algo-prog.info/3i024_1920/tme_02_-_cryptanalyse_vigenere/
# À chaque modification
$ git fetch upstream
$ git merge upstream/master -m "Merge upstream"
```
