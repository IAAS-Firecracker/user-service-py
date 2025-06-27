#!/bin/bash

# Stop script on error
set -e

# Créer un environnement virtuel s'il n'existe pas déjà
if [ ! -d "venv" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activer l'environnement virtuel
echo "Activation de l'environnement virtuel..."
source venv/bin/activate

# Installer les dépendances
echo "Installation des dépendances..."
pip install --upgrade pip
pip install -r requirements.txt

# Exécuter le script dans le dossier app
chmod +x app/start.sh

echo "Lancement de l'application..."
cd app
./start.sh
