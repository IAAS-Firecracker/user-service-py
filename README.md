# User Service Python

Service de gestion des utilisateurs développé avec Django REST Framework pour l'architecture microservices UE-PROJET.

## 📋 Description

Ce service fournit une API REST pour la gestion des utilisateurs avec authentification JWT, intégration Eureka pour la découverte de services, et support PostgreSQL avec PostGIS.

## 🛠️ Technologies

- **Framework**: Django 5.1+ avec Django REST Framework
- **Base de données**: PostgreSQL avec PostGIS
- **Cache**: Redis
- **Authentification**: JWT (Simple JWT)
- **Documentation API**: Swagger (drf-yasg)
- **Service Discovery**: Eureka Client
- **Messagerie**: RabbitMQ (aio-pika)

## 📁 Structure du projet

```
user-service-py/
├── app/
│   ├── accounts/          # Application de gestion des comptes utilisateurs
│   ├── app/              # Configuration Django principale
│   │   ├── settings.py   # Configuration Django
│   │   ├── urls.py       # URLs principales
│   │   └── config_client.py # Client de configuration Spring Cloud
│   ├── manage.py         # Script de gestion Django
│   └── start.sh          # Script de démarrage
├── Dockerfile            # Configuration Docker
├── docker-compose.yml    # Orchestration des services
├── requirements.txt      # Dépendances Python
└── .env                 # Variables d'environnement
```

## 🚀 Installation et utilisation

### Prérequis

- Python 3.9+
- PostgreSQL avec PostGIS
- Redis
- Docker et Docker Compose (pour l'utilisation Docker)

### 🔧 Utilisation locale

#### 1. Cloner le projet
```bash
git clone https://github.com/IAAS-Firecracker/user-service-py.git
cd user-service-py
```

#### 2. Créer un environnement virtuel
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

#### 3. Installer les dépendances
```bash
pip install -r requirements.txt
```

#### 4. Configuration des variables d'environnement

Créer un fichier `.env` à la racine du projet :
```env
DB_PORT=5433
DB_HOST=localhost
REDIS_HOST=localhost
REDIS_PORT=6379
DB_NAME=user_service_db
DB_USER=firecracker
DB_PASSWORD=fireCracker
```

#### 5. Préparer la base de données

Assurez-vous que PostgreSQL avec PostGIS est installé et configuré :
```bash
# Créer la base de données
createdb -U postgres user_service_db
```

#### 6. Migrations Django
```bash
cd app
python manage.py makemigrations
python manage.py makemigrations accounts
python manage.py migrate
```

#### 7. Collecter les fichiers statiques
```bash
python manage.py collectstatic --noinput
```

#### 8. Créer un superutilisateur (optionnel)
```bash
python manage.py createsuperuser
```

#### 9. Lancer le serveur de développement
```bash
python manage.py runserver 0.0.0.0:8000
```

Le service sera accessible sur `http://localhost:8000`

### 🐳 Utilisation avec Docker

#### 1. Utilisation avec Docker Compose (recommandé)

```bash
# Construire et lancer tous les services
docker-compose up --build

# Lancer en arrière-plan
docker-compose up -d --build

# Voir les logs
docker-compose logs -f app

# Arrêter les services
docker-compose down
```

#### 2. Utilisation Docker standalone

```bash
# Construire l'image
docker build -t user-service-py .

# Lancer le conteneur
docker run -p 8000:8000 --env-file .env user-service-py
```

#### 3. Intégration dans l'écosystème complet

Pour lancer avec tous les services de l'architecture :
```bash
cd ../starter
./run-docker.sh
```

## 🔗 Services dépendants

Le service nécessite les services suivants pour fonctionner correctement :

- **service-config** (port 8080) : Configuration centralisée Spring Cloud Config
- **service-registry** (port 8761) : Eureka Server pour la découverte de services
- **PostgreSQL** (port 5433) : Base de données principale
- **Redis** (port 6379) : Cache et sessions
- **RabbitMQ** (port 5672) : Messagerie asynchrone

## 📚 API Documentation

Une fois le service lancé, la documentation Swagger est disponible sur :
- **Swagger UI** : `http://localhost:8000/swagger/`
- **ReDoc** : `http://localhost:8000/redoc/`
- **Schema JSON** : `http://localhost:8000/swagger.json`

## 🔐 Authentification

Le service utilise JWT pour l'authentification :

### Obtenir un token
```bash
POST /api/auth/login/
{
    "username": "your_username",
    "password": "your_password"
}
```

### Utiliser le token
```bash
Authorization: Bearer <your_jwt_token>
```

## 🧪 Tests

```bash
# Lancer les tests
cd app
python manage.py test

# Avec coverage
pip install coverage
coverage run --source='.' manage.py test
coverage report
```

## 🔧 Configuration avancée

### Variables d'environnement disponibles

| Variable | Description | Défaut |
|----------|-------------|---------|
| `DB_HOST` | Hôte PostgreSQL | `localhost` |
| `DB_PORT` | Port PostgreSQL | `5433` |
| `DB_NAME` | Nom de la base de données | `user_service_db` |
| `DB_USER` | Utilisateur PostgreSQL | `firecracker` |
| `DB_PASSWORD` | Mot de passe PostgreSQL | `fireCracker` |
| `REDIS_HOST` | Hôte Redis | `redis` |
| `REDIS_PORT` | Port Redis | `6379` |

### Configuration Eureka

Le service s'enregistre automatiquement auprès d'Eureka Server en utilisant la configuration récupérée depuis Spring Cloud Config.

## 🐛 Dépannage

### Problèmes courants

1. **Erreur de connexion à la base de données**
   ```bash
   # Vérifier que PostgreSQL est lancé
   sudo systemctl status postgresql
   
   # Vérifier la connectivité
   pg_isready -h localhost -p 5433
   ```

2. **Erreur de connexion Redis**
   ```bash
   # Vérifier que Redis est lancé
   redis-cli ping
   ```

3. **Problèmes de migrations**
   ```bash
   # Réinitialiser les migrations
   python manage.py migrate --fake-initial
   ```

4. **Erreur de configuration Eureka**
   - Vérifier que `service-config` est accessible sur le port 8080
   - Vérifier que `service-registry` est accessible sur le port 8761

### Logs

```bash
# Logs Docker Compose
docker-compose logs -f app

# Logs Django en local
python manage.py runserver --verbosity=2
```

## 🤝 Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit les changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📄 Licence

Ce projet fait partie de l'architecture IAAS Firecracker.
