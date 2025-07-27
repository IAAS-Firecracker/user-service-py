# management/commands/setup_admin.py

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission

User = get_user_model()

class Command(BaseCommand):
    help = 'Setup complete admin user for TerraCity platform'

    def add_arguments(self, parser):
        parser.add_argument(
            '--password',
            type=str,
            default='CartolandAdmin2024!',
            help='Admin user password'
        )
        parser.add_argument(
            '--user',
            type=object,
            default=  {
            "username": "admin",
            "email": "manuel@cartoland.com",
            "first_name": "Cartoland",
            "last_name": "Manuel",
            "user_type": "ADMIN",
            "phone_number": "+237678939987",
            "bio": "Platform Owner"
        },
            help='User Object'
        )


        parser.add_argument(
            '--update',
            action='store_true',
            help='Update existing user if exists'
        )

    def handle(self, *args, **options):
        admin_data = {
            "username": "admin",
            "email": "manuel@cartoland.com",
            "first_name": "Cartoland",
            "last_name": "Manuel",
            "user_type": "ADMIN",
            "phone_number": "+237678939987",
            "bio": "Platform Owner"
        }
        
        password = options['password']
        
        self.stdout.write(
            self.style.SUCCESS('Setting up TerraCity Admin User...')
        )
        
        # Check if user exists
        if User.objects.filter(username=admin_data["username"]).exists():
            if options['update']:
                admin_user = User.objects.get(username=admin_data["username"])
                
                # Update user fields
                for field, value in admin_data.items():
                    setattr(admin_user, field, value)
                
                admin_user.is_staff = True
                admin_user.is_superuser = True
                admin_user.is_active = True
                admin_user.set_password(password)
                admin_user.save()
                
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Updated existing admin user: {admin_user.username}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'❌ User "{admin_data["username"]}" already exists. Use --update to update.')
                )
                return
        else:
            # Create new user
            try:
                admin_user = User.objects.create_user(
                    password=password,
                    is_staff=True,
                    is_superuser=True,
                    is_active=True,
                    **admin_data
                )
                
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Created admin user: {admin_user.username}')
                )
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'❌ Error creating user: {e}')
                )
                return
        
        # Setup admin group
        try:
            admin_group, created = Group.objects.get_or_create(name='Administrators')
            
            if created:
                all_permissions = Permission.objects.all()
                admin_group.permissions.set(all_permissions)
                self.stdout.write(
                    self.style.SUCCESS('✅ Created Administrators group with all permissions')
                )
            
            admin_user.groups.add(admin_group)
            
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'⚠️ Error setting up groups: {e}')
            )
        
        # Create API token if available
        try:
            from rest_framework.authtoken.models import Token
            token, created = Token.objects.get_or_create(user=admin_user)
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Created API token: {token.key}')
                )
            
        except ImportError:
            pass
        
        # Create welcome notification
        try:
            from infrastructures.models import Notification
            
            Notification.objects.get_or_create(
                user=admin_user,
                notification_type='WELCOME',
                defaults={
                    'title': 'Welcome to TerraCity Admin Panel',
                    'message': f'Welcome {admin_user.first_name}! You have admin access.',
                    'is_read': False
                }
            )
            
        except Exception:
            pass
        
        # Display final information
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('ADMIN USER SETUP COMPLETE!'))
        self.stdout.write('='*50)
        self.stdout.write(f'Username: {admin_user.username}')
        self.stdout.write(f'Email: {admin_user.email}')
        self.stdout.write(f'Name: {admin_user.first_name} {admin_user.last_name}')
        self.stdout.write(f'Phone: {admin_user.phone_number}')
        self.stdout.write(f'User Type: {admin_user.user_type}')
        self.stdout.write('='*50)
        self.stdout.write(self.style.WARNING(f'Password: {password}'))
        self.stdout.write(self.style.WARNING('⚠️  Save credentials securely!'))
        self.stdout.write('='*50)
        self.stdout.write('Access:')
        self.stdout.write('• Django Admin: http://localhost:8000/admin/')
        self.stdout.write('• Frontend Login: http://localhost:3000/login')
        self.stdout.write('='*50)