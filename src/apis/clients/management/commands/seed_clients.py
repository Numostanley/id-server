import json

from django.core.management.base import BaseCommand

from apis.clients.models import Client, WellKnownConfiguration
from core.settings import BASE_DIR


class Command(BaseCommand):

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        """execute command"""
        self.create_client()
        self.stdout.write(self.style.SUCCESS(
            '==================== Operation Complete! ===================='
        ))
        self.create_well_known_configs()
        self.stdout.write(self.style.SUCCESS(
            'Successfully created OAuth well known configurations!'
        ))

    def create_client(self):
        """seeding client on start up."""
        client_json = BASE_DIR / '.env/kredete/clients.json'

        with open(f'{client_json}', 'r') as f:
            data = json.load(f)
            for datum in data:
                if Client.get_client_by_id(datum['client_id']):
                    # if client exists, do nothing
                    self.stdout.write(self.style.ERROR(
                        f"{datum['client_id']} already exists!"
                    ))
                    pass
                else:
                    # if client does not exist, create new client
                    self.stdout.write(self.style.SUCCESS(
                        f"Successfully created {datum['client_id']} client!"
                    ))
                    Client.create_client(datum).save()

    def create_well_known_configs(self):
        """seeding the oauth2 well known configurations."""
        config_file = BASE_DIR / '.env/kredete/well_known_configuration.json'

        with open(f'{config_file}', 'r') as f:
            data = json.load(f)
            well_known_configs = WellKnownConfiguration.get_well_known_config()
            if len(well_known_configs):
                # if the length of the queryset is more than zero, do nothing
                pass
            else:
                # create well known configuration if none is found
                WellKnownConfiguration.create_well_known_configuration(data).save()
